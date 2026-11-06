use crate::{analysis::LocalPathProbe, *};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use winreg::{enums::*, RegKey, RegValue};

const MAX_ENTRIES_PER_SCOPE: usize = 5_000;
const MAX_VALUE_BYTES: usize = 32_768;

struct Source {
    category: Category,
    hive: &'static str,
    path: &'static str,
    flag: u32,
    view: &'static str,
}

fn sources() -> Vec<Source> {
    let mut result = Vec::new();
    for (category, path) in [
        (
            Category::Startup,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Category::Startup,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            Category::AppPaths,
            r"Software\Microsoft\Windows\CurrentVersion\App Paths",
        ),
        (
            Category::Uninstall,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ] {
        // These HKCU paths are shared: enumerate once, avoiding duplicate results.
        result.push(Source {
            category,
            hive: "HKCU",
            path,
            flag: 0,
            view: "shared",
        });
        for (flag, view) in [(KEY_WOW64_64KEY, "64"), (KEY_WOW64_32KEY, "32")] {
            result.push(Source {
                category,
                hive: "HKLM",
                path,
                flag,
                view,
            });
        }
    }
    result
}

fn text(value: &RegValue<'_>) -> Result<String, &'static str> {
    if !matches!(value.vtype, REG_SZ | REG_EXPAND_SZ) {
        return Err("This is not a text registry value and was not interpreted as a path.");
    }
    if value.bytes.len() > MAX_VALUE_BYTES {
        return Err("The value exceeds the size limit. Its target was not checked.");
    }
    if !value.bytes.len().is_multiple_of(2) {
        return Err("The value contains invalid UTF-16. Its target was not checked.");
    }
    let mut units: Vec<u16> = value
        .bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16(&units)
        .map_err(|_| "The value contains invalid UTF-16. Its target was not checked.")
}

fn read_error(error: &std::io::Error) -> String {
    let message = match error.kind() {
        std::io::ErrorKind::NotFound => "The specified key or value was not found",
        std::io::ErrorKind::PermissionDenied => "Access was denied",
        std::io::ErrorKind::InvalidData => "The registry data could not be decoded",
        _ => "The registry read could not be completed",
    };
    format!(
        "{message} (Windows error {})",
        error.raw_os_error().unwrap_or(0)
    )
}

fn read_optional(key: &RegKey, name: &str, notes: &mut Vec<String>) -> Option<String> {
    match key.get_raw_value(name) {
        Ok(value) => match text(&value) {
            Ok(value) => Some(value),
            Err(reason) => {
                notes.push(format!("{name}: {reason}"));
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            notes.push(format!("Could not read {name}: {}", read_error(&error)));
            None
        }
    }
}

fn make_entry(
    source: &Source,
    subkey: &str,
    name: String,
    value_name: &str,
    raw: Result<RegValue<'_>, String>,
    environment: &Environment,
) -> RegistryEntry {
    let snapshot = raw
        .as_ref()
        .ok()
        .filter(|value| {
            source.hive == "HKCU"
                && ((source.category == Category::Startup
                    && source.path == crate::changes::STARTUP_KEY)
                    || (source.category == Category::AppPaths
                        && source.path == crate::changes::APP_PATHS_KEY))
                && value.bytes.len() <= MAX_VALUE_BYTES
                && matches!(value.vtype, REG_SZ | REG_EXPAND_SZ)
        })
        .map(|value| crate::changes::StoredValue {
            kind: value.vtype.clone() as u32,
            bytes: value.bytes.to_vec(),
        });
    let path = if subkey.is_empty() {
        source.path.into()
    } else {
        format!("{}\\{}", source.path, subkey)
    };
    let (raw_value, value_type, value_assessment) = match raw {
        Ok(value) => {
            let value_type = format!("{:?}", value.vtype);
            match text(&value) {
                Ok(raw) => {
                    let kind = match source.category {
                        Category::Startup => TargetKind::Command,
                        Category::AppPaths => TargetKind::File,
                        Category::Uninstall => TargetKind::Directory,
                    };
                    let assessment = analyze_target(&raw, kind, environment, &LocalPathProbe);
                    (raw, value_type, assessment)
                }
                Err(reason) => (
                    String::new(),
                    value_type,
                    Assessment {
                        status: EntryStatus::Unknown,
                        code: "unsupported_value".into(),
                        explanation: reason.into(),
                        target: None,
                    },
                ),
            }
        }
        Err(reason) => (
            String::new(),
            "—".into(),
            Assessment {
                status: EntryStatus::Unknown,
                code: "value_unavailable".into(),
                explanation: reason,
                target: None,
            },
        ),
    };
    RegistryEntry {
        id: format!("{}|{}|{}|{}", source.hive, source.view, path, value_name),
        name,
        category: source.category,
        hive: source.hive.into(),
        key_path: path,
        view: source.view.into(),
        value_name: value_name.into(),
        value_type,
        raw_value,
        publisher: None,
        version: None,
        assessment: value_assessment,
        snapshot,
        app_path_guard: None,
        app_path_repairable: false,
    }
}

fn scan_source(
    source: &Source,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
) -> ScopeResult {
    let mut scope = ScopeResult {
        id: format!("{}|{}|{}", source.hive, source.view, source.path),
        category: source.category,
        hive: source.hive.into(),
        key_path: source.path.into(),
        view: source.view.into(),
        status: "complete".into(),
        entries: 0,
        notes: Vec::new(),
    };
    let hive = RegKey::predef(if source.hive == "HKCU" {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    });
    // Scanning opens handles only with KEY_READ; protected mutations live in windows_changes.
    let key = match hive.open_subkey_with_flags(source.path, KEY_READ | source.flag) {
        Ok(key) => key,
        Err(error) => {
            scope.status = match error.kind() {
                std::io::ErrorKind::NotFound => "missing",
                std::io::ErrorKind::PermissionDenied => "access_denied",
                _ => "error",
            }
            .into();
            scope.notes.push(read_error(&error));
            return scope;
        }
    };
    let start_count = entries.len();
    if source.category == Category::Startup {
        for (index, result) in key.enum_values().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                scope.status = "cancelled".into();
                break;
            }
            if index >= MAX_ENTRIES_PER_SCOPE {
                scope.status = "limited".into();
                break;
            }
            match result {
                Ok((name, value)) => entries.push(make_entry(
                    source,
                    "",
                    name.clone(),
                    &name,
                    Ok(value),
                    environment,
                )),
                Err(error) => scope.notes.push(format!(
                    "A startup value could not be read: {}",
                    read_error(&error)
                )),
            }
        }
    } else {
        for (index, result) in key.enum_keys().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                scope.status = "cancelled".into();
                break;
            }
            if index >= MAX_ENTRIES_PER_SCOPE {
                scope.status = "limited".into();
                break;
            }
            let name = match result {
                Ok(name) => name,
                Err(error) => {
                    scope.notes.push(format!(
                        "A subkey could not be read: {}",
                        read_error(&error)
                    ));
                    continue;
                }
            };
            let options = if source.category == Category::AppPaths {
                REG_OPTION_OPEN_LINK
            } else {
                0
            };
            let child =
                match key.open_subkey_with_options_flags(&name, options, KEY_READ | source.flag) {
                    Ok(child) => child,
                    Err(error) => {
                        scope
                            .notes
                            .push(format!("Could not open {name}: {}", read_error(&error)));
                        continue;
                    }
                };
            let value_name = if source.category == Category::AppPaths {
                ""
            } else {
                "InstallLocation"
            };
            let mut notes = Vec::new();
            let display_name = if source.category == Category::Uninstall {
                read_optional(&child, "DisplayName", &mut notes)
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| name.clone())
            } else {
                name.clone()
            };
            let raw = child.get_raw_value(value_name).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    "This record does not define a target path. Missing path information alone does not mean the record is broken.".into()
                } else { format!("The target value could not be read: {}", read_error(&error)) }
            });
            let mut entry = make_entry(source, &name, display_name, value_name, raw, environment);
            if source.category == Category::AppPaths
                && source.hive == "HKCU"
                && entry.assessment.status == EntryStatus::Review
                && entry.assessment.code == "target_missing"
                && entry.snapshot.is_some()
                && entry
                    .assessment
                    .target
                    .as_deref()
                    .is_some_and(|target| target.to_ascii_lowercase().ends_with(".exe"))
                && crate::changes::validate_app_path_name(&name).is_ok()
            {
                entry.app_path_guard = crate::windows_changes::read_app_path_guard(&child).ok();
                entry.app_path_repairable = entry.app_path_guard.is_some();
            }
            if source.category == Category::Uninstall {
                entry.publisher = read_optional(&child, "Publisher", &mut notes);
                entry.version = read_optional(&child, "DisplayVersion", &mut notes);
            }
            scope
                .notes
                .extend(notes.into_iter().map(|note| format!("{name}: {note}")));
            entries.push(entry);
        }
    }
    scope.entries = entries.len() - start_count;
    if !scope.notes.is_empty() && scope.status == "complete" {
        scope.status = "partial".into();
    }
    scope
}

pub fn scan(cancel: &AtomicBool, progress: impl Fn(ScanProgress)) -> Result<ScanReport, String> {
    if cfg!(not(target_arch = "x86_64")) {
        return Err("This release supports Windows x64 only. Registry view scanning is not supported on other architectures.".into());
    }
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    let timer = Instant::now();
    let environment = Environment::current();
    let sources = sources();
    let mut entries = Vec::new();
    let mut scopes = Vec::new();
    for source in &sources {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        progress(ScanProgress {
            completed: scopes.len(),
            total: sources.len(),
            entries: entries.len(),
            current: format!("{}\\{}", source.hive, source.path),
        });
        scopes.push(scan_source(source, cancel, &environment, &mut entries));
    }
    progress(ScanProgress {
        completed: scopes.len(),
        total: sources.len(),
        entries: entries.len(),
        current: "Scan complete".into(),
    });
    Ok(ScanReport {
        id: format!("scan-{started_at}"),
        started_at,
        duration_ms: timer.elapsed().as_millis() as u64,
        cancelled: cancel.load(Ordering::Relaxed),
        read_only: true,
        architecture: std::env::consts::ARCH.into(),
        entries,
        scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn decodes_registry_text_without_hiding_embedded_nulls() {
        let bytes: Vec<u8> = "C:\\Apps\\app.exe\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            text(&RegValue {
                bytes: Cow::Owned(bytes),
                vtype: REG_SZ
            })
            .unwrap(),
            r"C:\Apps\app.exe"
        );
        let bytes = vec![b'a', 0, 0, 0, b'b', 0, 0, 0];
        assert_eq!(
            text(&RegValue {
                bytes: Cow::Owned(bytes),
                vtype: REG_SZ
            })
            .unwrap(),
            "a\0b"
        );
    }

    #[test]
    fn malformed_or_non_text_registry_values_are_not_paths() {
        assert!(text(&RegValue {
            bytes: Cow::Owned(vec![1]),
            vtype: REG_SZ
        })
        .is_err());
        assert!(text(&RegValue {
            bytes: Cow::Owned(vec![0, 216]),
            vtype: REG_SZ
        })
        .is_err());
        assert!(text(&RegValue {
            bytes: Cow::Owned(vec![0; 4]),
            vtype: REG_DWORD
        })
        .is_err());
    }

    #[test]
    fn cancelled_scan_does_not_read_any_scopes() {
        let result = scan(&AtomicBool::new(true), |_| {}).unwrap();
        assert!(result.cancelled);
        assert!(result.read_only);
        assert!(result.entries.is_empty());
        assert!(result.scopes.is_empty());
    }

    #[test]
    fn cancellation_at_the_first_progress_event_stops_before_enumerating_values() {
        let cancel = AtomicBool::new(false);
        let result = scan(&cancel, |_| cancel.store(true, Ordering::Release)).unwrap();
        assert!(result.cancelled);
        assert!(result.entries.is_empty());
        assert_eq!(result.scopes.len(), 1);
        assert!(matches!(
            result.scopes[0].status.as_str(),
            "cancelled" | "missing"
        ));
    }
}
