use super::*;
use crate::{
    changes::{RegistryStore, StoredValue},
    type_libraries::*,
    windows_changes::{open_type_lib, WindowsRegistryStore},
};

pub(super) fn scan_type_libraries(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let start = entries.len();
    let mut walked = 0usize;
    let store = WindowsRegistryStore::default();
    'libraries: for library in root.enum_keys() {
        if stop(cancel, entries.len() - start, &mut walked, scope) {
            break;
        }
        let id = match library {
            Ok(id) => id,
            Err(error) => {
                scope.notes.push(read_error(&error));
                continue;
            }
        };
        if crate::com::validate_clsid(&id).is_err() {
            scope
                .notes
                .push(format!("{id}: unsupported type library identifier."));
            continue;
        }
        let library = match open_type_lib(root, &id, None, false) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(error) => {
                scope.notes.push(error);
                continue;
            }
        };
        for version in library.enum_keys() {
            if stop(cancel, entries.len() - start, &mut walked, scope) {
                break 'libraries;
            }
            let version = match version {
                Ok(v) => v,
                Err(error) => {
                    scope.notes.push(read_error(&error));
                    continue;
                }
            };
            if validate_version(&version).is_err() {
                scope
                    .notes
                    .push(format!("{id}: unsupported type library version."));
                continue;
            }
            let version_key = match open_type_lib(&library, &version, None, false) {
                Ok(Some(key)) => key,
                Ok(None) => continue,
                Err(error) => {
                    scope.notes.push(error);
                    continue;
                }
            };
            for locale in version_key.enum_keys() {
                if stop(cancel, entries.len() - start, &mut walked, scope) {
                    break 'libraries;
                }
                let locale = match locale {
                    Ok(v) => v,
                    Err(error) => {
                        scope.notes.push(read_error(&error));
                        continue;
                    }
                };
                if locale.eq_ignore_ascii_case("FLAGS") || locale.eq_ignore_ascii_case("HELPDIR") {
                    continue;
                }
                if validate_locale(&locale).is_err() {
                    scope
                        .notes
                        .push(format!("{id}: unsupported type library locale."));
                    continue;
                }
                let locale_key = match open_type_lib(&version_key, &locale, None, false) {
                    Ok(Some(key)) => key,
                    Ok(None) => continue,
                    Err(error) => {
                        scope.notes.push(error);
                        continue;
                    }
                };
                for platform in ["win32", "win64"] {
                    if stop(cancel, entries.len() - start, &mut walked, scope) {
                        break 'libraries;
                    }
                    let leaf = match open_type_lib(&locale_key, platform, None, false) {
                        Ok(Some(key)) => key,
                        Ok(None) => continue,
                        Err(error) => {
                            scope.notes.push(error);
                            continue;
                        }
                    };
                    let raw = leaf.get_raw_value("");
                    let original = raw.as_ref().ok().map(|v| StoredValue {
                        kind: v.vtype.clone() as u32,
                        bytes: v.bytes.to_vec(),
                    });
                    let friendly = version_key
                        .get_raw_value("")
                        .ok()
                        .and_then(|v| text(&v).ok())
                        .filter(|v| !v.trim().is_empty())
                        .unwrap_or_else(|| id.clone());
                    let subkey = format!(r"{id}\{version}\{locale}\{platform}");
                    let mut entry = make_entry(
                        source,
                        &subkey,
                        format!("{friendly} · {version} · {locale} · {platform}"),
                        "",
                        raw.map_err(|e| read_error(&e)),
                        environment,
                        probe,
                    );
                    entry.assessment=match &original {
                        None=>Assessment{status:EntryStatus::Unknown,code:"type_library_mapping_absent".into(),explanation:"No readable default type library mapping is present. This alone does not prove the library is broken.".into(),target:None},
                        Some(value)=>match value.text() {
                            Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"unsupported_value".into(),explanation:reason,target:None},
                            Ok(_) if platform=="win32"=>Assessment{status:EntryStatus::Unknown,code:"type_library_win32_unverified".into(),explanation:"The win32 mapping was inventoried without probing files in a 64-bit context. It remains read-only.".into(),target:None},
                            Ok(path)=>match validate_library_path(&path) {
                                Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"type_library_path_unverified".into(),explanation:reason,target:None},
                                Ok(())=>analyze_target(&path,TargetKind::File,environment,probe),
                            }
                        }
                    };
                    if source.hive == "HKCU"
                        && locale == "0"
                        && platform == "win64"
                        && entry.assessment.code == "target_missing"
                    {
                        let selector = TypeLibBackup::selector(&id, &version);
                        if let Ok(state) = store.read_type_library(&selector) {
                            if state.value == original {
                                entry.type_library_repairable = true;
                                entry.type_library_state = Some(state);
                            }
                        }
                    }
                    if entry.assessment.status == EntryStatus::Review {
                        entry.assessment.explanation.push_str(if entry.type_library_repairable {" This simple neutral win64 mapping can be reviewed for backed-up repair. Keys, metadata, and win32 mappings are preserved; no library is loaded or registered."} else {" Repair requires one neutral current-user version, supported unchanged metadata, and no machine counterpart. Other mappings remain read-only."});
                    }
                    entries.push(entry);
                }
            }
        }
    }
}

fn stop(cancel: &AtomicBool, entries: usize, walked: &mut usize, scope: &mut ScopeResult) -> bool {
    *walked += 1;
    if cancel.load(Ordering::Relaxed) {
        scope.status = "cancelled".into();
        true
    } else if entries >= MAX_ENTRIES_PER_SCOPE || *walked > 30000 {
        scope.status = "limited".into();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn type_library_inventory_preserves_both_platforms_and_never_probes_win32_targets() {
        struct Probe(Cell<usize>);
        impl PathProbe for Probe {
            fn probe(&self, path: &str, _: TargetKind) -> crate::ProbeResult {
                assert!(!path.contains("never-probe-win32"));
                self.0.set(self.0.get() + 1);
                crate::ProbeResult::Missing
            }
        }
        let base = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
        let (root, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&base)
            .unwrap();
        let id = format!("{{{}}}", uuid::Uuid::new_v4());
        let (version, _) = root.create_subkey(format!(r"{id}\1.0")).unwrap();
        version.set_value("", &"Owned scan fixture").unwrap();
        let (locale, _) = version.create_subkey("0").unwrap();
        let (win32, _) = locale.create_subkey("win32").unwrap();
        win32
            .set_value("", &r"C:\Missing\never-probe-win32.dll")
            .unwrap();
        let (win64, _) = locale.create_subkey("win64").unwrap();
        win64
            .set_value("", &r"C:\RustRegistryMissing\scan-library.tlb")
            .unwrap();
        let before32 = win32.get_raw_value("").unwrap().bytes.into_owned();
        let before64 = win64.get_raw_value("").unwrap().bytes.into_owned();
        let source = Source {
            category: Category::TypeLibraries,
            hive: "HKCU",
            path: TYPE_LIB_KEY,
            flag: 0,
            view: "shared",
        };
        let mut scope = ScopeResult {
            id: "owned".into(),
            category: source.category,
            hive: source.hive.into(),
            key_path: source.path.into(),
            view: source.view.into(),
            status: "complete".into(),
            entries: 0,
            notes: vec![],
        };
        let mut entries = vec![];
        let probe = Probe(Cell::new(0));
        scan_type_libraries(
            &source,
            &root,
            &AtomicBool::new(false),
            &Environment::default(),
            &mut entries,
            &mut scope,
            &probe,
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(probe.0.get(), 1);
        assert_eq!(
            entries
                .iter()
                .find(|e| e.key_path.ends_with("win32"))
                .unwrap()
                .assessment
                .code,
            "type_library_win32_unverified"
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.key_path.ends_with("win64"))
                .unwrap()
                .assessment
                .code,
            "target_missing"
        );
        assert_eq!(win32.get_raw_value("").unwrap().bytes.as_ref(), before32);
        assert_eq!(win64.get_raw_value("").unwrap().bytes.as_ref(), before64);
        let mut canceled = vec![];
        scan_type_libraries(
            &source,
            &root,
            &AtomicBool::new(true),
            &Environment::default(),
            &mut canceled,
            &mut scope,
            &probe,
        );
        assert!(canceled.is_empty());
        assert_eq!(scope.status, "cancelled");
        assert_eq!(probe.0.get(), 1);
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(base)
            .unwrap();
        let sources = super::super::sources();
        assert_eq!(sources.len(), 68);
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::TypeLibraries && s.view == "shared")
                .count(),
            2
        );
    }
}
