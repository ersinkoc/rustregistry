use crate::{
    analyze_target,
    changes::{NamedValue, StoredValue},
    EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};

pub const MUI_CACHE_KEY: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
pub const RUN_HISTORY_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
pub const TYPED_PATHS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";
pub const CACHE_SUFFIXES: [&str; 2] = [".FriendlyAppName", ".ApplicationCompany"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceKind {
    MuiCache,
    RunHistory,
    TypedPaths,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(name: &str, text: &str) -> NamedValue {
        NamedValue {
            name: name.into(),
            value: StoredValue {
                kind: 1,
                bytes: text
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            },
        }
    }
    #[test]
    fn cache_policy_accepts_only_recognized_executable_fields_and_preserves_empty_unicode_labels() {
        let path = r"C:\Removed Apps\player.exe";
        let mut app = MaintenanceBackup {
            kind: MaintenanceKind::MuiCache,
            item: path.into(),
            snapshot: MaintenanceSnapshot {
                values: vec![
                    v(&format!("{path}.FriendlyAppName"), ""),
                    v(&format!("{path}.ApplicationCompany"), "日本語"),
                ],
                preserved: vec![],
            },
        };
        app.validate().unwrap();
        assert!(app.summary().unwrap().contains("日本語"));
        for path in [
            r"relative.exe",
            r"C:\Windows\missing.exe",
            r"\\server\share\app.exe",
            r"C:\Removed Apps\..\app.exe",
            r"C:\path\APP.EXE:stream",
            r"C:\path\app.exe.",
            r"%TEMP%\app.exe",
        ] {
            app.item = path.into();
            assert!(app.validate().is_err());
        }
        app.item = r"C:\Removed Apps\player.exe".into();
        app.snapshot
            .values
            .push(v(&format!("{path}.Unknown"), "preserve"));
        assert!(app.validate().is_err());
    }
    #[test]
    fn history_policy_rejects_inconsistent_order_unknown_fields_types_and_oversized_data() {
        let good = MaintenanceBackup {
            kind: MaintenanceKind::RunHistory,
            item: "RunMRU".into(),
            snapshot: MaintenanceSnapshot {
                values: vec![v("MRUList", "ba"), v("a", "one\\1"), v("b", "two\\1")],
                preserved: vec![v("", "")],
            },
        };
        good.validate().unwrap();
        for order in ["aa", "a", "abc", "BA", "a\0b"] {
            let mut bad = good.clone();
            bad.snapshot.values[0] = v("MRUList", order);
            assert!(bad.validate().is_err());
        }
        let mut bad = good.clone();
        bad.snapshot.preserved[0] = v("", "custom default");
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.snapshot.values[1].value.kind = 2;
        assert!(bad.validate().is_err());
        let mut bad = good.clone();
        bad.snapshot.values[1] = v("a", &"x".repeat(9000));
        assert!(bad.validate().is_err());
        let mut paths = MaintenanceBackup {
            kind: MaintenanceKind::TypedPaths,
            item: "TypedPaths".into(),
            snapshot: MaintenanceSnapshot {
                values: vec![
                    v("url1", r"\\unreachable\never-probed"),
                    v("url25", "C:\\path"),
                ],
                preserved: vec![],
            },
        };
        paths.validate().unwrap();
        for name in ["url0", "url26", "url01", "url999", "Other", "MRUList"] {
            paths.snapshot.values[0].name = name.into();
            assert!(paths.validate().is_err());
        }
    }
}
impl MaintenanceKind {
    pub fn path(self) -> &'static str {
        match self {
            Self::MuiCache => MUI_CACHE_KEY,
            Self::RunHistory => RUN_HISTORY_KEY,
            Self::TypedPaths => TYPED_PATHS_KEY,
        }
    }
    pub fn scope(self) -> &'static str {
        match self {
            Self::MuiCache => "mui_cache",
            Self::RunHistory => "run_history",
            Self::TypedPaths => "typed_paths",
        }
    }
    pub fn history(self) -> bool {
        self != Self::MuiCache
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaintenanceSnapshot {
    pub values: Vec<NamedValue>,
    pub preserved: Vec<NamedValue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaintenanceBackup {
    pub kind: MaintenanceKind,
    pub item: String,
    pub snapshot: MaintenanceSnapshot,
}

pub fn maintenance_text(value: &StoredValue) -> Result<String, String> {
    if value.kind != 1 || value.bytes.len() > 16384 || !value.bytes.len().is_multiple_of(2) {
        return Err("Only bounded REG_SZ maintenance text is supported.".into());
    }
    let mut units: Vec<u16> = value
        .bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    let text =
        String::from_utf16(&units).map_err(|_| "Maintenance text contains invalid UTF-16.")?;
    if text.contains('\0') {
        return Err("Embedded nulls in maintenance text remain read-only.".into());
    }
    Ok(text)
}

pub fn cache_target(name: &str) -> Option<&str> {
    CACHE_SUFFIXES.iter().find_map(|suffix| {
        let start = name.len().checked_sub(suffix.len())?;
        let tail = name.get(start..)?;
        tail.eq_ignore_ascii_case(suffix).then(|| &name[..start])
    })
}
pub fn validate_cache_path(path: &str) -> Result<(), String> {
    if !path.to_ascii_lowercase().ends_with(".exe") {
        return Err("Only literal local .exe cache identities support cleaning.".into());
    }
    crate::shared_dlls::validate_shared_dll_path(&format!("{}.dll", &path[..path.len()-4]))
        .map_err(|_| "Only bounded literal local ASCII executable paths outside Windows support cache cleaning. Unicode display labels are preserved.".into())
}
impl MaintenanceSnapshot {
    pub fn validate_text(&self) -> Result<(), String> {
        if self.values.is_empty() || self.values.len() > 27 || self.preserved.len() > 1 {
            return Err("Empty or oversized maintenance snapshots remain read-only.".into());
        }
        let mut names = std::collections::HashSet::new();
        let mut size = 0;
        for v in self.values.iter().chain(&self.preserved) {
            size += v.value.bytes.len() + v.name.len();
            if size > 16384 || !names.insert(v.name.to_ascii_lowercase()) || v.value.kind != 1 {
                return Err("Maintenance requires bounded, unique REG_SZ values.".into());
            }
            maintenance_text(&v.value)?;
        }
        if self
            .preserved
            .iter()
            .any(|v| !v.name.is_empty() || !maintenance_text(&v.value).is_ok_and(|s| s.is_empty()))
        {
            return Err("Only an empty default history value can be preserved.".into());
        }
        Ok(())
    }
}

impl MaintenanceBackup {
    pub fn cleared(&self) -> MaintenanceSnapshot {
        MaintenanceSnapshot {
            values: vec![],
            preserved: self.snapshot.preserved.clone(),
        }
    }
    pub fn summary(&self) -> Result<String, String> {
        self.snapshot
            .values
            .iter()
            .map(|v| Ok(format!("{} = {}", v.name, maintenance_text(&v.value)?)))
            .collect::<Result<Vec<_>, String>>()
            .map(|v| v.join("\n"))
    }
    pub fn validate(&self) -> Result<(), String> {
        self.snapshot.validate_text()?;
        match self.kind {
            MaintenanceKind::MuiCache => {
                validate_cache_path(&self.item)?;
                if !self.snapshot.preserved.is_empty()
                    || self.snapshot.values.len() > 2
                    || self.snapshot.values.iter().any(|v| {
                        !cache_target(&v.name).is_some_and(|s| s.eq_ignore_ascii_case(&self.item))
                    })
                {
                    return Err("Unknown application cache fields remain read-only.".into());
                }
            }
            MaintenanceKind::RunHistory => {
                if self.item != "RunMRU" {
                    return Err("Unsupported history namespace.".into());
                }
                let order = maintenance_text(
                    &self
                        .snapshot
                        .values
                        .iter()
                        .find(|v| v.name == "MRUList")
                        .ok_or("Run history needs a complete MRUList.")?
                        .value,
                )?;
                let letters: std::collections::HashSet<_> = self
                    .snapshot
                    .values
                    .iter()
                    .filter(|v| v.name != "MRUList")
                    .map(|v| v.name.as_str())
                    .collect();
                let actual: std::collections::HashSet<_> =
                    order.chars().map(|c| c.to_string()).collect();
                if order.is_empty()
                    || !order.bytes().all(|b| b.is_ascii_lowercase())
                    || actual.len() != order.len()
                    || letters.len() != order.len()
                    || !letters.iter().all(|n| actual.contains(*n))
                    || letters
                        .iter()
                        .any(|n| n.len() != 1 || !n.as_bytes()[0].is_ascii_lowercase())
                {
                    return Err(
                        "Malformed or incomplete Run history ordering remains read-only.".into(),
                    );
                }
            }
            MaintenanceKind::TypedPaths => {
                if self.item != "TypedPaths"
                    || self.snapshot.values.iter().any(|v| {
                        v.name
                            .strip_prefix("url")
                            .and_then(|n| n.parse::<u8>().ok())
                            .is_none_or(|n| !(1..=25).contains(&n) || v.name != format!("url{n}"))
                    })
                {
                    return Err(
                        "Only bounded url1–url25 typed-path histories support cleaning.".into(),
                    );
                }
            }
        }
        Ok(())
    }
    pub fn verify_target(&self, probe: &impl PathProbe) -> Result<(), String> {
        self.validate()?;
        if self.kind == MaintenanceKind::MuiCache {
            let assessment =
                analyze_target(&self.item, TargetKind::File, &Environment::current(), probe);
            if assessment.status != EntryStatus::Review || assessment.code != "target_missing" {
                return Err("The cached application is not confirmed missing. Cleaning or restore is blocked.".into());
            }
        }
        Ok(())
    }
    pub fn sentinel(&self) -> StoredValue {
        self.snapshot.values[0].value.clone()
    }
}
