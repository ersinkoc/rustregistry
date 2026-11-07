pub use crate::applications::{validate_application_name, APPLICATIONS_KEY};
use crate::{
    analyze_target, applications::ApplicationSnapshot, changes::StoredValue, Assessment,
    EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};

pub fn validate_icon_path(path: &str) -> Result<(), String> {
    if !path.is_ascii() || path.len() < 4 || !path.to_ascii_lowercase().ends_with(".ico") {
        return Err("Only literal local .ico files support icon reference recovery.".into());
    }
    crate::shared_dlls::validate_shared_dll_path(&format!("{}.dll",&path[..path.len()-4])).map_err(|_|"Only bounded literal .ico paths outside Windows, without aliases, environment expressions or resource indexes, support recovery.".into())
}
pub fn assess_icon(raw: &str, environment: &Environment, probe: &impl PathProbe) -> Assessment {
    if raw.contains('%') || raw.contains(',') || !raw.to_ascii_lowercase().ends_with(".ico") {
        return Assessment{status:EntryStatus::Unknown,code:"icon_expression_unverified".into(),explanation:"Only literal .ico file references are checked. Resource containers/indexes, indirect icons, environment expressions and uncertain targets remain unverified. No icon or library is loaded.".into(),target:None};
    }
    analyze_target(raw, TargetKind::File, environment, probe)
}
pub fn verify_missing_icon(value: &StoredValue, probe: &impl PathProbe) -> Result<(), String> {
    let path = value.text()?;
    validate_icon_path(&path)?;
    let result = assess_icon(&path, &Environment::current(), probe);
    if result.status != EntryStatus::Review || result.code != "target_missing" {
        return Err("The icon file is not confirmed missing. Repair or restore is blocked.".into());
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconState {
    pub value: Option<StoredValue>,
    pub guard: ApplicationSnapshot,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IconBackup {
    pub executable: String,
    pub guard: ApplicationSnapshot,
}
impl IconBackup {
    pub fn validate(&self) -> Result<(), String> {
        validate_application_name(&self.executable)?;
        self.guard.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Missing;
    impl PathProbe for Missing {
        fn probe(&self, _: &str, _: TargetKind) -> crate::ProbeResult {
            crate::ProbeResult::Missing
        }
    }
    fn text(raw: &str) -> StoredValue {
        StoredValue {
            kind: 1,
            bytes: raw
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    #[test]
    fn icon_recovery_excludes_resources_aliases_environment_network_and_windows_paths() {
        verify_missing_icon(&text(r"C:\Missing Icons\application.ico"), &Missing).unwrap();
        for path in [
            r"C:\Missing\application.exe,0",
            r"C:\Missing\application.dll",
            r"%TEMP%\missing.ico",
            r"\\server\share\missing.ico",
            r"C:\Windows\missing.ico",
            r"C:\Missing\..\file.ico",
            r"C:\MISSIN~1\file.ico",
            r"relative.ico",
            r"C:\Missing\file.ico,0",
        ] {
            assert!(
                verify_missing_icon(&text(path), &Missing).is_err(),
                "{path}"
            );
        }
        struct NoProbe;
        impl PathProbe for NoProbe {
            fn probe(&self, _: &str, _: TargetKind) -> crate::ProbeResult {
                panic!("Resource expressions must not be probed")
            }
        }
        assert_eq!(
            assess_icon(
                r"C:\Missing\shell.dll,-1",
                &Environment::default(),
                &NoProbe
            )
            .status,
            EntryStatus::Unknown
        );
    }
}
