use crate::{
    analyze_target,
    changes::{NamedValue, StoredValue},
    EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};

pub const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
pub const COMPONENT: &str = "SystemComponent";

pub fn validate_uninstall_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.encode_utf16().count() > 255
        || name == "."
        || name == ".."
        || name.trim() != name
        || name
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    {
        return Err("Only a single current-user Uninstall registration name is supported.".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UninstallSnapshot {
    pub values: Vec<NamedValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UninstallBackup {
    pub key_name: String,
    pub snapshot: UninstallSnapshot,
}

impl UninstallSnapshot {
    pub fn get(&self, name: &str) -> Option<&StoredValue> {
        self.values
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case(name))
            .map(|item| &item.value)
    }
    pub fn text(&self, name: &str) -> Result<String, String> {
        self.get(name)
            .ok_or_else(|| format!("The uninstall entry does not define {name}."))?
            .text()
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.values.len() > 64
            || self
                .values
                .iter()
                .map(|v| v.value.bytes.len())
                .sum::<usize>()
                > 32_768
        {
            return Err("Uninstall metadata exceeds the supported backup limits.".into());
        }
        let mut names = std::collections::HashSet::new();
        for item in &self.values {
            if item.name.encode_utf16().count() > 256
                || item.name.contains('\0')
                || item.value.kind > 11
                || item.value.kind == 6
                || !names.insert(item.name.to_lowercase())
            {
                return Err("Uninstall metadata is unsupported or ambiguous.".into());
            }
        }
        Ok(())
    }
    pub fn validate_original(&self) -> Result<(), String> {
        self.validate()?;
        for flag in [COMPONENT, "WindowsInstaller", "NoRemove"] {
            if let Some(value) = self.get(flag) {
                if value.kind != 4 || value.bytes != [0, 0, 0, 0] {
                    return Err(format!("Protected or unsupported uninstall flag: {flag}."));
                }
            }
        }
        if ["ParentKeyName", "ParentDisplayName", "ReleaseType"]
            .iter()
            .any(|name| self.get(name).is_some())
        {
            return Err("Grouped entries and updates are outside uninstall repair scope.".into());
        }
        self.text("DisplayName")?;
        self.text("InstallLocation")?;
        self.text("UninstallString")?;
        Ok(())
    }
    pub fn hidden(&self) -> Result<Self, String> {
        self.validate_original()?;
        let mut snapshot = self.clone();
        snapshot
            .values
            .retain(|item| !item.name.eq_ignore_ascii_case(COMPONENT));
        snapshot.values.push(NamedValue {
            name: self
                .values
                .iter()
                .find(|item| item.name.eq_ignore_ascii_case(COMPONENT))
                .map_or_else(|| COMPONENT.into(), |item| item.name.clone()),
            value: StoredValue {
                kind: 4,
                bytes: vec![1, 0, 0, 0],
            },
        });
        snapshot.values.sort_by_key(|item| item.name.to_lowercase());
        Ok(snapshot)
    }
    pub fn is_hidden(&self) -> bool {
        self.get(COMPONENT)
            .is_some_and(|value| value.kind == 4 && value.bytes == [1, 0, 0, 0])
    }
}

pub fn verify_orphan(snapshot: &UninstallSnapshot, probe: &impl PathProbe) -> Result<(), String> {
    snapshot.validate_original()?;
    let environment = Environment::current();
    let directory = analyze_target(
        &snapshot.text("InstallLocation")?,
        TargetKind::Directory,
        &environment,
        probe,
    );
    if directory.status != EntryStatus::Review || directory.code != "target_missing" {
        return Err(
            "The installation directory is not confirmed missing. Uninstall repair is blocked."
                .into(),
        );
    }
    for field in ["UninstallString", "QuietUninstallString"] {
        if field == "QuietUninstallString" && snapshot.get(field).is_none() {
            continue;
        }
        let command = analyze_target(
            &snapshot.text(field)?,
            TargetKind::Command,
            &environment,
            probe,
        );
        if command.status != EntryStatus::Review
            || command.code != "target_missing"
            || !command
                .target
                .as_deref()
                .is_some_and(|target| target.to_ascii_lowercase().ends_with(".exe"))
        {
            return Err(format!("{field} is not a confirmed missing local executable. No uninstall entry can be hidden."));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture_snapshot(component: Option<u32>) -> UninstallSnapshot {
    let text = |value: &str| StoredValue {
        kind: 1,
        bytes: format!("{value}\0")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    let mut values: Vec<NamedValue> = [
        ("DisplayName", "Example"),
        ("DisplayVersion", "1.0"),
        ("InstallLocation", r"C:\RustRegistryMissing\Install"),
        (
            "UninstallString",
            r#""C:\RustRegistryMissing\uninstall.exe" /remove"#,
        ),
        (
            "QuietUninstallString",
            r#""C:\RustRegistryMissing\uninstall.exe" /quiet"#,
        ),
        ("Publisher", "Example publisher"),
    ]
    .into_iter()
    .map(|(name, value)| NamedValue {
        name: name.into(),
        value: text(value),
    })
    .collect();
    values.push(NamedValue {
        name: "CustomBinary".into(),
        value: StoredValue {
            kind: 3,
            bytes: vec![0, 255, 1, 0],
        },
    });
    if let Some(component) = component {
        values.push(NamedValue {
            name: "systemcomponent".into(),
            value: StoredValue {
                kind: 4,
                bytes: component.to_le_bytes().to_vec(),
            },
        });
    }
    values.sort_by_key(|item| item.name.to_lowercase());
    UninstallSnapshot { values }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProbeResult;
    struct Probe {
        uninstaller_found: bool,
        directory_found: bool,
    }
    impl PathProbe for Probe {
        fn probe(&self, _: &str, kind: TargetKind) -> ProbeResult {
            if match kind {
                TargetKind::Directory => self.directory_found,
                _ => self.uninstaller_found,
            } {
                ProbeResult::Found
            } else {
                ProbeResult::Missing
            }
        }
    }
    #[test]
    fn missing_directory_alone_is_not_enough_to_hide_an_uninstall_entry() {
        let original = fixture_snapshot(None);
        assert!(verify_orphan(
            &original,
            &Probe {
                uninstaller_found: true,
                directory_found: false
            }
        )
        .is_err());
        assert!(verify_orphan(
            &original,
            &Probe {
                uninstaller_found: false,
                directory_found: true
            }
        )
        .is_err());
        verify_orphan(
            &original,
            &Probe {
                uninstaller_found: false,
                directory_found: false,
            },
        )
        .unwrap();
    }
    #[test]
    fn msi_protected_hidden_and_ambiguous_commands_remain_read_only() {
        for flag in ["WindowsInstaller", "NoRemove", "SystemComponent"] {
            let mut original = fixture_snapshot(None);
            original.values.push(NamedValue {
                name: flag.into(),
                value: StoredValue {
                    kind: 4,
                    bytes: vec![1, 0, 0, 0],
                },
            });
            assert!(original.validate_original().is_err());
        }
        for field in ["ParentKeyName", "ParentDisplayName", "ReleaseType"] {
            let mut original = fixture_snapshot(None);
            original.values.push(NamedValue {
                name: field.into(),
                value: StoredValue {
                    kind: 1,
                    bytes: vec![65, 0],
                },
            });
            assert!(original.validate_original().is_err());
        }
        for command in [
            r"msiexec.exe /x product",
            r"C:\Windows\System32\msiexec.exe /x product",
            r"\\server\share\uninstall.exe",
            r"C:\Program Files\Example\uninstall.exe /remove",
        ] {
            let mut original = fixture_snapshot(None);
            original
                .values
                .iter_mut()
                .find(|item| item.name == "UninstallString")
                .unwrap()
                .value = StoredValue {
                kind: 1,
                bytes: command.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            };
            assert!(verify_orphan(
                &original,
                &Probe {
                    uninstaller_found: false,
                    directory_found: false
                }
            )
            .is_err());
        }
    }
    #[test]
    fn visibility_change_is_exact_and_metadata_limits_are_enforced() {
        for component in [None, Some(0)] {
            let original = fixture_snapshot(component);
            let hidden = original.hidden().unwrap();
            assert!(hidden.is_hidden());
            for item in &original.values {
                if !item.name.eq_ignore_ascii_case(COMPONENT) {
                    assert_eq!(hidden.get(&item.name), Some(&item.value));
                }
            }
            assert_eq!(
                hidden.values.len(),
                original.values.len() + usize::from(component.is_none())
            );
        }
        let mut oversized = fixture_snapshot(None);
        oversized.values[0].value.bytes = vec![0; 32_769];
        assert!(oversized.validate().is_err());
        let mut duplicate = fixture_snapshot(None);
        duplicate.values.push(duplicate.values[0].clone());
        assert!(duplicate.validate().is_err());
        let mut link = fixture_snapshot(None);
        link.values[0].value.kind = 6;
        assert!(link.validate().is_err());
        for key in ["", ".", "..", "child\\nested", "../escape"] {
            assert!(validate_uninstall_name(key).is_err());
        }
    }

    #[test]
    fn an_existing_quiet_uninstaller_blocks_repair_even_if_the_main_uninstaller_is_missing() {
        struct QuietExists;
        impl PathProbe for QuietExists {
            fn probe(&self, path: &str, _: TargetKind) -> ProbeResult {
                if path.ends_with("quiet.exe") {
                    ProbeResult::Found
                } else {
                    ProbeResult::Missing
                }
            }
        }
        let mut original = fixture_snapshot(None);
        original.values.iter_mut().find(|item| item.name == "QuietUninstallString").unwrap().value = StoredValue { kind: 1, bytes: r#""C:\Example\quiet.exe" /quiet"#.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        assert!(verify_orphan(&original, &QuietExists)
            .unwrap_err()
            .contains("QuietUninstallString"));
    }
}
