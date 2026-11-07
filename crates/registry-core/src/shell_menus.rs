use crate::{
    applications::assess_command,
    changes::{NamedValue, StoredValue},
    EntryStatus, Environment, PathProbe,
};
use serde::{Deserialize, Serialize};
pub const FILE_MENUS_KEY: &str = r"Software\Classes\*\shell";
pub const BACKGROUND_MENUS_KEY: &str = r"Software\Classes\Directory\Background\shell";
pub const PROGRAMMATIC_ONLY: &str = "ProgrammaticAccessOnly";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MenuLocation {
    Files,
    DirectoryBackground,
}
impl MenuLocation {
    pub fn path(self) -> &'static str {
        match self {
            Self::Files => FILE_MENUS_KEY,
            Self::DirectoryBackground => BACKGROUND_MENUS_KEY,
        }
    }
    pub fn components(self) -> &'static [&'static str] {
        match self {
            Self::Files => &["*", "shell"],
            Self::DirectoryBackground => &["Directory", "Background", "shell"],
        }
    }
    pub fn from_path(path: &str) -> Option<Self> {
        [Self::Files, Self::DirectoryBackground]
            .into_iter()
            .find(|p| p.path() == path)
    }
}
pub fn validate_custom_verb(name: &str) -> Result<(), String> {
    let lower = name.to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || lower.starts_with("windows.")
        || lower.starts_with("microsoft.")
        || [
            "open",
            "opennew",
            "opennewwindow",
            "opennewprocess",
            "openwith",
            "explore",
            "find",
            "print",
            "printto",
            "edit",
            "runas",
            "runasuser",
            "properties",
            "delete",
            "rename",
            "cut",
            "copy",
            "paste",
            "new",
            "share",
            "cmd",
            "powershell",
            "windowsterminal",
        ]
        .contains(&lower.as_str())
    {
        return Err("Only bounded custom verb names support recovery; canonical and system verbs remain read-only.".into());
    }
    Ok(())
}
pub fn verify_missing_menu_command(
    value: &StoredValue,
    probe: &impl PathProbe,
) -> Result<(), String> {
    crate::applications::verify_missing_command(value, probe)?;
    let result = assess_command(&value.text()?, &Environment::current(), probe);
    let path = result
        .target
        .filter(|_| result.status == EntryStatus::Review)
        .ok_or("The context-menu executable is not confirmed missing.")?;
    crate::shared_dlls::validate_shared_dll_path(&format!("{}.dll",&path[..path.len()-4])).map_err(|_|"Only literal local menu executables outside Windows, without aliases or indirection, support recovery.".into())
}
fn empty_string(v: &StoredValue) -> bool {
    v.kind == 1 && v.bytes.len().is_multiple_of(2) && v.bytes.iter().all(|b| *b == 0)
}
fn validate_root(values: &[NamedValue]) -> Result<(), String> {
    crate::associations::validate_values(values)?;
    if values.len() > 1
        || values
            .iter()
            .any(|v| !v.name.is_empty() || !empty_string(&v.value))
    {
        return Err(
            "A preferred/default verb or unknown shell-root metadata blocks menu recovery.".into(),
        );
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MenuSnapshot {
    pub user_root_values: Vec<NamedValue>,
    pub machine_root_values: Option<Vec<NamedValue>>,
    pub verb_values: Vec<NamedValue>,
    pub command_values: Vec<NamedValue>,
}
impl MenuSnapshot {
    pub fn command(&self) -> Result<&StoredValue, String> {
        self.command_values
            .iter()
            .find(|v| v.name.is_empty())
            .map(|v| &v.value)
            .ok_or("The menu command is absent.".into())
    }
    pub fn is_hidden(&self) -> bool {
        self.verb_values
            .iter()
            .any(|v| v.name.eq_ignore_ascii_case(PROGRAMMATIC_ONLY))
    }
    pub fn value_count(&self) -> usize {
        self.user_root_values.len()
            + self.machine_root_values.as_ref().map_or(0, Vec::len)
            + self.verb_values.len()
            + self.command_values.len()
    }
    pub fn validate(&self) -> Result<(), String> {
        validate_root(&self.user_root_values)?;
        if let Some(values) = &self.machine_root_values {
            validate_root(values)?;
        }
        for values in [&self.verb_values, &self.command_values] {
            crate::associations::validate_values(values)?;
        }
        if self.value_count() > 64
            || self
                .verb_values
                .iter()
                .chain(&self.command_values)
                .map(|v| v.value.bytes.len())
                .sum::<usize>()
                > 32768
            || self.command_values.len() != 1
            || !self.command_values[0].name.is_empty()
        {
            return Err("Only a bounded flat default command without delegated or alternative activation supports menu recovery.".into());
        }
        self.command()?.text()?;
        for item in &self.verb_values {
            let name = item.name.to_ascii_lowercase();
            if name == "programmaticaccessonly" || name == "extended" {
                if !empty_string(&item.value) {
                    return Err("Menu visibility flags must be empty REG_SZ values.".into());
                }
            } else if name == "position" {
                if item.value.kind != 1
                    || !["top", "bottom"]
                        .contains(&item.value.text()?.to_ascii_lowercase().as_str())
                {
                    return Err("Unknown menu position metadata remains read-only.".into());
                }
            } else if name.is_empty() || name == "muiverb" || name == "icon" {
                if ![1, 2].contains(&item.value.kind)
                    || (!empty_string(&item.value) && item.value.text().is_err())
                {
                    return Err("Malformed menu display metadata remains read-only.".into());
                }
            } else {
                return Err("Unknown, policy, cascading, or alternative activation metadata remains read-only.".into());
            }
        }
        Ok(())
    }
    pub fn validate_original(&self) -> Result<(), String> {
        self.validate()?;
        if self.is_hidden() {
            return Err(
                "This menu is already programmatic-only and cannot be hidden again.".into(),
            );
        }
        Ok(())
    }
    pub fn hidden(&self) -> Result<Self, String> {
        self.validate_original()?;
        let mut hidden = self.clone();
        hidden.verb_values.push(NamedValue {
            name: PROGRAMMATIC_ONLY.into(),
            value: StoredValue {
                kind: 1,
                bytes: vec![0, 0],
            },
        });
        hidden
            .verb_values
            .sort_by_key(|v| v.name.to_ascii_lowercase());
        hidden.validate()?;
        Ok(hidden)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MenuBackup {
    pub location: MenuLocation,
    pub verb_name: String,
    pub snapshot: MenuSnapshot,
}
impl MenuBackup {
    pub fn validate(&self) -> Result<(), String> {
        validate_custom_verb(&self.verb_name)?;
        self.snapshot.validate_original()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn value(name: &str, text: &str) -> NamedValue {
        NamedValue {
            name: name.into(),
            value: StoredValue {
                kind: 1,
                bytes: text
                    .encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            },
        }
    }
    #[test]
    fn menu_policy_preserves_metadata_excludes_defaults_system_verbs_and_unsupported_flags() {
        let snapshot = MenuSnapshot {
            user_root_values: vec![],
            machine_root_values: None,
            verb_values: vec![
                value("MUIVerb", "Open custom app"),
                value("Icon", r"C:\Preserved\app.exe,0"),
                value("Extended", ""),
            ],
            command_values: vec![value("", r#""C:\Missing App\tool.exe" "%1" %*"#)],
        };
        snapshot.validate_original().unwrap();
        assert_eq!(
            snapshot.hidden().unwrap().command_values,
            snapshot.command_values
        );
        assert!(snapshot.hidden().unwrap().validate_original().is_err());
        for name in [
            "open",
            "PrintTo",
            "runas",
            "Microsoft.Test",
            "Windows.Test",
            r"Custom\Nested",
            ".Bad",
            "",
        ] {
            assert!(validate_custom_verb(name).is_err());
        }
        validate_custom_verb("Example.Custom").unwrap();
        for scenario in 0..5 {
            let mut changed = snapshot.clone();
            match scenario {
                0 => changed.user_root_values = vec![value("", "Example.Custom")],
                1 => changed.machine_root_values = Some(vec![value("", "other")]),
                2 => changed.verb_values.push(value("SubCommands", "x")),
                3 => changed.command_values.push(value("DelegateExecute", "x")),
                4 => changed.verb_values[2].value.kind = 4,
                _ => unreachable!(),
            };
            assert!(changed.validate().is_err());
        }
    }
}
