use crate::changes::{NamedValue, StoredValue};
use serde::{Deserialize, Serialize};

pub const CLASSES_KEY: &str = r"Software\Classes";
pub const FILE_EXTS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts";
pub const OPEN_WITH: &str = "OpenWithProgids";

pub fn validate_extension(name: &str) -> Result<(), String> {
    if !(2..=64).contains(&name.len())
        || !name.starts_with('.')
        || !name[1..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-+".contains(&b))
    {
        return Err("Only a single, bounded ASCII file extension is supported.".into());
    }
    Ok(())
}

pub fn validate_progid(name: &str) -> Result<(), String> {
    if name.len() > 128
        || !name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        || !name.contains('.')
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("Only a bounded, single ASCII file-type identifier is supported.".into());
    }
    Ok(())
}

pub fn validate_suggestion(value: &StoredValue) -> Result<(), String> {
    if !((value.kind == 0 && value.bytes.is_empty())
        || (value.kind == 1 && (value.bytes.is_empty() || value.bytes == [0, 0])))
    {
        return Err("Only empty REG_NONE or REG_SZ Open with suggestions can be repaired.".into());
    }
    Ok(())
}

pub(crate) fn validate_values(values: &[NamedValue]) -> Result<(), String> {
    let mut names = std::collections::HashSet::new();
    if values.len() > 64 || values.iter().map(|v| v.value.bytes.len()).sum::<usize>() > 32_768 {
        return Err("File association metadata exceeds the supported backup limits.".into());
    }
    for item in values {
        if !item.name.is_ascii()
            || item.name.len() > 256
            || item.name.contains('\0')
            || item.value.kind > 11
            || item.value.kind == 6
            || !names.insert(item.name.to_ascii_lowercase())
        {
            return Err("File association metadata is unsupported or ambiguous.".into());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssociationGuard {
    pub suggestions: Vec<NamedValue>,
    pub extension_values: Vec<NamedValue>,
    pub machine_extension_values: Option<Vec<NamedValue>>,
    pub user_choice: Option<Vec<NamedValue>>,
}

impl AssociationGuard {
    pub fn validate(&self, progid: &str) -> Result<(), String> {
        validate_progid(progid)?;
        for values in [
            Some(&self.suggestions),
            Some(&self.extension_values),
            self.machine_extension_values.as_ref(),
            self.user_choice.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_values(values)?;
        }
        if self
            .suggestions
            .iter()
            .any(|v| v.name.eq_ignore_ascii_case(progid))
        {
            return Err("The guarded suggestion list must exclude the selected value.".into());
        }
        for (values, field) in [
            (self.extension_values.as_slice(), ""),
            (self.machine_extension_values.as_deref().unwrap_or(&[]), ""),
            (self.user_choice.as_deref().unwrap_or(&[]), "ProgId"),
        ] {
            if let Some(item) = values.iter().find(|v| v.name.eq_ignore_ascii_case(field)) {
                let empty = [1, 2].contains(&item.value.kind)
                    && (item.value.bytes.is_empty() || item.value.bytes == [0, 0]);
                if !empty && item.value.text()?.eq_ignore_ascii_case(progid) {
                    return Err("This identifier is a default application selection. It is outside repair scope.".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationState {
    pub value: Option<StoredValue>,
    pub guard: AssociationGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssociationBackup {
    pub extension: String,
    pub guard: AssociationGuard,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selectors_and_empty_value_types_are_strictly_bounded() {
        for extension in [".txt", ".RR123"] {
            validate_extension(extension).unwrap();
        }
        for extension in ["", ".", ".a\\b", ".a.b", ".é", "txt"] {
            assert!(validate_extension(extension).is_err());
        }
        for progid in ["Example.Document", "AppX.test-1_2"] {
            validate_progid(progid).unwrap();
        }
        for progid in ["CLSID", ".txt", "x\\y.z", "a/b.c", "é.x", "a."] {
            assert!(validate_progid(progid).is_err());
        }
        for value in [
            StoredValue {
                kind: 0,
                bytes: vec![],
            },
            StoredValue {
                kind: 1,
                bytes: vec![0, 0],
            },
        ] {
            validate_suggestion(&value).unwrap();
        }
        for value in [
            StoredValue {
                kind: 0,
                bytes: vec![0],
            },
            StoredValue {
                kind: 2,
                bytes: vec![0, 0],
            },
            StoredValue {
                kind: 1,
                bytes: vec![65, 0],
            },
        ] {
            assert!(validate_suggestion(&value).is_err());
        }
    }
}
