use crate::changes::{NamedValue, StoredValue};
use serde::{Deserialize, Serialize};

pub const PROG_IDS_KEY: &str = r"Software\Classes";

pub fn validate_com_progid(name: &str) -> Result<(), String> {
    if name.len() > 39
        || !name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        || !name.contains('.')
        || name.split('.').any(str::is_empty)
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
    {
        return Err("Only bounded COM ProgIDs with alphanumeric segments and periods support recovery (up to 39 ASCII characters).".into());
    }
    Ok(())
}

pub fn mapping_clsid(value: &StoredValue) -> Result<String, String> {
    let id = value.text()?;
    crate::com::validate_clsid(&id)?;
    Ok(id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgIdGuard {
    pub values: Vec<NamedValue>,
}
impl ProgIdGuard {
    pub fn validate(&self) -> Result<(), String> {
        crate::associations::validate_values(&self.values)?;
        if self.values.len() > 1
            || self.values.iter().any(|v| {
                !v.name.is_empty()
                    || ![1, 2].contains(&v.value.kind)
                    || (v.value.text().is_err()
                        && !(v.value.bytes.len().is_multiple_of(2)
                            && v.value.bytes.iter().all(|b| *b == 0)))
            })
        {
            return Err(
                "Only bounded default description metadata supports ProgID recovery.".into(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgIdState {
    pub value: Option<StoredValue>,
    pub guard: ProgIdGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgIdBackup {
    pub prog_id: String,
    pub clsid: String,
    pub guard: ProgIdGuard,
}
impl ProgIdBackup {
    pub fn validate(&self) -> Result<(), String> {
        validate_com_progid(&self.prog_id)?;
        crate::com::validate_clsid(&self.clsid)?;
        self.guard.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn com_progid_policy_bounds_names_literal_guids_and_description_metadata() {
        for name in [
            "Example.Component.1",
            "Example.Component",
            &format!("A.{}", "x".repeat(37)),
        ] {
            validate_com_progid(name).unwrap();
        }
        for name in [
            "",
            ".ext",
            "CLSID",
            "1Example.App",
            "A..B",
            "A.B.",
            "A_B.C",
            "A-B.C",
            "A.é",
            r"Example.App\CLSID",
            &format!("A.{}", "x".repeat(38)),
        ] {
            assert!(validate_com_progid(name).is_err(), "{name}");
        }
        let valid = text("{11111111-1111-4111-8111-111111111111}");
        mapping_clsid(&valid).unwrap();
        for raw in [
            "11111111-1111-4111-8111-111111111111",
            "{00000000-0000-0000-0000-000000000000}",
            "%CLSID%",
            "{11111111-1111-4111-8111-111111111111} extra",
        ] {
            assert!(mapping_clsid(&text(raw)).is_err());
        }
        let mut wrong_type = valid;
        wrong_type.kind = 4;
        assert!(mapping_clsid(&wrong_type).is_err());
        let mut guard = ProgIdGuard {
            values: vec![NamedValue {
                name: String::new(),
                value: text("Friendly description"),
            }],
        };
        guard.validate().unwrap();
        guard.values[0].name = "Unknown".into();
        assert!(guard.validate().is_err());
        guard.values[0].name.clear();
        guard.values[0].value.kind = 6;
        assert!(guard.validate().is_err());
    }
}
