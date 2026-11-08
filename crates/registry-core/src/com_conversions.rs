use crate::changes::{NamedValue, StoredValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversionGuard {
    pub values: Vec<NamedValue>,
}
impl ConversionGuard {
    pub fn validate(&self) -> Result<(), String> {
        crate::prog_ids::ProgIdGuard {
            values: self.values.clone(),
        }
        .validate()
        .map_err(|_| {
            "Only bounded default class-description metadata supports AutoConvertTo recovery."
                .into()
        })
    }
}

pub fn mapping_target(value: &StoredValue) -> Result<String, String> {
    if value.kind != 1 {
        return Err(
            "AutoConvertTo supports only a literal REG_SZ CLSID. Other types remain unverified."
                .into(),
        );
    }
    crate::prog_ids::mapping_clsid(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionState {
    pub value: Option<StoredValue>,
    pub guard: ConversionGuard,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversionBackup {
    pub owner: String,
    pub target: String,
    pub guard: ConversionGuard,
}
impl ConversionBackup {
    pub fn validate(&self) -> Result<(), String> {
        crate::com::validate_clsid(&self.owner)?;
        crate::com::validate_clsid(&self.target)?;
        if self.owner.eq_ignore_ascii_case(&self.target) {
            return Err("Self-referencing AutoConvertTo registrations remain read-only.".into());
        }
        self.guard.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conversion_policy_requires_distinct_literal_clsids_and_bounded_description() {
        let mut app = ConversionBackup {
            owner: "{11111111-1111-4111-8111-111111111111}".into(),
            target: "{22222222-2222-4222-8222-222222222222}".into(),
            guard: ConversionGuard { values: vec![] },
        };
        app.validate().unwrap();
        let mut value = StoredValue {
            kind: 1,
            bytes: app
                .target
                .encode_utf16()
                .chain([0, 0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        assert_eq!(mapping_target(&value).unwrap(), app.target);
        value.kind = 2;
        assert!(mapping_target(&value).unwrap_err().contains("REG_SZ"));
        app.target = app.owner.to_lowercase();
        assert!(app.validate().unwrap_err().contains("Self-referencing"));
        app.target = "%CLSID%".into();
        assert!(app.validate().is_err());
        app.target = "{22222222-2222-4222-8222-222222222222}".into();
        app.guard.values.push(NamedValue {
            name: "AppID".into(),
            value,
        });
        assert!(app
            .validate()
            .unwrap_err()
            .contains("class-description metadata"));
    }
}
