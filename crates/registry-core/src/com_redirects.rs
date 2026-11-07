use crate::changes::StoredValue;
pub use crate::prog_ids::ProgIdGuard as RedirectionGuard;
use serde::{Deserialize, Serialize};

pub fn mapping_target(value: &StoredValue) -> Result<String, String> {
    if value.kind != 1 {
        return Err(
            "TreatAs supports only a literal REG_SZ CLSID. Other types remain unverified.".into(),
        );
    }
    crate::prog_ids::mapping_clsid(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectionState {
    pub value: Option<StoredValue>,
    pub guard: RedirectionGuard,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedirectionBackup {
    pub owner: String,
    pub target: String,
    pub guard: RedirectionGuard,
}
impl RedirectionBackup {
    pub fn validate(&self) -> Result<(), String> {
        crate::com::validate_clsid(&self.owner)?;
        crate::com::validate_clsid(&self.target)?;
        if self.owner.eq_ignore_ascii_case(&self.target) {
            return Err("Self-referencing TreatAs registrations remain read-only.".into());
        }
        self.guard.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redirection_policy_requires_distinct_literal_clsids_and_bounded_description() {
        let mut app = RedirectionBackup {
            owner: "{11111111-1111-4111-8111-111111111111}".into(),
            target: "{22222222-2222-4222-8222-222222222222}".into(),
            guard: RedirectionGuard { values: vec![] },
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
    }
}
