use crate::changes::{NamedValue, StoredValue};
use serde::{Deserialize, Serialize};

pub const INTERFACES_KEY: &str = r"Software\Classes\Interface";
pub use crate::prog_ids::mapping_clsid as mapping_library;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterfaceGuard {
    pub values: Vec<NamedValue>,
    pub type_lib_values: Vec<NamedValue>,
    pub proxy_values: Option<Vec<NamedValue>>,
}
impl InterfaceGuard {
    pub fn validate(&self) -> Result<(), String> {
        crate::prog_ids::ProgIdGuard {
            values: self.values.clone(),
        }
        .validate()?;
        crate::associations::validate_values(&self.type_lib_values)?;
        if self.type_lib_values.len() > 1 {
            return Err("Only optional Version metadata supports recovery.".into());
        }
        for value in &self.type_lib_values {
            if !value.name.eq_ignore_ascii_case("Version") {
                return Err("Unknown interface TypeLib metadata remains read-only.".into());
            }
            crate::type_libraries::validate_version(&value.value.text()?)?;
        }
        if let Some(values) = &self.proxy_values {
            crate::associations::validate_values(values)?;
            if values.len() != 1 || !values[0].name.is_empty() {
                return Err("Only a literal default proxy CLSID supports recovery.".into());
            }
            mapping_library(&values[0].value)?;
        }
        Ok(())
    }
    pub fn value_count(&self) -> usize {
        self.values.len()
            + self.type_lib_values.len()
            + self.proxy_values.as_ref().map_or(0, Vec::len)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceState {
    pub value: Option<StoredValue>,
    pub guard: InterfaceGuard,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterfaceBackup {
    pub iid: String,
    pub library_id: String,
    pub guard: InterfaceGuard,
}
impl InterfaceBackup {
    pub fn validate(&self) -> Result<(), String> {
        crate::com::validate_clsid(&self.iid)?;
        crate::com::validate_clsid(&self.library_id)?;
        self.guard.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value(name: &str, text: &str) -> NamedValue {
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
    fn interface_guard_bounds_version_proxy_and_unknown_metadata() {
        let guard = InterfaceGuard {
            values: vec![value("", "Description")],
            type_lib_values: vec![value("Version", "1.0")],
            proxy_values: Some(vec![value("", "{11111111-1111-4111-8111-111111111111}")]),
        };
        guard.validate().unwrap();
        for scenario in 0..6 {
            let mut changed = guard.clone();
            match scenario {
                0 => changed.type_lib_values[0].name = "Unknown".into(),
                1 => changed.type_lib_values[0].value = value("", "01.0").value,
                2 => changed.proxy_values.as_mut().unwrap()[0].name = "Unknown".into(),
                3 => changed.proxy_values.as_mut().unwrap()[0].value = value("", "%CLSID%").value,
                4 => changed.values[0].name = "Unknown".into(),
                5 => changed.type_lib_values[0].value.kind = 4,
                _ => unreachable!(),
            }
            assert!(changed.validate().is_err());
        }
    }
}
