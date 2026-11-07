use crate::changes::{NamedValue, StoredValue};
pub use crate::interfaces::{mapping_library as mapping_clsid, INTERFACES_KEY};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyGuard {
    pub values: Vec<NamedValue>,
    pub type_lib_values: Option<Vec<NamedValue>>,
}
impl ProxyGuard {
    pub fn validate(&self) -> Result<(), String> {
        crate::prog_ids::ProgIdGuard {
            values: self.values.clone(),
        }
        .validate()?;
        if let Some(values) = &self.type_lib_values {
            crate::associations::validate_values(values)?;
            if !(1..=2).contains(&values.len()) || !values.iter().any(|v| v.name.is_empty()) {
                return Err("Only a complete flat TypeLib reference with optional Version metadata supports proxy recovery.".into());
            }
            for value in values {
                if value.name.is_empty() {
                    mapping_clsid(&value.value)?;
                } else if value.name.eq_ignore_ascii_case("Version") {
                    crate::type_libraries::validate_version(&value.value.text()?)?;
                } else {
                    return Err(
                        "Unknown TypeLib metadata remains outside proxy recovery scope.".into(),
                    );
                }
            }
        }
        Ok(())
    }
    pub fn value_count(&self) -> usize {
        self.values.len() + self.type_lib_values.as_ref().map_or(0, Vec::len)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyState {
    pub value: Option<StoredValue>,
    pub guard: ProxyGuard,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProxyBackup {
    pub iid: String,
    pub clsid: String,
    pub guard: ProxyGuard,
}
impl ProxyBackup {
    pub fn validate(&self) -> Result<(), String> {
        crate::com::validate_clsid(&self.iid)?;
        crate::com::validate_clsid(&self.clsid)?;
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
    fn proxy_guards_preserve_optional_typelib_and_reject_ambiguous_metadata() {
        ProxyGuard {
            values: vec![],
            type_lib_values: None,
        }
        .validate()
        .unwrap();
        let guard = ProxyGuard {
            values: vec![value("", "Description")],
            type_lib_values: Some(vec![
                value("", "{11111111-1111-4111-8111-111111111111}"),
                value("Version", "1.0"),
            ]),
        };
        guard.validate().unwrap();
        for scenario in 0..7 {
            let mut changed = guard.clone();
            match scenario {
                0 => changed.values[0].name = "Unknown".into(),
                1 => changed.type_lib_values = Some(vec![]),
                2 => changed.type_lib_values.as_mut().unwrap()[0] = value("", "%LIBID%"),
                3 => changed.type_lib_values.as_mut().unwrap()[1] = value("Version", "01.0"),
                4 => changed.type_lib_values.as_mut().unwrap()[1] = value("Unknown", "1.0"),
                5 => changed.type_lib_values.as_mut().unwrap()[0].value.kind = 4,
                6 => changed
                    .type_lib_values
                    .as_mut()
                    .unwrap()
                    .push(value("VERSION", "1.0")),
                _ => unreachable!(),
            }
            assert!(changed.validate().is_err(), "scenario {scenario}");
        }
    }
}
