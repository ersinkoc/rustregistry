use crate::changes::{NamedValue, StoredValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UrlMetadataBackup {
    pub path_name: String,
    pub search_path: StoredValue,
    pub values: Vec<NamedValue>,
}

pub fn is_url_value(name: &str) -> bool {
    name.eq_ignore_ascii_case("SupportedProtocols") || name.eq_ignore_ascii_case("UseUrl")
}
pub fn validate_value(name: &str, value: &StoredValue) -> Result<(), String> {
    if name.eq_ignore_ascii_case("UseUrl") {
        if value.kind != 4 || ![vec![0, 0, 0, 0], vec![1, 0, 0, 0]].contains(&value.bytes) {
            return Err(
                "Only a conventional zero/one REG_DWORD UseUrl value supports cleanup.".into(),
            );
        }
    } else if name.eq_ignore_ascii_case("SupportedProtocols") {
        if value.kind != 1 {
            return Err("SupportedProtocols must be a literal REG_SZ scheme list.".into());
        }
        let text = value.text()?;
        let schemes: Vec<_> = text.split(':').collect();
        let mut seen = std::collections::HashSet::new();
        if text.len() > 512
            || schemes.len() > 16
            || schemes.iter().any(|s| {
                let b = s.as_bytes();
                b.is_empty()
                    || b.len() > 32
                    || !b[0].is_ascii_alphabetic()
                    || !b[1..]
                        .iter()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-'))
                    || !seen.insert(s.to_ascii_lowercase())
            })
        {
            return Err(
                "Only bounded, unique colon-separated literal URL schemes support cleanup.".into(),
            );
        }
    } else {
        return Err("Unsupported App Paths URL metadata name.".into());
    }
    Ok(())
}
pub fn display_value(name: &str, value: &StoredValue) -> Result<String, String> {
    validate_value(name, value)?;
    if value.kind == 4 {
        Ok(value.bytes[0].to_string())
    } else {
        value.text()
    }
}
impl UrlMetadataBackup {
    pub fn validate(&self) -> Result<(), String> {
        if !self.path_name.eq_ignore_ascii_case("Path")
            || self.values.is_empty()
            || self.values.len() > 2
        {
            return Err("URL metadata requires a bounded existing search path and one or two recognized values.".into());
        }
        crate::app_leftovers::literal_directory(&self.search_path)?;
        let mut names = std::collections::HashSet::new();
        for v in &self.values {
            validate_value(&v.name, &v.value)?;
            if !names.insert(v.name.to_ascii_lowercase()) {
                return Err("Duplicate URL metadata names remain protected.".into());
            }
        }
        Ok(())
    }
    pub fn original(&self, name: &str) -> Option<&StoredValue> {
        self.values
            .iter()
            .find(|v| v.name == name)
            .map(|v| &v.value)
    }
}
