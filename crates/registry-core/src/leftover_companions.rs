use crate::changes::NamedValue;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppPathsCompanion {
    pub values: Vec<NamedValue>,
}

impl AppPathsCompanion {
    pub fn get(&self, name: &str) -> Option<&crate::changes::StoredValue> {
        self.values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(name))
            .map(|v| &v.value)
    }
    pub fn validate(&self) -> Result<(), String> {
        crate::associations::validate_values(&self.values)?;
        if self.values.len() > 32
            || self
                .values
                .iter()
                .map(|v| v.name.len() + v.value.bytes.len())
                .sum::<usize>()
                > 16384
            || self.values.iter().any(|v| {
                [
                    "DropTarget",
                    "DelegateExecute",
                    "UseUrl",
                    "SupportedProtocols",
                ]
                .iter()
                .any(|name| v.name.eq_ignore_ascii_case(name))
            })
        {
            return Err("Unsupported metadata or alternate activation in the corroborating App Paths registration remains protected.".into());
        }
        Ok(())
    }
    pub fn verify(&self, directory: &str, executable_name: &str) -> Result<(), String> {
        self.validate()?;
        let executable = format!(r"{directory}\{executable_name}");
        let target = self.get("");
        let path = self.get("Path");
        if target.is_none() && path.is_none() {
            return Err("The corroborating App Paths registration has no exact executable or installation path evidence.".into());
        }
        if let Some(target) = target {
            if target.kind != 1 || !target.text()?.eq_ignore_ascii_case(&executable) {
                return Err("The App Paths executable does not identify the same exact missing application. Counterpart ownership remains uncertain.".into());
            }
        }
        if let Some(path) = path {
            if !crate::app_leftovers::literal_directory(path)?.eq_ignore_ascii_case(directory) {
                return Err("The App Paths search directory differs from the exact missing installation directory.".into());
            }
        }
        Ok(())
    }
    pub fn matches_current(&self, current: &Self) -> Result<(), String> {
        current.validate()?;
        let unchanged = self
            .values
            .iter()
            .filter(|v| !v.name.is_empty())
            .eq(current.values.iter().filter(|v| !v.name.is_empty()));
        if !unchanged || current.get("").is_some_and(|v| Some(v) != self.get("")) {
            return Err("The corroborating App Paths mapping, search path or metadata changed. Nothing was overwritten.".into());
        }
        Ok(())
    }
}
