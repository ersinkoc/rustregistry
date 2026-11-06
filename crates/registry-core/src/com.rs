use crate::{
    analyze_target,
    changes::{NamedValue, StoredValue},
    EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};

pub const CLSID_KEY: &str = r"Software\Classes\CLSID";
pub const INPROC_SERVER: &str = "InprocServer32";

pub fn validate_clsid(name: &str) -> Result<(), String> {
    if name.len() != 38 || !name.starts_with('{') || !name.ends_with('}') {
        return Err("A single braced COM class GUID is required.".into());
    }
    let id =
        uuid::Uuid::parse_str(&name[1..37]).map_err(|_| "Invalid COM class GUID.".to_string())?;
    if !format!("{{{id}}}").eq_ignore_ascii_case(name) || id.is_nil() {
        return Err("Unsupported COM class GUID.".into());
    }
    Ok(())
}

pub fn verify_missing_dll(value: &StoredValue, probe: &impl PathProbe) -> Result<(), String> {
    let assessment = analyze_target(
        &value.text()?,
        TargetKind::File,
        &Environment::current(),
        probe,
    );
    if assessment.status != EntryStatus::Review
        || assessment.code != "target_missing"
        || !assessment
            .target
            .is_some_and(|target| target.to_ascii_lowercase().ends_with(".dll"))
    {
        return Err(
            "The explicit local DLL is not confirmed missing. This COM mapping cannot be repaired."
                .into(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComGuard {
    pub class_values: Vec<NamedValue>,
    pub server_values: Vec<NamedValue>,
}
impl ComGuard {
    pub fn validate(&self) -> Result<(), String> {
        crate::associations::validate_values(&self.class_values)?;
        crate::associations::validate_values(&self.server_values)?;
        // An allowlist excludes AppID, managed servers, services, and unknown activation metadata.
        if self
            .class_values
            .iter()
            .any(|item| !item.name.is_empty() || item.value.kind != 1)
            || self.server_values.iter().any(|item| {
                !item.name.eq_ignore_ascii_case("ThreadingModel") || item.value.kind != 1
            })
        {
            return Err("Only a simple DLL registration with an optional class description and ThreadingModel is repairable. Alternative or unknown activation metadata remains read-only.".into());
        }
        if let Some(threading) = self.server_values.first() {
            let value = &threading.value;
            let empty = value.bytes.is_empty() || value.bytes == [0, 0];
            if !empty
                && !["apartment", "both", "free", "neutral"]
                    .contains(&value.text()?.to_ascii_lowercase().as_str())
            {
                return Err(
                    "Unsupported COM threading model. The mapping remains read-only.".into(),
                );
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComState {
    pub value: Option<StoredValue>,
    pub guard: ComGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComBackup {
    pub clsid: String,
    pub view: String,
    pub guard: ComGuard,
}
impl ComBackup {
    pub fn validate(&self) -> Result<(), String> {
        validate_clsid(&self.clsid)?;
        if self.view != "64" {
            return Err("Only the current-user 64-bit COM view supports protected changes.".into());
        }
        self.guard.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Missing;
    impl PathProbe for Missing {
        fn probe(&self, _: &str, _: TargetKind) -> crate::ProbeResult {
            crate::ProbeResult::Missing
        }
    }
    fn text(s: &str) -> StoredValue {
        StoredValue {
            kind: 1,
            bytes: format!("{s}\0")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    #[test]
    fn com_repair_requires_a_strict_guid_missing_local_dll_and_simple_metadata() {
        validate_clsid("{11111111-1111-4111-8111-111111111111}").unwrap();
        for name in [
            "../escape",
            "11111111-1111-4111-8111-111111111111",
            "{00000000-0000-0000-0000-000000000000}",
            "{11111111111141118111111111111111}",
        ] {
            assert!(validate_clsid(name).is_err());
        }
        verify_missing_dll(&text(r"C:\Missing\server.dll"), &Missing).unwrap();
        for value in [
            r"server.dll",
            r"\\server\share\server.dll",
            r"C:\Missing\server.exe",
            r"%UNKNOWN_COM_VARIABLE%\server.dll",
            r"C:\Missing\server.dll /command",
        ] {
            assert!(verify_missing_dll(&text(value), &Missing).is_err());
        }
        let guard = ComGuard {
            class_values: vec![],
            server_values: vec![NamedValue {
                name: "ThreadingModel".into(),
                value: text("Both"),
            }],
        };
        guard.validate().unwrap();
        for name in ["AppID", "LocalService", "TreatAs", "CustomActivation"] {
            let mut other = guard.clone();
            other.class_values.push(NamedValue {
                name: name.into(),
                value: text("value"),
            });
            assert!(other.validate().is_err());
        }
        for name in [
            "Assembly",
            "CodeBase",
            "RuntimeVersion",
            "Class",
            "ServerExecutable",
        ] {
            let mut other = guard.clone();
            other.server_values.push(NamedValue {
                name: name.into(),
                value: text("value"),
            });
            assert!(other.validate().is_err());
        }
    }
}
