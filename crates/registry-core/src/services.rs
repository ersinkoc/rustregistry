use crate::{
    analyze_target,
    changes::{NamedValue, StoredValue},
    EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};

pub const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";
pub const MANUAL: u32 = 3;
pub const DISABLED: u32 = 4;

pub fn validate_service_name(name: &str) -> Result<(), String> {
    if !name
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        || name.len() > 256
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err("Only a single bounded ASCII service name is supported.".into());
    }
    Ok(())
}
pub fn dword(value: u32) -> StoredValue {
    StoredValue {
        kind: 4,
        bytes: value.to_le_bytes().to_vec(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub service_type: u32,
    pub start_type: u32,
    pub error_control: u32,
    pub binary_path: String,
    pub load_order_group: String,
    pub tag_id: u32,
    pub dependencies: Vec<String>,
    pub account: String,
    pub display_name: String,
    pub security: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceSnapshot {
    pub values: Vec<NamedValue>,
    pub security_values: Option<Vec<NamedValue>>,
    pub config: ServiceConfig,
}
impl ServiceSnapshot {
    pub fn get(&self, name: &str) -> Option<&StoredValue> {
        self.values
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case(name))
            .map(|item| &item.value)
    }
    pub fn validate(&self) -> Result<(), String> {
        crate::associations::validate_values(&self.values)?;
        if let Some(values) = &self.security_values {
            crate::associations::validate_values(values)?;
            if values
                .iter()
                .any(|item| !item.name.eq_ignore_ascii_case("Security") || item.value.kind != 3)
            {
                return Err("Unsupported service security metadata.".into());
            }
        }
        if self.values.iter().any(|item| {
            ![
                "type",
                "start",
                "errorcontrol",
                "imagepath",
                "objectname",
                "displayname",
                "description",
            ]
            .contains(&item.name.to_ascii_lowercase().as_str())
        }) {
            return Err("Service dependencies, triggers, recovery, custom parameters, and unknown metadata remain outside repair scope.".into());
        }
        let config = &self.config;
        if config.service_type != 16
            || ![MANUAL, DISABLED].contains(&config.start_type)
            || config.error_control > 1
            || !config.load_order_group.is_empty()
            || config.tag_id != 0
            || !config.dependencies.is_empty()
            || !config
                .account
                .eq_ignore_ascii_case(r"NT AUTHORITY\LocalService")
            || config.security.len() > 32_768
        {
            return Err("Only independent, noncritical, own-process LocalService registrations with Manual/Disabled startup are supported. Drivers, Windows/shared/protected services and privileged/custom accounts remain read-only.".into());
        }
        for (name, expected) in [
            ("Type", config.service_type),
            ("Start", config.start_type),
            ("ErrorControl", config.error_control),
        ] {
            if self.get(name) != Some(&dword(expected)) {
                return Err("The service registry and SCM configuration disagree.".into());
            }
        }
        if self
            .get("ImagePath")
            .ok_or("Service image path is missing.")?
            .text()?
            != config.binary_path
            || !self
                .get("ObjectName")
                .ok_or("Service account is missing.")?
                .text()?
                .eq_ignore_ascii_case(&config.account)
        {
            return Err("The service image/account metadata does not match SCM.".into());
        }
        Ok(())
    }
    pub fn validate_original(&self) -> Result<(), String> {
        self.validate()?;
        if self.config.start_type != MANUAL {
            return Err("Only a Manual service can be reviewed for disabling.".into());
        }
        Ok(())
    }
    pub fn disabled(&self) -> Result<Self, String> {
        self.validate_original()?;
        let mut result = self.clone();
        result.config.start_type = DISABLED;
        result
            .values
            .iter_mut()
            .find(|item| item.name.eq_ignore_ascii_case("Start"))
            .ok_or("Missing startup metadata.")?
            .value = dword(DISABLED);
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct ServiceState {
    pub snapshot: ServiceSnapshot,
    pub stopped: bool,
    pub has_dependents: bool,
    pub change_allowed: bool,
}
impl ServiceState {
    pub fn validate_change(&self) -> Result<(), String> {
        self.snapshot.validate()?;
        if !self.stopped || self.has_dependents {
            return Err("The service must be stopped and have no dependent services. It will never be stopped automatically.".into());
        }
        if !self.change_allowed {
            return Err("Windows has not granted service configuration access to this process. This service remains read-only; permissions are never changed automatically.".into());
        }
        Ok(())
    }
}

pub fn verify_missing_service(
    snapshot: &ServiceSnapshot,
    probe: &impl PathProbe,
) -> Result<(), String> {
    snapshot.validate_original()?;
    if snapshot.config.binary_path.contains('%') {
        return Err("Service-account environment expansion is outside repair scope. A literal local executable path is required.".into());
    }
    let environment = Environment::current();
    let assessment = analyze_target(
        &snapshot.config.binary_path,
        TargetKind::Command,
        &environment,
        probe,
    );
    let target = assessment
        .target
        .as_deref()
        .ok_or("The service executable is ambiguous.")?;
    let windows = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    if assessment.status != EntryStatus::Review
        || assessment.code != "target_missing"
        || !target.to_ascii_lowercase().ends_with(".exe")
        || target.to_ascii_lowercase().starts_with(&format!(
            "{}\\",
            windows.trim_end_matches('\\').to_ascii_lowercase()
        ))
    {
        return Err("Only a confirmed missing explicit local executable outside Windows supports service repair.".into());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceBackup {
    pub service_name: String,
    pub snapshot: ServiceSnapshot,
}

#[cfg(test)]
pub(crate) fn fixture_snapshot() -> ServiceSnapshot {
    let text = |value: &str| StoredValue {
        kind: 1,
        bytes: format!("{value}\0")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    let config = ServiceConfig {
        service_type: 16,
        start_type: MANUAL,
        error_control: 0,
        binary_path: r#""C:\RustRegistryMissing\service.exe""#.into(),
        load_order_group: String::new(),
        tag_id: 0,
        dependencies: vec![],
        account: r"NT AUTHORITY\LocalService".into(),
        display_name: "Example service".into(),
        security: vec![1, 0, 4, 128],
    };
    let mut values = vec![
        NamedValue {
            name: "Type".into(),
            value: dword(16),
        },
        NamedValue {
            name: "Start".into(),
            value: dword(MANUAL),
        },
        NamedValue {
            name: "ErrorControl".into(),
            value: dword(0),
        },
    ];
    for (name, value) in [
        ("ImagePath", config.binary_path.as_str()),
        ("ObjectName", config.account.as_str()),
        ("DisplayName", config.display_name.as_str()),
    ] {
        values.push(NamedValue {
            name: name.into(),
            value: text(value),
        });
    }
    values.sort_by_key(|item| item.name.to_ascii_lowercase());
    ServiceSnapshot {
        values,
        security_values: None,
        config,
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
    #[test]
    fn service_policy_accepts_only_a_simple_missing_manual_localservice_registration() {
        let original = fixture_snapshot();
        verify_missing_service(&original, &Missing).unwrap();
        assert_eq!(original.disabled().unwrap().config.start_type, DISABLED);
        for name in ["", "..\\other", "a/b", "a b", "é"] {
            assert!(validate_service_name(name).is_err());
        }
        let state = ServiceState {
            snapshot: original.clone(),
            stopped: true,
            has_dependents: false,
            change_allowed: true,
        };
        state.validate_change().unwrap();
        for invalid in [
            ServiceState {
                stopped: false,
                ..state.clone()
            },
            ServiceState {
                has_dependents: true,
                ..state.clone()
            },
            ServiceState {
                change_allowed: false,
                ..state.clone()
            },
        ] {
            assert!(invalid.validate_change().is_err());
        }
        for scenario in 0..7 {
            let mut invalid = original.clone();
            match scenario {
                0 => invalid.config.service_type = 1,
                1 => invalid.config.start_type = 2,
                2 => invalid.config.error_control = 3,
                3 => invalid.config.account = "LocalSystem".into(),
                4 => invalid.config.dependencies.push("CriticalService".into()),
                5 => invalid.values.push(NamedValue {
                    name: "FailureActions".into(),
                    value: StoredValue {
                        kind: 3,
                        bytes: vec![],
                    },
                }),
                6 => {
                    invalid.config.binary_path =
                        r#""C:\Windows\System32\missing-service.exe""#.into()
                }
                _ => unreachable!(),
            }
            assert!(
                verify_missing_service(&invalid, &Missing).is_err(),
                "scenario {scenario}"
            );
        }
    }
}
