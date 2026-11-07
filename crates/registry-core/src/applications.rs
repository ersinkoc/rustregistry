use crate::{
    analyze_target,
    changes::{NamedValue, StoredValue},
    Assessment, EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};

pub const APPLICATIONS_KEY: &str = r"Software\Classes\Applications";
pub const OPEN_COMMAND: &str = r"shell\open\command";
pub const NO_OPEN_WITH: &str = "NoOpenWith";

pub fn validate_application_name(name: &str) -> Result<(), String> {
    crate::changes::validate_app_path_name(name)?;
    if !name.is_ascii() || !name.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(
            "Only a single ASCII executable registration name supports application repair.".into(),
        );
    }
    Ok(())
}

fn executable_expression(raw: &str) -> &str {
    let raw = raw.trim();
    // Shell placeholders in arguments ("%1", %*) are not environment variables.
    if raw.contains('\0') {
        raw
    } else if let Some(rest) = raw.strip_prefix('"') {
        rest.find('"')
            .filter(|end| {
                rest[end + 1..].is_empty() || rest[end + 1..].starts_with(char::is_whitespace)
            })
            .map_or(raw, |end| &raw[..end + 2])
    } else {
        raw.split_whitespace().next().unwrap_or(raw)
    }
}

pub fn assess_command(raw: &str, environment: &Environment, probe: &impl PathProbe) -> Assessment {
    analyze_target(
        executable_expression(raw),
        TargetKind::Command,
        environment,
        probe,
    )
}

pub fn verify_missing_command(value: &StoredValue, probe: &impl PathProbe) -> Result<(), String> {
    let raw = value.text()?;
    if executable_expression(&raw).contains('%') {
        return Err(
            "Environment-dependent executable paths remain outside application repair scope."
                .into(),
        );
    }
    let assessment = assess_command(&raw, &Environment::current(), probe);
    if assessment.status != EntryStatus::Review
        || assessment.code != "target_missing"
        || !assessment
            .target
            .is_some_and(|p| p.to_ascii_lowercase().ends_with(".exe"))
    {
        return Err("The explicit local application executable is not confirmed missing.".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationSnapshot {
    pub application_values: Vec<NamedValue>,
    pub shell_values: Vec<NamedValue>,
    pub verb_values: Vec<NamedValue>,
    pub command_values: Vec<NamedValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationBackup {
    pub executable: String,
    pub snapshot: ApplicationSnapshot,
}

impl ApplicationSnapshot {
    pub fn command(&self) -> Result<&StoredValue, String> {
        self.command_values
            .iter()
            .find(|v| v.name.is_empty())
            .map(|v| &v.value)
            .ok_or_else(|| "The application open command is absent.".into())
    }
    pub fn value_count(&self) -> usize {
        self.application_values.len()
            + self.shell_values.len()
            + self.verb_values.len()
            + self.command_values.len()
    }
    pub fn validate(&self) -> Result<(), String> {
        let groups = [
            &self.application_values,
            &self.shell_values,
            &self.verb_values,
            &self.command_values,
        ];
        for values in groups {
            crate::associations::validate_values(values)?;
        }
        if self.value_count() > 64
            || groups
                .iter()
                .flat_map(|g| g.iter())
                .map(|v| v.value.bytes.len())
                .sum::<usize>()
                > 32_768
        {
            return Err("Application metadata exceeds the supported backup limits.".into());
        }
        if !self.shell_values.is_empty()
            || !self.verb_values.is_empty()
            || self.command_values.len() != 1
            || !self.command_values[0].name.is_empty()
        {
            return Err("Only a simple open command without delegated, DDE, or alternative activation metadata supports repair.".into());
        }
        self.command()?.text()?;
        for item in &self.application_values {
            if item.name.eq_ignore_ascii_case(NO_OPEN_WITH) {
                if item.value.kind != 1 || item.value.bytes != [0, 0] {
                    return Err(
                        "An unsupported NoOpenWith flag blocks application recovery.".into(),
                    );
                }
            } else if (!item.name.is_empty() && !item.name.eq_ignore_ascii_case("FriendlyAppName"))
                || item.value.kind != 1
            {
                return Err("Unknown or protected application metadata remains read-only.".into());
            }
        }
        Ok(())
    }
    pub fn is_hidden(&self) -> bool {
        self.application_values
            .iter()
            .any(|v| v.name.eq_ignore_ascii_case(NO_OPEN_WITH))
    }
    pub fn validate_original(&self) -> Result<(), String> {
        self.validate()?;
        if self.is_hidden() {
            return Err(
                "This application is already marked NoOpenWith and cannot be cleaned again.".into(),
            );
        }
        Ok(())
    }
    pub fn hidden(&self) -> Result<Self, String> {
        self.validate_original()?;
        let mut hidden = self.clone();
        hidden.application_values.push(NamedValue {
            name: NO_OPEN_WITH.into(),
            value: StoredValue {
                kind: 1,
                bytes: vec![0, 0],
            },
        });
        hidden
            .application_values
            .sort_by_key(|v| v.name.to_ascii_lowercase());
        hidden.validate()?;
        Ok(hidden)
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
    fn text(value: &str) -> StoredValue {
        StoredValue {
            kind: 1,
            bytes: format!("{value}\0")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    #[test]
    fn application_policy_preserves_shell_arguments_and_excludes_ambiguous_indirect_and_environment_targets(
    ) {
        for raw in [
            r#""C:\Missing App\app.exe" "%1" %*"#,
            r"C:\Missing\app.exe /open %1",
        ] {
            verify_missing_command(&text(raw), &Missing).unwrap();
        }
        for raw in [
            r"app.exe %1",
            r"C:\Missing App\app.exe %1",
            r#""%TEMP%\app.exe" "%1""#,
            r"\\server\share\app.exe",
            r"C:\Windows\System32\cmd.exe /c app.exe",
            r"C:\Missing\app.dll",
        ] {
            assert!(
                verify_missing_command(&text(raw), &Missing).is_err(),
                "{raw}"
            );
        }
        for name in [
            "../app.exe",
            "app.exe\\command",
            ".app.exe",
            "app.exe ",
            "éxample.exe",
        ] {
            assert!(validate_application_name(name).is_err());
        }
        validate_application_name("Example app.exe").unwrap();
    }
    #[test]
    fn hiding_changes_only_the_optional_flag_and_rejects_unsupported_metadata() {
        let original = ApplicationSnapshot {
            application_values: vec![],
            shell_values: vec![],
            verb_values: vec![],
            command_values: vec![NamedValue {
                name: String::new(),
                value: text(r#""C:\Missing\app.exe" "%1""#),
            }],
        };
        original.validate_original().unwrap();
        let hidden = original.hidden().unwrap();
        assert!(hidden.is_hidden());
        assert_eq!(hidden.command_values, original.command_values);
        assert!(hidden.validate_original().is_err());
        for field in ["DelegateExecute", "IsHostApp", "NoOpenWith", "Custom"] {
            let mut changed = original.clone();
            changed.application_values.push(NamedValue {
                name: field.into(),
                value: text("value"),
            });
            assert!(changed.validate_original().is_err());
        }
        let mut delegated = original;
        delegated.command_values.push(NamedValue {
            name: "DelegateExecute".into(),
            value: text("value"),
        });
        assert!(delegated.validate().is_err());
    }
}
