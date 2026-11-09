use crate::{
    app_leftovers::*,
    applications,
    changes::{NamedValue, StoredValue},
    EntryStatus, Environment, PathProbe,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupportedTypeBackup {
    pub shell_values: Vec<NamedValue>,
    pub verb_values: Vec<NamedValue>,
    pub command_values: Vec<NamedValue>,
    pub icon_values: Option<Vec<NamedValue>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_paths: Option<Box<crate::leftover_companions::AppPathsCompanion>>,
}

pub fn validate_extension(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    if !(2..=32).contains(&bytes.len())
        || bytes[0] != b'.'
        || !bytes[1].is_ascii_alphanumeric()
        || !bytes[2..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(
            "Only a bounded simple file extension supports leftover suggestion cleanup.".into(),
        );
    }
    Ok(())
}
pub fn validate_hint(value: &StoredValue) -> Result<(), String> {
    if value.kind != 1 || !matches!(value.bytes.len(), 2 | 4) || value.bytes.iter().any(|b| *b != 0)
    {
        return Err(
            "Only an explicit empty REG_SZ SupportedTypes suggestion supports cleanup.".into(),
        );
    }
    Ok(())
}
impl SupportedTypeBackup {
    pub fn command(&self) -> Result<&StoredValue, String> {
        if !self.shell_values.is_empty()
            || !self.verb_values.is_empty()
            || self.command_values.len() != 1
            || !self.command_values[0].name.is_empty()
            || self.command_values[0].value.kind != 1
        {
            return Err(
                "Only a simple literal open command supports leftover file-type cleanup.".into(),
            );
        }
        Ok(&self.command_values[0].value)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.command()?.text()?;
        if let Some(companion) = &self.app_paths {
            companion.validate()?;
        }
        for values in [&self.shell_values, &self.verb_values, &self.command_values]
            .into_iter()
            .chain(self.icon_values.iter())
        {
            crate::associations::validate_values(values)?;
        }
        if let Some(values) = &self.icon_values {
            if values.len() > 1
                || values
                    .iter()
                    .any(|v| !v.name.is_empty() || !matches!(v.value.kind, 1 | 2))
            {
                return Err("Unsupported icon metadata blocks leftover suggestion cleanup.".into());
            }
        }
        Ok(())
    }
    pub fn evidence(
        &self,
        app: &LeftoverBackup,
        probe: &impl PathProbe,
    ) -> Result<LeftoverEvidence, String> {
        self.validate()?;
        applications::verify_missing_command(self.command()?, probe)?;
        let assessment =
            applications::assess_command(&self.command()?.text()?, &Environment::current(), probe);
        let expected = format!(r"{}\{}", app.directory, app.executable_name);
        if assessment.status != EntryStatus::Review
            || !assessment
                .target
                .as_ref()
                .is_some_and(|p| p.eq_ignore_ascii_case(&expected))
        {
            return Err("The registered open command must identify this exact missing application inside its installation directory.".into());
        }
        if let Some(companion) = &self.app_paths {
            companion.verify(&app.directory, &app.executable_name)?;
        }
        let value = StoredValue {
            kind: 1,
            bytes: app
                .directory
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        let mut evidence = correlate(
            &app.executable_name,
            &value,
            &app.uninstall_key,
            &app.anchor,
            probe,
        )?;
        evidence.application_path = format!(
            r"{}\{}",
            applications::APPLICATIONS_KEY,
            app.executable_name
        );
        if self.app_paths.is_some() {
            evidence.app_paths_companion = Some(format!(
                r"HKCU\{}\{}",
                crate::changes::APP_PATHS_KEY,
                app.executable_name
            ));
        }
        Ok(evidence)
    }
}
