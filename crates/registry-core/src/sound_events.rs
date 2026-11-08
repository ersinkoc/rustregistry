use crate::{
    analyze_target,
    changes::{NamedValue, StoredValue},
    Assessment, EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};

pub const SOUND_SCHEMES: &str = r"AppEvents\Schemes";
pub const SOUND_APPS: &str = r"AppEvents\Schemes\Apps";
pub const CURRENT: &str = ".Current";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoundVariant {
    pub name: String,
    pub values: Vec<NamedValue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoundGuard {
    pub selected: Option<StoredValue>,
    pub application_values: Vec<NamedValue>,
    pub event_values: Vec<NamedValue>,
    pub variants: Vec<SoundVariant>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoundState {
    pub value: Option<StoredValue>,
    pub guard: SoundGuard,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoundBackup {
    pub application: String,
    pub event: String,
    pub target: String,
    pub guard: SoundGuard,
}

pub fn component(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name.is_ascii()
        || name.trim() != name
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && !"._- ".contains(c))
        || [".", ".."].contains(&name)
    {
        return Err("Sound identifiers must be bounded unambiguous ASCII key components.".into());
    }
    Ok(())
}
pub fn empty_assignment() -> StoredValue {
    StoredValue {
        kind: 1,
        bytes: vec![0, 0],
    }
}
pub fn sound_text(value: &StoredValue) -> Result<String, String> {
    if [1, 2].contains(&value.kind)
        && value.bytes.len() <= 32768
        && value.bytes.len().is_multiple_of(2)
        && value.bytes.iter().all(|b| *b == 0)
    {
        return Ok(String::new());
    }
    value.text()
}
impl SoundBackup {
    pub fn key_path(&self) -> String {
        format!(
            r"{SOUND_APPS}\{}\{}\{CURRENT}",
            self.application, self.event
        )
    }
    pub fn validate(&self) -> Result<(), String> {
        component(&self.application)?;
        component(&self.event)?;
        if self.event.eq_ignore_ascii_case(".Default")
            || self.event.eq_ignore_ascii_case("SystemDefault")
        {
            return Err("Default fallback events remain read-only.".into());
        }
        if self.target.len() > 255 || !self.target.to_ascii_lowercase().ends_with(".wav") {
            return Err("Only bounded literal local .wav assignments support repair.".into());
        }
        crate::shared_dlls::validate_shared_dll_path(&format!(
            "{}.dll",
            &self.target[..self.target.len() - 4]
        ))
        .map_err(|_| "Only literal local ASCII sound files outside Windows support repair.")?;
        let selection = self
            .guard
            .selected
            .as_ref()
            .ok_or("The selected sound scheme is unknown.")?;
        if selection.kind != 1 {
            return Err("The selected sound scheme has an unsupported type.".into());
        }
        let selected = selection.text()?;
        component(&selected)?;
        if selected.eq_ignore_ascii_case(".None") {
            return Err("The No Sounds scheme remains read-only.".into());
        }
        let mut size = selection.bytes.len();
        let validate_values = |values: &[NamedValue], size: &mut usize| -> Result<(), String> {
            if values.len() > 32 {
                return Err("Sound metadata exceeds the supported limits.".into());
            }
            let mut names = std::collections::HashSet::new();
            for v in values {
                *size += v.name.len() + v.value.bytes.len();
                if v.name.len() > 256
                    || v.name.contains('\0')
                    || !names.insert(v.name.to_lowercase())
                    || *size > 32768
                {
                    return Err("Sound metadata is oversized or ambiguous.".into());
                }
            }
            Ok(())
        };
        validate_values(&self.guard.application_values, &mut size)?;
        validate_values(&self.guard.event_values, &mut size)?;
        if self.guard.variants.is_empty() || self.guard.variants.len() > 32 {
            return Err("Sound scheme evidence is incomplete or oversized.".into());
        }
        let mut current = false;
        let mut variants = std::collections::HashSet::new();
        for variant in &self.guard.variants {
            component(&variant.name)?;
            if !variants.insert(variant.name.to_lowercase()) {
                return Err("Sound scheme names are ambiguous.".into());
            }
            if variant.name.eq_ignore_ascii_case(CURRENT) {
                current = true;
                if variant.values.iter().any(|v| v.name.is_empty()) {
                    return Err("Current sound metadata contains the mutable default.".into());
                }
            }
            validate_values(&variant.values, &mut size)?;
        }
        if !current {
            return Err("The existing current sound assignment key is required.".into());
        }
        Ok(())
    }
    pub fn verify_original(
        &self,
        value: &StoredValue,
        probe: &impl PathProbe,
    ) -> Result<(), String> {
        self.validate()?;
        if value.kind != 1 || value.text()? != self.target {
            return Err("Original sound assignment does not match the backup evidence.".into());
        }
        let a = analyze_target(
            &self.target,
            TargetKind::File,
            &Environment::current(),
            probe,
        );
        if a.status != EntryStatus::Review || a.code != "target_missing" {
            return Err(
                "The sound file is not confirmed missing. Repair or restore is blocked.".into(),
            );
        }
        Ok(())
    }
}
pub fn assess_sound(
    value: Option<&StoredValue>,
    environment: &Environment,
    probe: &impl PathProbe,
) -> Assessment {
    let unknown = |reason: &str| Assessment {
        status: EntryStatus::Unknown,
        code: "sound_unverified".into(),
        explanation: reason.into(),
        target: None,
    };
    let Some(value) = value else {
        return unknown("No explicit sound value exists. Absence is not an explicit empty assignment; application and system fallback are not inferred.");
    };
    if ![1, 2].contains(&value.kind) {
        return unknown("Only text sound assignments can be inspected.");
    }
    let Ok(raw) = sound_text(value) else {
        return unknown("The sound assignment is not readable text.");
    };
    if raw.is_empty() {
        return Assessment{status:EntryStatus::Found,code:"sound_unassigned".into(),explanation:"This is an explicit empty sound assignment, not a broken file reference. No playback or application-specific fallback was tested.".into(),target:None};
    }
    if value.kind != 1 {
        return unknown("Expandable sound assignments require the consuming application's environment and remain unverified.");
    }
    if !raw.to_ascii_lowercase().ends_with(".wav") {
        return unknown("Only a single .wav file assignment is inspected; aliases, resources and other formats remain unverified.");
    }
    let mut a = analyze_target(&raw, TargetKind::File, environment, probe);
    a.code = match a.status {
        EntryStatus::Found => "sound_file_found",
        EntryStatus::Review => "sound_file_missing",
        EntryStatus::Unknown => "sound_unverified",
    }
    .into();
    a.explanation.push_str(" Only file presence is checked. Sound contents, playback, device settings, cached sounds and application fallback are not tested.");
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(s: &str) -> StoredValue {
        StoredValue {
            kind: 1,
            bytes: s
                .encode_utf16()
                .chain([0, 0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    pub(super) fn guard() -> SoundGuard {
        SoundGuard {
            selected: Some(text(".Default")),
            application_values: vec![],
            event_values: vec![],
            variants: vec![
                SoundVariant {
                    name: CURRENT.into(),
                    values: vec![],
                },
                SoundVariant {
                    name: ".Default".into(),
                    values: vec![NamedValue {
                        name: "".into(),
                        value: text(r"C:\Windows\Media\notify.wav"),
                    }],
                },
            ],
        }
    }
    struct Probe(crate::ProbeResult);
    impl PathProbe for Probe {
        fn probe(&self, _: &str, _: TargetKind) -> crate::ProbeResult {
            self.0
        }
    }
    #[test]
    fn sound_policy_preserves_no_sound_default_and_ambiguous_settings() {
        let app = SoundBackup {
            application: "Custom App".into(),
            event: "Notify".into(),
            target: r"C:\Removed\sound.wav".into(),
            guard: guard(),
        };
        app.verify_original(&text(&app.target), &Probe(crate::ProbeResult::Missing))
            .unwrap();
        for path in [
            r"C:\Windows\Media\missing.wav",
            r"%TEMP%\sound.wav",
            r"\\server\share\sound.wav",
            "sound.wav",
            r"C:\Removed\sound.mp3",
            r"C:\Removed\..\sound.wav",
        ] {
            let mut bad = app.clone();
            bad.target = path.into();
            assert!(bad.validate().is_err());
        }
        for event in [".Default", "SystemDefault", r"Notify\Other", ".."] {
            let mut bad = app.clone();
            bad.event = event.into();
            assert!(bad.validate().is_err());
        }
        let mut bad = app.clone();
        bad.guard.selected = Some(text(".None"));
        assert!(bad.validate().is_err());
        let mut expanded = text(&app.target);
        expanded.kind = 2;
        assert!(app
            .verify_original(&expanded, &Probe(crate::ProbeResult::Missing))
            .is_err());
        assert!(app
            .verify_original(&text(&app.target), &Probe(crate::ProbeResult::Found))
            .is_err());
        assert!(app
            .verify_original(&text(&app.target), &Probe(crate::ProbeResult::Inaccessible))
            .is_err());
        assert_eq!(empty_assignment().bytes, vec![0, 0]);
    }
    #[test]
    fn empty_absent_relative_expanded_found_and_missing_sounds_remain_distinct() {
        let env = Environment::current();
        let probe = Probe(crate::ProbeResult::Missing);
        assert_eq!(
            assess_sound(Some(&text("")), &env, &probe).code,
            "sound_unassigned"
        );
        assert_eq!(
            assess_sound(None, &env, &probe).status,
            EntryStatus::Unknown
        );
        assert_eq!(
            assess_sound(Some(&text("sound.wav")), &env, &probe).status,
            EntryStatus::Unknown
        );
        let mut expanded = text(r"C:\Removed\sound.wav");
        expanded.kind = 2;
        assert_eq!(
            assess_sound(Some(&expanded), &env, &probe).status,
            EntryStatus::Unknown
        );
        assert_eq!(
            assess_sound(Some(&text(r"C:\Removed\sound.wav")), &env, &probe).code,
            "sound_file_missing"
        );
        assert_eq!(
            assess_sound(
                Some(&text(r"C:\Owned\sound.wav")),
                &env,
                &Probe(crate::ProbeResult::Found)
            )
            .code,
            "sound_file_found"
        );
    }
}
