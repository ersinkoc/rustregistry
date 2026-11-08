use crate::{
    analyze_target, changes::StoredValue, Assessment, EntryStatus, Environment, PathProbe,
    TargetKind,
};
use serde::{Deserialize, Serialize};

pub const FONTS_KEY: &str = r"Software\Microsoft\Windows NT\CurrentVersion\Fonts";
pub const WINHELP_KEY: &str = r"Software\Microsoft\Windows\Help";
pub const HTML_HELP_KEY: &str = r"Software\Microsoft\Windows\HTML Help";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileReferenceLocation {
    UserFont,
    HtmlHelp64,
    HtmlHelp32,
    WinHelp64,
    WinHelp32,
}
impl FileReferenceLocation {
    pub fn font(self) -> bool {
        self == Self::UserFont
    }
    pub fn hive(self) -> &'static str {
        if self.font() {
            "HKCU"
        } else {
            "HKLM"
        }
    }
    pub fn path(self) -> &'static str {
        match self {
            Self::UserFont => FONTS_KEY,
            Self::HtmlHelp64 | Self::HtmlHelp32 => HTML_HELP_KEY,
            Self::WinHelp64 | Self::WinHelp32 => WINHELP_KEY,
        }
    }
    pub fn view(self) -> &'static str {
        match self {
            Self::UserFont => "shared",
            Self::HtmlHelp64 | Self::WinHelp64 => "64",
            _ => "32",
        }
    }
    pub fn scope(self) -> &'static str {
        if self.font() {
            "font_reference"
        } else {
            "help_reference"
        }
    }
    pub fn extension(self) -> &'static str {
        match self {
            Self::UserFont => "",
            Self::HtmlHelp64 | Self::HtmlHelp32 => ".chm",
            _ => ".hlp",
        }
    }
    pub fn from_source(hive: &str, path: &str, view: &str) -> Option<Self> {
        [
            Self::UserFont,
            Self::HtmlHelp64,
            Self::HtmlHelp32,
            Self::WinHelp64,
            Self::WinHelp32,
        ]
        .into_iter()
        .find(|l| l.hive() == hive && l.path() == path && l.view() == view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value(text: &str) -> StoredValue {
        StoredValue {
            kind: 1,
            bytes: text
                .encode_utf16()
                .chain([0, 0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    struct Probe(ProbeResult);
    use crate::ProbeResult;
    impl PathProbe for Probe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            self.0
        }
    }
    #[test]
    fn repair_policy_requires_literal_supported_files_names_types_and_matching_backup_targets() {
        let font = FileReferenceBackup::from_original(
            FileReferenceLocation::UserFont,
            "Example (TrueType)",
            &value(r"C:\Removed\font.ttf"),
        )
        .unwrap();
        font.verify_original(&value(r"C:\Removed\font.ttf"), &Probe(ProbeResult::Missing))
            .unwrap();
        for path in [
            "font.ttf",
            r"%LOCALAPPDATA%\font.ttf",
            r"C:\Windows\Fonts\font.ttf",
            r"\\server\share\font.ttf",
            r"C:\Removed\font.ttc",
            r"C:\Removed\font.fon",
            r"C:\Removed\font.pfm|font.pfb",
            r"C:\Removed\..\font.ttf",
        ] {
            assert!(FileReferenceBackup::from_original(
                FileReferenceLocation::UserFont,
                "Example (TrueType)",
                &value(path)
            )
            .is_err());
        }
        let mut expanded = value(r"C:\Removed\font.otf");
        expanded.kind = 2;
        assert!(FileReferenceBackup::from_original(
            FileReferenceLocation::UserFont,
            "Example",
            &expanded
        )
        .is_err());
        for name in ["", r"a\b", " Example", "Example & Other (TrueType)"] {
            assert!(FileReferenceBackup::from_original(
                FileReferenceLocation::UserFont,
                name,
                &value(r"C:\Removed\font.ttf")
            )
            .is_err());
        }
        for location in [
            FileReferenceLocation::HtmlHelp32,
            FileReferenceLocation::HtmlHelp64,
            FileReferenceLocation::WinHelp32,
            FileReferenceLocation::WinHelp64,
        ] {
            let name = format!("manual{}", location.extension());
            let original = value(r"C:\Removed\Help\");
            let app = FileReferenceBackup::from_original(location, &name, &original).unwrap();
            assert_eq!(app.target, format!(r"C:\Removed\Help\{name}"));
            app.verify_original(&original, &Probe(ProbeResult::Missing))
                .unwrap();
            let mut bad = app.clone();
            bad.target = bad.target.replace("manual", "other");
            assert!(bad.validate().is_err());
            assert!(FileReferenceBackup::from_original(
                location,
                &format!(r"folder\{name}"),
                &original
            )
            .is_err());
        }
        assert_eq!(
            font_identities("Example & Other (TrueType)"),
            vec!["example", "other"]
        );
    }
    #[test]
    fn verification_rejects_found_inaccessible_redirected_and_wrong_kind_targets() {
        let original = value(r"C:\Removed\font.otf");
        let app = FileReferenceBackup::from_original(
            FileReferenceLocation::UserFont,
            "Example",
            &original,
        )
        .unwrap();
        for result in [
            ProbeResult::Found,
            ProbeResult::Inaccessible,
            ProbeResult::Redirected,
            ProbeResult::WrongKind,
        ] {
            assert!(app.verify_original(&original, &Probe(result)).is_err());
        }
    }
    #[test]
    fn relative_font_candidates_and_expandable_help_directories_never_become_guessed_repairs() {
        let env = Environment::current();
        let found = assess_registration(
            true,
            "HKLM",
            "shared",
            "Example",
            &value("example.ttf"),
            &env,
            &Probe(ProbeResult::Found),
        );
        assert_eq!(found.code, "font_file_found");
        assert!(found.target.unwrap().ends_with(r"\Fonts\example.ttf"));
        assert_eq!(
            assess_registration(
                true,
                "HKLM",
                "shared",
                "Example",
                &value("example.ttf"),
                &env,
                &Probe(ProbeResult::Missing)
            )
            .status,
            EntryStatus::Unknown
        );
        assert_eq!(
            assess_registration(
                true,
                "HKCU",
                "shared",
                "Example",
                &value("example.ttf"),
                &env,
                &Probe(ProbeResult::Missing)
            )
            .status,
            EntryStatus::Unknown
        );
        let mut expanded = value(r"%SystemRoot%\Help");
        expanded.kind = 2;
        assert_eq!(
            assess_registration(
                false,
                "HKLM",
                "32",
                "manual.chm",
                &expanded,
                &env,
                &Probe(ProbeResult::Missing)
            )
            .status,
            EntryStatus::Unknown
        );
        assert!(FileReferenceLocation::from_source("HKLM", FONTS_KEY, "shared").is_none());
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileReferenceBackup {
    pub location: FileReferenceLocation,
    pub name: String,
    pub target: String,
}

pub fn validate_font_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 255
        || !name.is_ascii()
        || name.trim() != name
        || name
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|%&".contains(c))
    {
        return Err("Only bounded, unambiguous ASCII font display names support repair.".into());
    }
    Ok(())
}
pub fn font_identities(name: &str) -> Vec<String> {
    let mut base = name.trim();
    for suffix in [" (TrueType)", " (OpenType)"] {
        if base.len() >= suffix.len()
            && base
                .get(base.len() - suffix.len()..)
                .is_some_and(|s| s.eq_ignore_ascii_case(suffix))
        {
            base = &base[..base.len() - suffix.len()];
            break;
        }
    }
    base.split(" & ")
        .map(|part| part.trim().to_ascii_lowercase())
        .collect()
}
pub fn validate_help_name(name: &str, extension: &str) -> Result<(), String> {
    if name.len() > 255
        || name.len() <= extension.len()
        || !name.is_ascii()
        || name.trim() != name
        || !name.to_ascii_lowercase().ends_with(extension)
        || name
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|%".contains(c))
        || name.ends_with(['.', ' '])
    {
        return Err("Only a single bounded ASCII help filename with the expected .chm/.hlp extension supports repair.".into());
    }
    Ok(())
}
fn literal_target(path: &str, extensions: &[&str]) -> Result<(), String> {
    if !extensions
        .iter()
        .any(|ext| path.to_ascii_lowercase().ends_with(ext))
    {
        return Err("Only a single supported font or help file is eligible; collections and multi-file resources remain read-only.".into());
    }
    crate::shared_dlls::validate_shared_dll_path(&format!("{}.dll",&path[..path.len()-4])).map_err(|_|"Repair requires a bounded literal local ASCII file path outside Windows, without environment variables, aliases or ambiguous segments.".into())
}
impl FileReferenceBackup {
    pub fn validate(&self) -> Result<(), String> {
        if self.location.font() {
            validate_font_name(&self.name)?;
            literal_target(&self.target, &[".ttf", ".otf"])
        } else {
            validate_help_name(&self.name, self.location.extension())?;
            literal_target(&self.target, &[self.location.extension()])?;
            let basename = self
                .target
                .rsplit('\\')
                .next()
                .ok_or("Help filename is absent.")?;
            if !basename.eq_ignore_ascii_case(&self.name) {
                return Err("The help target filename does not match its registered name.".into());
            }
            Ok(())
        }
    }
    pub fn from_original(
        location: FileReferenceLocation,
        name: &str,
        value: &StoredValue,
    ) -> Result<Self, String> {
        if value.kind != 1 {
            return Err("Repair supports literal REG_SZ mappings only; expandable, binary and unsupported values remain read-only.".into());
        }
        let original = value.text()?;
        let target = if location.font() {
            original
        } else {
            format!("{}\\{}", original.trim_end_matches('\\'), name)
        };
        let app = Self {
            location,
            name: name.into(),
            target,
        };
        app.validate()?;
        Ok(app)
    }
    pub fn verify_original(
        &self,
        value: &StoredValue,
        probe: &impl PathProbe,
    ) -> Result<(), String> {
        self.validate()?;
        if Self::from_original(self.location, &self.name, value)? != *self {
            return Err(
                "Font/help backup target evidence does not match its original value.".into(),
            );
        }
        let assessment = analyze_target(
            &self.target,
            TargetKind::File,
            &Environment::current(),
            probe,
        );
        if assessment.status != EntryStatus::Review || assessment.code != "target_missing" {
            return Err(
                "The font/help file is not confirmed missing. Repair or restore is blocked.".into(),
            );
        }
        Ok(())
    }
}

pub fn assess_registration(
    font: bool,
    hive: &str,
    view: &str,
    name: &str,
    value: &StoredValue,
    environment: &Environment,
    probe: &impl PathProbe,
) -> Assessment {
    let unknown = |reason: String, target: Option<String>| Assessment {
        status: EntryStatus::Unknown,
        code: if font {
            "font_unverified"
        } else {
            "help_unverified"
        }
        .into(),
        explanation: reason,
        target,
    };
    let raw = match value.text() {
        Ok(s) => s,
        Err(reason) => return unknown(reason, None),
    };
    if ![1, 2].contains(&value.kind) {
        return unknown("Only text registrations can be inspected.".into(), None);
    }
    if font {
        if value.kind != 1 {
            return unknown("Expandable font registrations require loader-specific environment resolution and remain unverified.".into(),None);
        }
        if raw.contains('|') {
            return unknown(
                "Multi-file font resources are not resolved or loaded.".into(),
                None,
            );
        }
        let absolute = raw.as_bytes().get(1) == Some(&b':');
        if !absolute {
            if raw.contains(['\\', '/', ':']) || raw.contains('%') || raw.ends_with(['.', ' ']) {
                return unknown("Relative, expanded or ambiguous font paths require installer-specific resolution and remain unverified.".into(),None);
            }
            if hive == "HKLM" {
                if let Ok(windows) = crate::shared_dlls::windows_directory() {
                    let candidate = format!("{windows}\\Fonts\\{raw}");
                    let mut assessment =
                        analyze_target(&candidate, TargetKind::File, environment, probe);
                    if assessment.status != EntryStatus::Found {
                        return unknown("The conventional Windows Fonts candidate was not confirmed present. Relative-path font loading and fallback are not inferred; no repair is offered.".into(),Some(candidate));
                    }
                    assessment.code = "font_file_found".into();
                    assessment.explanation="The registered filename exists in the Windows Fonts directory. Font contents, loading, family membership and usability were not tested.".into();
                    return assessment;
                }
            }
            return unknown("A relative per-user font name has no verified absolute target; it remains read-only.".into(),None);
        }
        let mut assessment = analyze_target(&raw, TargetKind::File, environment, probe);
        assessment.code = match assessment.status {
            EntryStatus::Found => "font_file_found",
            EntryStatus::Review => "font_file_missing",
            EntryStatus::Unknown => "font_unverified",
        }
        .into();
        assessment.explanation.push_str(" Only file presence is checked. No font is parsed, installed, loaded, unloaded or broadcast to applications.");
        assessment
    } else {
        let ext = if name.to_ascii_lowercase().ends_with(".chm") {
            ".chm"
        } else {
            ".hlp"
        };
        if let Err(reason) = validate_help_name(name, ext) {
            return unknown(reason, None);
        }
        let candidate = format!("{}\\{}", raw.trim_end_matches('\\'), name);
        if value.kind != 1 {
            return unknown("Expandable help directories require the consuming process's environment and remain unverified; literal registrations are inspected separately.".into(),Some(candidate));
        }
        if view == "32"
            && crate::shared_dlls::windows_directory().is_ok_and(|w| {
                candidate
                    .to_ascii_lowercase()
                    .starts_with(&format!("{}\\", w.to_ascii_lowercase()))
            })
        {
            return unknown("A 32-bit Windows help path requires a matching filesystem context and remains read-only.".into(),Some(candidate));
        }
        let mut assessment = analyze_target(&candidate, TargetKind::File, environment, probe);
        assessment.code = match assessment.status {
            EntryStatus::Found => "help_file_found",
            EntryStatus::Review => "help_file_missing",
            EntryStatus::Unknown => "help_unverified",
        }
        .into();
        assessment.explanation.push_str(" This checks only the named file in its registered directory. Help search fallbacks and document contents are not tested; no help viewer or document is opened.");
        assessment
    }
}
