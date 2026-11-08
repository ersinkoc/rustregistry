use super::*;
use crate::{
    changes::{RegistryStore, StoredValue},
    file_references::*,
    windows_changes::WindowsRegistryStore,
};

pub(super) fn scan_file_references(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let font = source.category == Category::Fonts;
    for (index, item) in root.enum_values().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            scope
                .notes
                .push("Font/help inventory reached its 10,000-value limit.".into());
            break;
        }
        let (name, value) = match item {
            Ok(v) => v,
            Err(e) => {
                scope.notes.push(read_error(&e));
                continue;
            }
        };
        let original = StoredValue {
            kind: value.vtype.clone() as u32,
            bytes: value.bytes.to_vec(),
        };
        let mut entry = make_entry(
            source,
            "",
            name.clone(),
            &name,
            Err("Font/help evidence has not been assessed.".into()),
            environment,
            probe,
        );
        entry.value_type = format!("{:?}", value.vtype);
        entry.raw_value = original.text().unwrap_or_default();
        entry.assessment = if original.bytes.len() > MAX_VALUE_BYTES {
            Assessment {
                status: EntryStatus::Unknown,
                code: "file_reference_oversized".into(),
                explanation:
                    "This font/help value exceeds the inventory size limit and remains read-only."
                        .into(),
                target: None,
            }
        } else {
            assess_registration(
                font,
                source.hive,
                source.view,
                &name,
                &original,
                environment,
                probe,
            )
        };
        if !font {
            let ext = if source.path == HTML_HELP_KEY {
                ".chm"
            } else {
                ".hlp"
            };
            if let Err(reason) = validate_help_name(&name, ext) {
                entry.assessment = Assessment {
                    status: EntryStatus::Unknown,
                    code: "help_unverified".into(),
                    explanation: reason,
                    target: None,
                };
            }
        }
        if entry.assessment.status == EntryStatus::Review {
            let eligibility = (|| -> Result<FileReferenceBackup, String> {
                let location=FileReferenceLocation::from_source(source.hive,source.path,source.view).ok_or("System-wide font registrations remain read-only; only supported current-user font mappings have a repair action.")?;
                let app = FileReferenceBackup::from_original(location, &name, &original)?;
                if WindowsRegistryStore::default()
                    .read_file_reference(&app)?
                    .as_ref()
                    != Some(&original)
                {
                    return Err("The font/help mapping changed during the scan.".into());
                }
                Ok(app)
            })();
            match eligibility {
                Ok(app) => {
                    entry.snapshot = Some(original);
                    entry.file_reference = Some(app);
                    entry.file_reference_repairable = true;
                }
                Err(reason) => entry
                    .assessment
                    .explanation
                    .push_str(&format!(" Repair unavailable: {reason}")),
            }
        }
        entries.push(entry);
    }
    scope.notes.push(if font{"Only persisted direct font registrations are inventoried. Packaged/per-process fonts, font contents, active font tables, linking and substitution are not resolved or changed. Conventional machine basename candidates do not establish full font-search behavior."}else{"Only the named .chm/.hlp file in its registered directory is checked. Help search paths, security policies, fallback locations and document contents are not changed or executed. Repairs require existing write rights; the app does not request elevation."}.into());
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Probe;
    impl PathProbe for Probe {
        fn probe(&self, path: &str, _: TargetKind) -> ProbeResult {
            if path.ends_with("found.ttf") || path.ends_with("found.chm") {
                ProbeResult::Found
            } else {
                ProbeResult::Missing
            }
        }
    }
    #[test]
    fn inventory_is_read_only_preserves_package_children_and_separates_supported_and_ambiguous_paths(
    ) {
        let base = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
        let root = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&base)
            .unwrap()
            .0;
        root.create_subkey("Package")
            .unwrap()
            .0
            .set_value("Keep", &17u32)
            .unwrap();
        for (name, value) in [
            ("Found (TrueType)", r"C:\Owned\found.ttf"),
            ("Missing (TrueType)", r"C:\Owned\missing.ttf"),
            ("Relative", "font.ttf"),
            ("Multi", r"C:\Owned\one.pfm|two.pfb"),
        ] {
            root.set_value(name, &value).unwrap();
        }
        root.set_value("Binary", &17u32).unwrap();
        let before: Vec<_> = root
            .enum_values()
            .map(|v| {
                let (n, v) = v.unwrap();
                (n, v.vtype, v.bytes.into_owned())
            })
            .collect();
        let source = Source {
            category: Category::Fonts,
            hive: "HKCU",
            path: FONTS_KEY,
            view: "shared",
            flag: KEY_WOW64_64KEY,
        };
        let mut scope = ScopeResult {
            id: "owned".into(),
            category: source.category,
            hive: source.hive.into(),
            key_path: source.path.into(),
            view: source.view.into(),
            status: "complete".into(),
            entries: 0,
            notes: vec![],
        };
        let mut entries = vec![];
        scan_file_references(
            &source,
            &root,
            &AtomicBool::new(false),
            &Environment::current(),
            &mut entries,
            &mut scope,
            &Probe,
        );
        assert_eq!(entries.len(), 5);
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "Found (TrueType)")
                .unwrap()
                .assessment
                .status,
            EntryStatus::Found
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "Missing (TrueType)")
                .unwrap()
                .assessment
                .status,
            EntryStatus::Review
        );
        for name in ["Relative", "Multi", "Binary"] {
            assert_eq!(
                entries
                    .iter()
                    .find(|e| e.name == name)
                    .unwrap()
                    .assessment
                    .status,
                EntryStatus::Unknown
            );
        }
        let after: Vec<_> = root
            .enum_values()
            .map(|v| {
                let (n, v) = v.unwrap();
                (n, v.vtype, v.bytes.into_owned())
            })
            .collect();
        assert_eq!(before, after);
        assert_eq!(
            root.open_subkey("Package")
                .unwrap()
                .get_value::<u32, _>("Keep")
                .unwrap(),
            17
        );
        drop(root);
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(base)
            .unwrap();
        let sources = super::super::sources();
        assert_eq!(sources.len(), 64);
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::Fonts)
                .count(),
            2
        );
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::HelpFiles)
                .count(),
            4
        );
    }
}
