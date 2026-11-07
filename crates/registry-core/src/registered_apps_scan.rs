use super::*;
use crate::{
    changes::RegistryStore,
    registered_apps::*,
    windows_changes::{open_registration_path, WindowsRegistryStore},
};

pub(super) fn scan_registered_applications(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    for (index, item) in root.enum_values().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
        let (name, value) = match item {
            Ok(item) => item,
            Err(e) => {
                scope.notes.push(read_error(&e));
                continue;
            }
        };
        let original = crate::changes::StoredValue {
            kind: value.vtype.clone() as u32,
            bytes: value.bytes.to_vec(),
        };
        let mut entry = make_entry(
            source,
            "",
            name.clone(),
            &name,
            Ok(value),
            environment,
            probe,
        );
        let evidence = (|| -> Result<(String, bool), String> {
            validate_registration_name(&name)?;
            let path = capabilities_path(&original)?;
            let hive = if source.hive == "HKCU" {
                HKEY_CURRENT_USER
            } else {
                HKEY_LOCAL_MACHINE
            };
            let mut exists = false;
            // RegisteredApplications itself is shared; its machine target may be redirected.
            for flag in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
                if open_registration_path(hive, &path, flag, None, false)?.is_some() {
                    exists = true;
                    break;
                }
            }
            Ok((path, exists))
        })();
        entry.assessment = match evidence {
            Ok((path, true)) => Assessment { status:EntryStatus::Found, code:"capabilities_found".into(), explanation:"The registered Capabilities key exists. No application command was run and no default selection was changed.".into(), target:Some(format!("{}\\{path}", source.hive)) },
            Ok((path, false)) => {
                entry.registered_app_repairable = source.hive == "HKCU" && WindowsRegistryStore::default().read_registered_app(&name, &original).is_ok_and(|current| current.as_ref() == Some(&original));
                Assessment { status:EntryStatus::Review, code:"capabilities_missing".into(), explanation:if entry.registered_app_repairable { "The application registration points to a missing Capabilities key and has no machine counterpart or matching machine target. Its exact named value can be reviewed for backed-up removal. Default selections and all other keys remain unchanged." } else { "The application registration points to a missing Capabilities key. Machine entries, duplicate registrations, protected paths, or uncertain evidence remain outside repair scope." }.into(), target:Some(format!("{}\\{path}", source.hive)) }
            },
            Err(reason) => Assessment { status:EntryStatus::Unknown, code:"capabilities_unverified".into(), explanation:reason, target:None },
        };
        entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registered_application_inventory_reads_capabilities_without_changing_values_or_probing_files(
    ) {
        struct NoFileProbe;
        impl PathProbe for NoFileProbe {
            fn probe(&self, _: &str, _: TargetKind) -> crate::ProbeResult {
                panic!("Registry capabilities are not filesystem paths");
            }
        }
        let base = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
        let (root, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"{base}\Registrations"))
            .unwrap();
        RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"{base}\Found\Capabilities"))
            .unwrap();
        root.set_value("Found", &format!(r"{base}\Found\Capabilities"))
            .unwrap();
        root.set_value("Missing", &format!(r"{base}\Missing\Capabilities"))
            .unwrap();
        root.set_value("Malformed", &7u32).unwrap();
        let before: Vec<_> = root
            .enum_values()
            .map(Result::unwrap)
            .map(|(name, v)| (name, v.vtype, v.bytes.to_vec()))
            .collect();
        let source = Source {
            category: Category::RegisteredApplications,
            hive: "HKCU",
            path: REGISTERED_APPS_KEY,
            view: "shared",
            flag: 0,
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
        let mut entries = Vec::new();
        scan_registered_applications(
            &source,
            &root,
            &AtomicBool::new(false),
            &Environment::default(),
            &mut entries,
            &mut scope,
            &NoFileProbe,
        );
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "Found")
                .unwrap()
                .assessment
                .status,
            EntryStatus::Found
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "Missing")
                .unwrap()
                .assessment
                .code,
            "capabilities_missing"
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "Malformed")
                .unwrap()
                .assessment
                .status,
            EntryStatus::Unknown
        );
        let after: Vec<_> = root
            .enum_values()
            .map(Result::unwrap)
            .map(|(name, v)| (name, v.vtype, v.bytes.to_vec()))
            .collect();
        assert_eq!(before, after);
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(&base)
            .unwrap();
        let sources = super::super::sources();
        assert_eq!(sources.len(), 33);
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::RegisteredApplications)
                .count(),
            2
        );
    }
}
