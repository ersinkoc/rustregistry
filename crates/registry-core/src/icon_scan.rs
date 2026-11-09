use super::*;
use crate::{
    application_icons::*,
    changes::RegistryStore,
    windows_changes::{open_icon_child, WindowsRegistryStore},
};

pub(super) fn scan_icons(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let start = entries.len();
    let store = WindowsRegistryStore::default();
    for (index, item) in root.enum_keys().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= 30000 || entries.len() - start >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
        let name = match item {
            Ok(name) => name,
            Err(error) => {
                scope.notes.push(read_error(&error));
                continue;
            }
        };
        if validate_application_name(&name).is_err() {
            continue;
        }
        let interface = match open_icon_child(root, &name) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(error) => {
                scope.notes.push(error);
                continue;
            }
        };
        let clsid = match open_icon_child(&interface, "DefaultIcon") {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(error) => {
                scope.notes.push(error);
                continue;
            }
        };
        let raw = clsid.get_raw_value("");
        let original = raw.as_ref().ok().map(|v| crate::changes::StoredValue {
            kind: v.vtype.clone() as u32,
            bytes: v.bytes.to_vec(),
        });
        let path = format!(r"{name}\DefaultIcon");
        let mut entry = make_entry(
            source,
            &path,
            read_optional(&interface, "", &mut scope.notes).unwrap_or_else(|| name.clone()),
            "",
            raw.map_err(|e| read_error(&e)),
            environment,
            probe,
        );
        entry.assessment=match &original {
            None=>Assessment{status:EntryStatus::Unknown,code:"icon_mapping_absent".into(),explanation:"No readable default icon reference is present. This alone does not prove an application is broken.".into(),target:None},
            Some(value)=>match value.text(){Ok(raw)=>assess_icon(&raw,environment,probe),Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"icon_value_unverified".into(),explanation:reason,target:None}}
        };
        if source.hive == "HKCU" && entry.assessment.code == "target_missing" {
            // A valid placeholder is used only to select the fixed key; all live
            // metadata is captured before the entry can become a repair candidate.
            let placeholder = crate::applications::ApplicationSnapshot {
                application_values: vec![],
                shell_values: vec![],
                verb_values: vec![],
                command_values: vec![crate::changes::NamedValue {
                    name: String::new(),
                    value: crate::changes::StoredValue {
                        kind: 1,
                        bytes: vec![120, 0, 0, 0],
                    },
                }],
            };
            let app = IconBackup {
                executable: name.clone(),
                guard: placeholder,
            };
            if let Ok(state) = store.read_icon(&app) {
                if state.value == original
                    && original
                        .as_ref()
                        .is_some_and(|v| verify_missing_icon(v, &LocalPathProbe).is_ok())
                {
                    entry.icon_state = Some(state);
                    entry.icon_repairable = true;
                }
            }
        }
        entry.assessment.explanation.push_str(" Only the icon file reference is assessed. Open commands and default application choices are preserved; no icon is loaded or decoded.");
        entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Owned(String);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
        }
    }
    struct Probe;
    impl PathProbe for Probe {
        fn probe(&self, path: &str, _: TargetKind) -> crate::ProbeResult {
            if path.ends_with("found.ico") {
                crate::ProbeResult::Found
            } else {
                crate::ProbeResult::Missing
            }
        }
    }
    #[test]
    fn icon_inventory_is_read_only_and_does_not_guess_resource_or_absent_references() {
        let path = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
        let _owned = Owned(path.clone());
        let root = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&path)
            .unwrap()
            .0;
        for (name, value) in [
            ("Missing.exe", Some(r"C:\Missing\one.ico")),
            ("Found.exe", Some(r"C:\Missing\found.ico")),
            ("Resource.exe", Some(r"C:\Missing\container.dll,0")),
            ("Empty.exe", None),
        ] {
            let key = root
                .create_subkey(format!(r"{name}\DefaultIcon"))
                .unwrap()
                .0;
            if let Some(value) = value {
                key.set_value("", &value).unwrap();
            }
        }
        let source = Source {
            category: Category::ApplicationIcons,
            hive: "HKCU",
            path: APPLICATIONS_KEY,
            flag: 0,
            view: "shared",
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
        scan_icons(
            &source,
            &root,
            &AtomicBool::new(false),
            &Environment::default(),
            &mut entries,
            &mut scope,
            &Probe,
        );
        assert_eq!(entries.len(), 4);
        for (name, code) in [
            ("Missing.exe", "target_missing"),
            ("Found.exe", "target_found"),
            ("Resource.exe", "icon_expression_unverified"),
            ("Empty.exe", "icon_mapping_absent"),
        ] {
            assert_eq!(
                entries
                    .iter()
                    .find(|e| e.name == name)
                    .unwrap()
                    .assessment
                    .code,
                code
            );
        }
        assert_eq!(
            root.open_subkey(r"Missing.exe\DefaultIcon")
                .unwrap()
                .get_value::<String, _>("")
                .unwrap(),
            r"C:\Missing\one.ico"
        );
        let mut cancelled = vec![];
        scan_icons(
            &source,
            &root,
            &AtomicBool::new(true),
            &Environment::default(),
            &mut cancelled,
            &mut scope,
            &Probe,
        );
        assert!(cancelled.is_empty());
        assert_eq!(scope.status, "cancelled");
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(path)
            .unwrap();
        assert_eq!(super::super::sources().len(), 68);
    }
}
