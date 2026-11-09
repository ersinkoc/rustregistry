use super::*;
use crate::{
    changes::{NamedValue, RegistryStore, StoredValue},
    shell_menus::*,
    windows_changes::{open_icon_child, WindowsRegistryStore},
};
pub(super) fn scan_menus(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let location = MenuLocation::from_path(source.path).expect("fixed menu source");
    let store = WindowsRegistryStore::default();
    let start = entries.len();
    for (index, item) in root.enum_keys().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= MAX_ENTRIES_PER_SCOPE || entries.len() - start >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
        let inspected = (|| -> Result<Option<RegistryEntry>, String> {
            let name = item.map_err(|e| read_error(&e))?;
            let Some(verb) = open_icon_child(root, &name)? else {
                return Ok(None);
            };
            let Some(command) = open_icon_child(&verb, "command")? else {
                return Ok(None);
            };
            let raw = command.get_raw_value("");
            let mut entry = make_entry(
                source,
                &format!(r"{name}\command"),
                name.clone(),
                "",
                raw.map_err(|e| read_error(&e)),
                environment,
                probe,
            );
            let command_names = command
                .enum_values()
                .map(|v| v.map(|(name, _)| name))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "Command metadata is unreadable.")?;
            let verb_names = verb
                .enum_values()
                .map(|v| v.map(|(name, _)| name))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "Menu display metadata is unreadable.")?;
            let children = verb
                .enum_keys()
                .take(3)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "Menu structure is unreadable.")?;
            entry.menu_hidden = verb_names.iter().any(|v| {
                v.eq_ignore_ascii_case(PROGRAMMATIC_ONLY) || v.eq_ignore_ascii_case("LegacyDisable")
            });
            let alternate = command_names.iter().any(|v| !v.is_empty())
                || command.enum_keys().next().is_some()
                || children.len() != 1
                || !children[0].eq_ignore_ascii_case("command")
                || verb_names.iter().any(|n| {
                    ![
                        "",
                        "muiverb",
                        "icon",
                        "position",
                        "extended",
                        "programmaticaccessonly",
                    ]
                    .contains(&n.to_ascii_lowercase().as_str())
                });
            entry.assessment = if entry.menu_hidden {
                Assessment{status:EntryStatus::Unknown,code:"shell_menu_hidden".into(),explanation:"A menu visibility flag is already present. The command is preserved and no repeated hiding is offered.".into(),target:None}
            } else if alternate {
                Assessment{status:EntryStatus::Unknown,code:"shell_menu_activation_unverified".into(),explanation:"Delegated, cascading, conditional or unknown activation metadata prevents a reliable command-only diagnosis. No executable was probed or run.".into(),target:None}
            } else {
                crate::applications::assess_command(&entry.raw_value, environment, probe)
            };
            if source.hive == "HKCU"
                && !entry.menu_hidden
                && entry.assessment.code == "target_missing"
            {
                let selector = MenuBackup {
                    location,
                    verb_name: name.clone(),
                    snapshot: MenuSnapshot {
                        user_root_values: vec![],
                        machine_root_values: None,
                        verb_values: vec![],
                        command_values: vec![NamedValue {
                            name: String::new(),
                            value: StoredValue {
                                kind: 1,
                                bytes: vec![120, 0, 0, 0],
                            },
                        }],
                    },
                };
                match store.read_menu(&selector) {
                    Ok(snapshot) => {
                        match verify_missing_menu_command(snapshot.command()?, &LocalPathProbe) {
                            Ok(()) => {
                                entry.menu_repairable = true;
                                entry.menu_snapshot = Some(snapshot);
                            }
                            Err(reason) => entry
                                .assessment
                                .explanation
                                .push_str(&format!(" Recovery unavailable: {reason}")),
                        }
                    }
                    Err(reason) => entry
                        .assessment
                        .explanation
                        .push_str(&format!(" Recovery unavailable: {reason}")),
                }
            } else if source.hive == "HKLM" {
                entry
                    .assessment
                    .explanation
                    .push_str(" Machine menu registrations remain read-only.");
            }
            entry.assessment.explanation.push_str(" Only static menu commands are inventoried. No command, icon or COM handler is executed or loaded.");
            Ok(Some(entry))
        })();
        match inspected {
            Ok(Some(e)) => entries.push(e),
            Ok(None) => {}
            Err(reason) => scope.notes.push(reason),
        }
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
            assert!(!path.contains("delegate"));
            if path.contains("found") {
                crate::ProbeResult::Found
            } else {
                crate::ProbeResult::Missing
            }
        }
    }
    #[test]
    fn menu_inventory_is_read_only_skips_activation_probes_and_preserves_visibility() {
        let owned = Owned(format!(
            r"Software\RustRegistryTests\{}",
            uuid::Uuid::new_v4()
        ));
        let root = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&owned.0)
            .unwrap()
            .0;
        for (name, path) in [
            ("Example.Missing", r"C:\Missing\app.exe %1"),
            ("Example.Found", r"C:\found\app.exe %1"),
            ("Example.Delegate", r"C:\delegate\app.exe %1"),
            ("Example.Hidden", r"C:\Missing\app.exe %1"),
        ] {
            let verb = root.create_subkey(name).unwrap().0;
            verb.create_subkey("command")
                .unwrap()
                .0
                .set_value("", &path)
                .unwrap();
            if name.ends_with("Delegate") {
                verb.set_value("ExplorerCommandHandler", &"unknown")
                    .unwrap();
            }
            if name.ends_with("Hidden") {
                verb.set_value(PROGRAMMATIC_ONLY, &"").unwrap();
            }
        }
        let source = Source {
            category: Category::ShellMenus,
            hive: "HKCU",
            path: FILE_MENUS_KEY,
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
        scan_menus(
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
            ("Example.Missing", "target_missing"),
            ("Example.Found", "target_found"),
            ("Example.Delegate", "shell_menu_activation_unverified"),
            ("Example.Hidden", "shell_menu_hidden"),
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
            root.open_subkey(r"Example.Hidden\command")
                .unwrap()
                .get_value::<String, _>("")
                .unwrap(),
            r"C:\Missing\app.exe %1"
        );
        let mut cancelled = vec![];
        scan_menus(
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
        assert_eq!(super::super::sources().len(), 67);
    }
}
