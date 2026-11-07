use super::*;

pub(super) const APPLICATIONS_KEY: &str = r"Software\Classes\Applications";

pub(super) fn assess_command(
    raw: &str,
    environment: &Environment,
    probe: &impl PathProbe,
) -> Assessment {
    let raw = raw.trim();
    // Shell argument placeholders such as "%1" and %* are not environment
    // variables. Only interpret the executable expression; never expand arguments.
    let executable = if raw.contains('\0') {
        raw
    } else if let Some(rest) = raw.strip_prefix('"') {
        rest.find('"')
            .filter(|end| {
                rest[end + 1..].is_empty() || rest[end + 1..].starts_with(char::is_whitespace)
            })
            .map_or(raw, |end| &raw[..end + 2])
    } else {
        raw.split_whitespace().next().unwrap_or(raw)
    };
    analyze_target(executable, TargetKind::Command, environment, probe)
}

struct CommandProbe<'a, P> {
    inner: &'a P,
    enabled: bool,
}
impl<P: PathProbe> PathProbe for CommandProbe<'_, P> {
    fn probe(&self, path: &str, kind: TargetKind) -> ProbeResult {
        if self.enabled {
            self.inner.probe(path, kind)
        } else {
            ProbeResult::Inaccessible
        }
    }
}

// Open each component without following registry links. No command is ever executed.
fn open_child(parent: &RegKey, name: &str) -> Result<Option<RegKey>, String> {
    let key = match parent.open_subkey_with_options_flags(name, REG_OPTION_OPEN_LINK, KEY_READ) {
        Ok(key) => key,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(read_error(&error)),
    };
    match key.get_raw_value("SymbolicLinkValue") {
        Ok(value) if value.vtype == REG_LINK => Err("Registry link not followed.".into()),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(read_error(&error)),
        _ => Ok(Some(key)),
    }
}

pub(super) fn scan_applications(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    for (index, item) in root.enum_keys().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= MAX_ENTRIES_PER_SCOPE {
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
        let inspected = (|| -> Result<Option<RegistryEntry>, String> {
            let Some(app) = open_child(root, &name)? else {
                return Ok(None);
            };
            let Some(shell) = open_child(&app, "shell")? else {
                return Ok(None);
            };
            let Some(verb) = open_child(&shell, "open")? else {
                return Ok(None);
            };
            let Some(command) = open_child(&verb, "command")? else {
                return Ok(None);
            };
            let mut alternate = false;
            // DDE, DropTarget, delegated execution, or an overridden command cannot
            // be diagnosed from the default command alone.
            for child in verb.enum_keys() {
                let child = child.map_err(|error| read_error(&error))?;
                alternate |= !child.eq_ignore_ascii_case("command");
                if alternate {
                    break;
                }
            }
            alternate |= command.enum_keys().next().is_some();
            for item in command.enum_values().take(2) {
                let (name, _) = item.map_err(|error| read_error(&error))?;
                alternate |= !name.is_empty();
            }
            for field in [
                "DelegateExecute",
                "ExplorerCommandHandler",
                "CommandStateHandler",
            ] {
                match verb.get_raw_value(field) {
                    Ok(_) => alternate = true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(read_error(&error)),
                }
            }
            let mut entry = make_entry(
                source,
                &format!(r"{name}\shell\open\command"),
                name.clone(),
                "",
                command
                    .get_raw_value("")
                    .map_err(|error| read_error(&error)),
                environment,
                &CommandProbe {
                    inner: probe,
                    enabled: !alternate,
                },
            );
            if alternate {
                entry.assessment = Assessment {
                    status: EntryStatus::Unknown,
                    code: "application_alternate_activation".into(),
                    explanation: "This open command has additional or unreadable activation settings. The default command alone does not establish its effective target. Application commands remain read-only.".into(),
                    target: None,
                };
            } else {
                entry.assessment.explanation.push_str(" This inventories the registered open command only; application commands remain read-only and default application selections are not tested.");
            }
            Ok(Some(entry))
        })();
        match inspected {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => {}
            Err(reason) => scope.notes.push(format!("{name}: {reason}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Fixture(String);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
        }
    }
    struct Probe(Cell<usize>);
    impl PathProbe for Probe {
        fn probe(&self, path: &str, _: TargetKind) -> ProbeResult {
            self.0.set(self.0.get() + 1);
            if path.ends_with("found.exe") {
                ProbeResult::Found
            } else {
                ProbeResult::Missing
            }
        }
    }
    #[test]
    fn application_commands_inventory_is_read_only_and_alternate_activation_is_not_probed() {
        let fixture = Fixture(format!(
            r"Software\RustRegistryTests\{}",
            uuid::Uuid::new_v4()
        ));
        let (root, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&fixture.0)
            .unwrap();
        let original = r#""C:\Missing App\missing.exe" "%1""#;
        for name in [
            "missing.exe",
            "found.exe",
            "delegate.exe",
            "dde.exe",
            "ambiguous.exe",
        ] {
            let (key, _) = root
                .create_subkey(format!(r"{name}\shell\open\command"))
                .unwrap();
            key.set_value(
                "",
                &if name == "found.exe" {
                    r"C:\Apps\found.exe"
                } else if name == "ambiguous.exe" {
                    r"C:\Missing App\ambiguous.exe"
                } else {
                    original
                },
            )
            .unwrap();
            if name == "delegate.exe" {
                key.set_value("DelegateExecute", &"{11111111-1111-4111-8111-111111111111}")
                    .unwrap();
            }
            if name == "dde.exe" {
                root.create_subkey(r"dde.exe\shell\open\ddeexec").unwrap();
            }
        }
        let source = Source {
            category: Category::ApplicationCommands,
            hive: "HKCU",
            path: APPLICATIONS_KEY,
            flag: 0,
            view: "shared",
        };
        let mut scope = ScopeResult {
            id: "test".into(),
            category: source.category,
            hive: "HKCU".into(),
            key_path: source.path.into(),
            view: "shared".into(),
            status: "complete".into(),
            entries: 0,
            notes: vec![],
        };
        let mut entries = vec![];
        let probe = Probe(Cell::new(0));
        scan_applications(
            &source,
            &root,
            &AtomicBool::new(false),
            &Environment::default(),
            &mut entries,
            &mut scope,
            &probe,
        );
        assert_eq!(entries.len(), 5);
        assert_eq!(probe.0.get(), 2);
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "missing.exe")
                .unwrap()
                .assessment
                .status,
            EntryStatus::Review
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "found.exe")
                .unwrap()
                .assessment
                .status,
            EntryStatus::Found
        );
        for name in ["delegate.exe", "dde.exe", "ambiguous.exe"] {
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
        let backups = tempfile::tempdir().unwrap();
        let mut manager = crate::changes::ChangeManager::new(
            crate::windows_changes::WindowsRegistryStore::default(),
            backups.path().join("unused"),
            LocalPathProbe,
        );
        for entry in &entries {
            assert!(!crate::changes::is_repair_candidate(entry));
            assert!(manager.prepare_quarantine(entry).is_err());
            assert_eq!(
                root.open_subkey(format!(r"{}\shell\open\command", entry.name))
                    .unwrap()
                    .get_value::<String, _>("")
                    .unwrap(),
                entry.raw_value
            );
        }
        assert!(!backups.path().join("unused").exists());
        entries.clear();
        scan_applications(
            &source,
            &root,
            &AtomicBool::new(true),
            &Environment::default(),
            &mut entries,
            &mut scope,
            &probe,
        );
        assert!(entries.is_empty());
        assert_eq!(scope.status, "cancelled");
        assert_eq!(probe.0.get(), 2);
    }
}
