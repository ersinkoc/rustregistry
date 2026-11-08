use super::{read_value, WindowsRegistryStore};
use crate::{
    applications::*,
    changes::{NamedValue, StoredValue},
};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

pub(super) fn open(
    parent: &RegKey,
    name: &str,
    transaction: Option<&Transaction>,
    write: bool,
) -> Result<Option<RegKey>, String> {
    let flags = KEY_READ | if write { KEY_SET_VALUE } else { 0 };
    let result = if let Some(tx) = transaction {
        parent.open_subkey_transacted_with_options_flags(name, tx, REG_OPTION_OPEN_LINK, flags)
    } else {
        parent.open_subkey_with_options_flags(name, REG_OPTION_OPEN_LINK, flags)
    };
    match result {
        Ok(key) => {
            if read_value(&key, "SymbolicLinkValue")?.is_some_and(|v| v.kind == 6) {
                return Err("Application registry links are outside repair scope.".into());
            }
            Ok(Some(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "Application metadata could not be read (Windows error {}).",
            error.raw_os_error().unwrap_or(0)
        )),
    }
}
pub(super) fn required(
    parent: &RegKey,
    name: &str,
    tx: Option<&Transaction>,
    write: bool,
) -> Result<RegKey, String> {
    open(parent, name, tx, write)?.ok_or_else(|| {
        "An application registration key is missing. Keys are never recreated.".into()
    })
}
pub(super) fn root(
    parent: &RegKey,
    path: &str,
    tx: Option<&Transaction>,
) -> Result<RegKey, String> {
    // Follow only the fixed Windows-managed Classes hive alias.
    let result = if let Some(tx) = tx {
        parent.open_subkey_transacted_with_flags(path, tx, KEY_READ)
    } else {
        parent.open_subkey_with_flags(path, KEY_READ)
    };
    result.map_err(|_| "The Classes root could not be completely verified.".into())
}
pub(super) fn only_child(key: &RegKey, expected: Option<&str>) -> Result<(), String> {
    let children = key
        .enum_keys()
        .take(2)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Application child keys could not be completely read.".to_string())?;
    if expected.map_or(!children.is_empty(), |name| {
        children.len() != 1 || !children[0].eq_ignore_ascii_case(name)
    }) {
        return Err(
            "Alternative, nested, or unknown application activation keys remain read-only.".into(),
        );
    }
    Ok(())
}
pub(super) fn values(key: &RegKey) -> Result<Vec<NamedValue>, String> {
    let mut values = vec![];
    let mut size = 0;
    for item in key.enum_values() {
        let (name, value) =
            item.map_err(|_| "Application metadata could not be completely read.".to_string())?;
        size += value.bytes.len();
        if values.len() >= 64 || size > 32_768 {
            return Err("Application metadata exceeds the backup limit.".into());
        }
        values.push(NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        });
    }
    values.sort_by_key(|v| v.name.to_ascii_lowercase());
    crate::associations::validate_values(&values)?;
    Ok(values)
}
impl WindowsRegistryStore {
    fn application_state_in(
        &self,
        name: &str,
        tx: Option<&Transaction>,
    ) -> Result<ApplicationSnapshot, String> {
        validate_application_name(name)?;
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        let classes = root(&user, &self.classes_path, tx)?;
        let machine = root(&machine, &self.machine_classes_path, tx)?;
        if let Some(apps) = open(&machine, "Applications", tx, false)? {
            if open(&apps, name, tx, false)?.is_some() {
                return Err("A machine-wide application with the same name exists. Repair and restore are blocked.".into());
            }
        }
        let apps = required(&classes, "Applications", tx, false)?;
        let app = required(&apps, name, tx, false)?;
        only_child(&app, Some("shell"))?;
        let shell = required(&app, "shell", tx, false)?;
        only_child(&shell, Some("open"))?;
        let verb = required(&shell, "open", tx, false)?;
        only_child(&verb, Some("command"))?;
        let command = required(&verb, "command", tx, false)?;
        only_child(&command, None)?;
        let snapshot = ApplicationSnapshot {
            application_values: values(&app)?,
            shell_values: values(&shell)?,
            verb_values: values(&verb)?,
            command_values: values(&command)?,
        };
        snapshot.validate()?;
        if read_value(&command, "")?.as_ref() != Some(snapshot.command()?) {
            return Err("The application command changed while its metadata was read.".into());
        }
        Ok(snapshot)
    }
    pub(crate) fn application_state(&self, name: &str) -> Result<ApplicationSnapshot, String> {
        self.application_state_in(name, None)
    }
    pub(crate) fn change_application_hidden(
        &self,
        name: &str,
        original: &ApplicationSnapshot,
        hide: bool,
    ) -> Result<(), String> {
        validate_application_name(name)?;
        original.validate_original()?;
        let expected = if hide {
            original.clone()
        } else {
            original.hidden()?
        };
        if self.application_state(name)? != expected {
            return Err("The application changed after review. Nothing was changed.".into());
        }
        let tx = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        if self.application_state_in(name, Some(&tx))? != expected {
            return Err(
                "The application changed before its transaction. Nothing was overwritten.".into(),
            );
        }
        let classes = root(
            &RegKey::predef(HKEY_CURRENT_USER),
            &self.classes_path,
            Some(&tx),
        )?;
        let apps = required(&classes, "Applications", Some(&tx), false)?;
        let app = required(&apps, name, Some(&tx), true)?;
        if hide {
            app.set_raw_value(
                NO_OPEN_WITH,
                &RegValue {
                    vtype: REG_SZ,
                    bytes: Cow::Borrowed(&[0, 0]),
                },
            )
        } else {
            app.delete_value(NO_OPEN_WITH)
        }
        .map_err(|error| {
            format!(
                "The application visibility change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        tx.commit().map_err(|error| format!("Windows did not commit the application change (Windows error {}). The backup is preserved.", error.raw_os_error().unwrap_or(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{ChangeManager, RegistryStore},
        Assessment, Category, EntryStatus, LocalPathProbe, RegistryEntry,
    };
    struct Fixture {
        classes: String,
        name: String,
        directory: tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            let id = uuid::Uuid::new_v4();
            let fixture = Self {
                classes: format!(r"Software\RustRegistryTests\{id}"),
                name: format!("Application-{id}.exe"),
                directory: tempfile::tempdir().unwrap(),
            };
            let (command, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(
                    r"{}\Applications\{}\{OPEN_COMMAND}",
                    fixture.classes, fixture.name
                ))
                .unwrap();
            let raw = format!("\"{}\" \"%1\" %*\0\0", fixture.target().display());
            command
                .set_raw_value(
                    "",
                    &RegValue {
                        vtype: REG_EXPAND_SZ,
                        bytes: Cow::Owned(raw.encode_utf16().flat_map(u16::to_le_bytes).collect()),
                    },
                )
                .unwrap();
            fixture
                .app()
                .set_value("FriendlyAppName", &"Application recovery fixture")
                .unwrap();
            fixture
        }
        fn target(&self) -> std::path::PathBuf {
            self.directory.path().join("missing app.exe")
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                classes_path: self.classes.clone(),
                ..Default::default()
            }
        }
        fn app(&self) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(
                    format!(r"{}\Applications\{}", self.classes, self.name),
                    KEY_ALL_ACCESS,
                )
                .unwrap()
        }
        fn command(&self) -> RegKey {
            self.app()
                .open_subkey_with_flags(OPEN_COMMAND, KEY_ALL_ACCESS)
                .unwrap()
        }
        fn entry(&self) -> RegistryEntry {
            let snapshot = self.store().read_application(&self.name).unwrap();
            RegistryEntry {
                id: self.name.clone(),
                name: self.name.clone(),
                category: Category::ApplicationCommands,
                hive: "HKCU".into(),
                key_path: format!(r"{APPLICATIONS_KEY}\{}\{OPEN_COMMAND}", self.name),
                view: "shared".into(),
                value_name: String::new(),
                value_type: "REG_EXPAND_SZ".into(),
                raw_value: snapshot.command().unwrap().text().unwrap(),
                publisher: None,
                version: None,
                assessment: Assessment {
                    status: EntryStatus::Review,
                    code: "target_missing".into(),
                    explanation: "Owned missing executable".into(),
                    target: Some(self.target().display().to_string()),
                },
                snapshot: None,
                app_path_guard: None,
                app_path_repairable: false,
                uninstall_snapshot: None,
                uninstall_repairable: false,
                uninstall_hidden: false,
                association_state: None,
                association_repairable: false,
                com_state: None,
                com_repairable: false,
                service_state: None,
                service_repairable: false,
                application_snapshot: Some(snapshot),
                application_repairable: true,
                application_hidden: false,
                shared_dll_repairable: false,
                registered_app_repairable: false,
                type_library_state: None,
                type_library_repairable: false,
                prog_id_state: None,
                prog_id_repairable: false,
                interface_state: None,
                interface_repairable: false,
                conversion_state: None,
                maintenance_state: None,
                file_reference: None,
                file_reference_repairable: false,
                sound_state: None,
                sound_repairable: false,
                maintenance_repairable: false,
                conversion_repairable: false,
                redirection_state: None,
                redirection_repairable: false,
                proxy_state: None,
                proxy_repairable: false,
                icon_state: None,
                icon_repairable: false,
                menu_snapshot: None,
                menu_repairable: false,
                menu_hidden: false,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.classes);
        }
    }

    #[test]
    fn application_quick_and_selected_clean_back_up_restart_and_restore_without_changing_command_bytes(
    ) {
        for mode in ["quick", "selected"] {
            let fixture = Fixture::new();
            let directory = tempfile::tempdir().unwrap();
            let backups = directory.path().join("backups");
            let entry = fixture.entry();
            let original = entry.application_snapshot.clone().unwrap();
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            assert!(crate::changes::is_repair_candidate(&entry));
            let preview = manager
                .prepare_clean(std::slice::from_ref(&entry), mode)
                .unwrap();
            assert_eq!(preview.items.len(), 1);
            assert_eq!(preview.items[0].scope, "application");
            assert_eq!(preview.items[0].value_name, NO_OPEN_WITH);
            assert_eq!(preview.items[0].value_type, "REG_SZ");
            assert_eq!(
                preview.items[0].application_command.as_deref(),
                Some(entry.raw_value.as_str())
            );
            assert_eq!(
                fixture.store().read_application(&fixture.name).unwrap(),
                original
            );
            assert!(!backups.exists());
            manager.cancel();
            assert!(manager.apply_clean(&preview.token).is_err());
            let preview = manager.prepare_clean(&[entry], mode).unwrap();
            let result = manager.apply_clean(&preview.token).unwrap();
            assert!(result.failed.is_none());
            assert_eq!(result.completed.len(), 1);
            let id = &result.completed[0].backup_id;
            assert_eq!(
                fixture.store().read_application(&fixture.name).unwrap(),
                original.hidden().unwrap()
            );
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(backups.join(format!("{id}.json"))).unwrap())
                    .unwrap();
            assert_eq!(record["schemaVersion"], 8);
            assert_eq!(
                record["original"],
                serde_json::to_value(original.command().unwrap()).unwrap()
            );
            assert_eq!(
                record["application"]["snapshot"],
                serde_json::to_value(&original).unwrap()
            );
            drop(manager);
            let mut manager = ChangeManager::new(fixture.store(), backups, LocalPathProbe);
            let inventory = manager.inventory().unwrap();
            assert_eq!(inventory.backups[0].state, "restore_available");
            assert_eq!(inventory.backups[0].scope, "application");
            assert!(inventory.backups[0].note.contains("NoOpenWith"));
            let restore = manager.prepare_restore(id).unwrap();
            manager.apply(&restore.token).unwrap();
            assert_eq!(
                fixture.store().read_application(&fixture.name).unwrap(),
                original
            );
        }
    }

    #[test]
    fn application_repairs_block_changed_commands_metadata_alternate_activation_reappearing_files_and_failed_backups(
    ) {
        for scenario in 0..10 {
            let fixture = Fixture::new();
            let directory = tempfile::tempdir().unwrap();
            let backups = directory.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager.prepare_quarantine(&fixture.entry()).unwrap();
            match scenario {
                0 => fixture
                    .command()
                    .set_value("", &"preserve changed command")
                    .unwrap(),
                1 => fixture
                    .app()
                    .set_value("FriendlyAppName", &"changed name")
                    .unwrap(),
                2 => fixture
                    .command()
                    .set_value("DelegateExecute", &"value")
                    .unwrap(),
                3 => {
                    fixture.app().create_subkey(r"shell\open\ddeexec").unwrap();
                }
                4 => {
                    fixture.app().create_subkey("SupportedTypes").unwrap();
                }
                5 => fixture
                    .app()
                    .open_subkey_with_flags("shell", KEY_ALL_ACCESS)
                    .unwrap()
                    .set_value("", &"open")
                    .unwrap(),
                6 => fixture.command().delete_value("").unwrap(),
                7 => std::fs::write(fixture.target(), b"never executed").unwrap(),
                8 => fixture.app().set_value(NO_OPEN_WITH, &"").unwrap(),
                9 => std::fs::write(backups, b"not a directory").unwrap(),
                _ => unreachable!(),
            }
            assert!(manager.apply(&plan.token).is_err(), "scenario {scenario}");
            assert_eq!(
                fixture.app().get_raw_value(NO_OPEN_WITH).is_ok(),
                scenario == 8
            );
            if scenario == 0 {
                assert_eq!(
                    fixture.command().get_value::<String, _>("").unwrap(),
                    "preserve changed command"
                );
            }
        }
    }

    #[test]
    fn application_restore_refuses_changed_flags_commands_metadata_missing_keys_and_corrupt_backups(
    ) {
        for scenario in 0..9 {
            let fixture = Fixture::new();
            let directory = tempfile::tempdir().unwrap();
            let backups = directory.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager.prepare_quarantine(&fixture.entry()).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            match scenario {
                0 => fixture.app().delete_value(NO_OPEN_WITH).unwrap(),
                1 => fixture.app().set_value(NO_OPEN_WITH, &1u32).unwrap(),
                2 => fixture
                    .command()
                    .set_value("", &"keep newer command")
                    .unwrap(),
                3 => fixture
                    .app()
                    .set_value("FriendlyAppName", &"keep newer name")
                    .unwrap(),
                4 => {
                    fixture.app().create_subkey("Custom").unwrap();
                }
                5 => fixture.command().delete_value("").unwrap(),
                6 => fixture.app().delete_subkey_all("shell").unwrap(),
                7 | 8 => {
                    let path = backups.join(format!("{}.json", result.backup_id));
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    if scenario == 7 {
                        record["application"]["executable"] = serde_json::json!("Other.exe");
                    } else {
                        record["schemaVersion"] = serde_json::json!(2);
                    }
                    std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                manager.prepare_restore(&result.backup_id).is_err(),
                "scenario {scenario}"
            );
            if scenario == 2 {
                assert_eq!(
                    fixture.command().get_value::<String, _>("").unwrap(),
                    "keep newer command"
                );
            }
            if scenario == 6 {
                assert!(fixture.app().open_subkey("shell").is_err());
            }
        }
    }

    #[test]
    fn application_batch_stops_on_changed_registration_and_keeps_completed_entries_restorable() {
        let first = Fixture::new();
        // Both fixtures live under one isolated Classes root, as they do in production.
        let mut second = Fixture::new();
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let old_second = second.classes.clone();
        let old_values = second.store().read_application(&second.name).unwrap();
        let (command, _) = user
            .create_subkey(format!(
                r"{}\Applications\{}\{OPEN_COMMAND}",
                first.classes, second.name
            ))
            .unwrap();
        command
            .set_raw_value(
                "",
                &RegValue {
                    vtype: REG_EXPAND_SZ,
                    bytes: Cow::Borrowed(&old_values.command().unwrap().bytes),
                },
            )
            .unwrap();
        second.classes = first.classes.clone();
        user.delete_subkey_all(old_second).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut manager = ChangeManager::new(
            first.store(),
            directory.path().join("backups"),
            LocalPathProbe,
        );
        let original = first.store().read_application(&first.name).unwrap();
        let plan = manager
            .prepare_clean(&[first.entry(), second.entry()], "selected")
            .unwrap();
        second
            .command()
            .set_value("", &"preserve conflict")
            .unwrap();
        let result = manager.apply_clean(&plan.token).unwrap();
        assert_eq!(result.completed.len(), 1);
        assert!(result.failed.is_some());
        assert_eq!(result.not_attempted, 0);
        assert!(second.app().get_raw_value(NO_OPEN_WITH).is_err());
        let restore = manager
            .prepare_restore(&result.completed[0].backup_id)
            .unwrap();
        manager.apply(&restore.token).unwrap();
        assert_eq!(
            first.store().read_application(&first.name).unwrap(),
            original
        );
    }

    #[test]
    fn restores_unchanged_v018_application_backup_without_migration() {
        let fixture = Fixture::new();
        let directory = tempfile::tempdir().unwrap();
        let legacy = include_str!("../tests/fixtures/application-backup-v8.json");
        let record: serde_json::Value = serde_json::from_str(legacy).unwrap();
        let name = record["application"]["executable"].as_str().unwrap();
        let original: StoredValue = serde_json::from_value(record["original"].clone()).unwrap();
        let original_snapshot: ApplicationSnapshot =
            serde_json::from_value(record["application"]["snapshot"].clone()).unwrap();
        let (app, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"{}\Applications\{name}", fixture.classes))
            .unwrap();
        app.set_value(NO_OPEN_WITH, &"").unwrap();
        let (command, _) = app.create_subkey(OPEN_COMMAND).unwrap();
        command
            .set_raw_value(
                "",
                &RegValue {
                    vtype: REG_EXPAND_SZ,
                    bytes: Cow::Borrowed(&original.bytes),
                },
            )
            .unwrap();
        let id = record["id"].as_str().unwrap();
        let path = directory.path().join(format!("{id}.json"));
        std::fs::write(&path, legacy).unwrap();
        let mut manager =
            ChangeManager::new(fixture.store(), directory.path().into(), LocalPathProbe);
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "application");
        manager.apply(&plan.token).unwrap();
        assert_eq!(
            fixture.store().read_application(name).unwrap(),
            original_snapshot
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), legacy);
    }
}
