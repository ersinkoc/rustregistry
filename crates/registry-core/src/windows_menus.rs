use super::{
    applications::{only_child, open, required, root, values},
    WindowsRegistryStore,
};
use crate::{analysis::LocalPathProbe, shell_menus::*};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};
fn menu_root(
    hive: winreg::HKEY,
    classes: &str,
    location: MenuLocation,
    tx: Option<&Transaction>,
) -> Result<Option<RegKey>, String> {
    let mut key = root(&RegKey::predef(hive), classes, tx)?;
    for component in location.components() {
        let Some(child) = open(&key, component, tx, false)? else {
            return Ok(None);
        };
        key = child;
    }
    Ok(Some(key))
}
pub(crate) fn open_menu_source(
    hive: &str,
    location: MenuLocation,
) -> Result<Option<RegKey>, String> {
    menu_root(
        if hive == "HKCU" {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        },
        r"Software\Classes",
        location,
        None,
    )
}
impl WindowsRegistryStore {
    fn menu_roots(
        &self,
        app: &MenuBackup,
        tx: Option<&Transaction>,
    ) -> Result<(RegKey, Option<RegKey>), String> {
        app.validate()?;
        let machine_hive = {
            #[cfg(test)]
            {
                if self.menu_test_machine_user {
                    HKEY_CURRENT_USER
                } else {
                    HKEY_LOCAL_MACHINE
                }
            }
            #[cfg(not(test))]
            {
                HKEY_LOCAL_MACHINE
            }
        };
        let user = menu_root(HKEY_CURRENT_USER, &self.classes_path, app.location, tx)?
            .ok_or("The existing user menu root is missing. Keys are not recreated.")?;
        let machine = menu_root(machine_hive, &self.machine_classes_path, app.location, tx)?;
        if let Some(machine) = &machine {
            if open(machine, &app.verb_name, tx, false)?.is_some() {
                return Err("A machine menu counterpart exists. Changing registration fallback remains outside recovery scope.".into());
            }
        }
        Ok((user, machine))
    }
    fn menu_snapshot_in(
        &self,
        app: &MenuBackup,
        tx: Option<&Transaction>,
    ) -> Result<MenuSnapshot, String> {
        let (user, machine) = self.menu_roots(app, tx)?;
        let verb = required(&user, &app.verb_name, tx, false)?;
        only_child(&verb, Some("command"))?;
        let command = required(&verb, "command", tx, false)?;
        only_child(&command, None)?;
        let snapshot = MenuSnapshot {
            user_root_values: values(&user)?,
            machine_root_values: machine.as_ref().map(values).transpose()?,
            verb_values: values(&verb)?,
            command_values: values(&command)?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
    pub(crate) fn menu_snapshot(&self, app: &MenuBackup) -> Result<MenuSnapshot, String> {
        self.menu_snapshot_in(app, None)
    }
    pub(crate) fn menu_write_access(&self, app: &MenuBackup) -> Result<(), String> {
        let (user, _) = self.menu_roots(app, None)?;
        required(&user, &app.verb_name, None, true).map(|_| ())
    }
    pub(crate) fn change_menu_hidden(&self, app: &MenuBackup, hidden: bool) -> Result<(), String> {
        app.validate()?;
        verify_missing_menu_command(app.snapshot.command()?, &LocalPathProbe)?;
        let expected = if hidden {
            app.snapshot.clone()
        } else {
            app.snapshot.hidden()?
        };
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.menu_snapshot_in(app, Some(&tx))? != expected {
            return Err("Menu metadata or visibility changed. Nothing was overwritten.".into());
        }
        verify_missing_menu_command(app.snapshot.command()?, &LocalPathProbe)?;
        let (user, _) = self.menu_roots(app, Some(&tx))?;
        let verb = required(&user, &app.verb_name, Some(&tx), true)?;
        if hidden {
            verb.set_raw_value(
                PROGRAMMATIC_ONLY,
                &RegValue {
                    vtype: REG_SZ,
                    bytes: Cow::Borrowed(&[0, 0]),
                },
            )
        } else {
            verb.delete_value(PROGRAMMATIC_ONLY)
        }
        .map_err(|e| format!("Menu visibility update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Menu transaction did not commit: {e}"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{ChangeManager, NamedValue, RegistryStore, StoredValue},
        RegistryEntry,
    };
    struct Fixture {
        base: String,
        files: tempfile::TempDir,
    }
    fn text(name: &str, raw: &str) -> NamedValue {
        NamedValue {
            name: name.into(),
            value: StoredValue {
                kind: 1,
                bytes: raw
                    .encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            },
        }
    }
    impl Fixture {
        fn new() -> Self {
            let f = Self {
                base: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
                files: tempfile::tempdir().unwrap(),
            };
            for scope in ["User", "Machine"] {
                for location in [MenuLocation::Files, MenuLocation::DirectoryBackground] {
                    RegKey::predef(HKEY_CURRENT_USER)
                        .create_subkey(format!(
                            r"{}\{scope}\{}",
                            f.base,
                            location.components().join("\\")
                        ))
                        .unwrap();
                }
            }
            for i in 0..2 {
                let key = f.create(i);
                key.set_value("MUIVerb", &"Owned menu description").unwrap();
                key.set_value("Icon", &r"C:\Preserved\icon.exe,0").unwrap();
                key.set_value("Extended", &"").unwrap();
                key.create_subkey("command")
                    .unwrap()
                    .0
                    .set_raw_value(
                        "",
                        &RegValue {
                            vtype: if i == 0 { REG_EXPAND_SZ } else { REG_SZ },
                            bytes: Cow::Owned(f.command(i).bytes),
                        },
                    )
                    .unwrap();
            }
            f
        }
        fn location(&self, i: usize) -> MenuLocation {
            if i == 0 {
                MenuLocation::Files
            } else {
                MenuLocation::DirectoryBackground
            }
        }
        fn name(&self, i: usize) -> String {
            format!("RustRegistry.Custom{i}")
        }
        fn path(&self, i: usize) -> String {
            format!(
                r"{}\User\{}\{}",
                self.base,
                self.location(i).components().join("\\"),
                self.name(i)
            )
        }
        fn create(&self, i: usize) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(self.path(i))
                .unwrap()
                .0
        }
        fn key(&self, i: usize, suffix: &str) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(format!("{}\\{suffix}", self.path(i)), KEY_ALL_ACCESS)
                .unwrap()
        }
        fn file(&self, i: usize) -> std::path::PathBuf {
            self.files.path().join(format!("missing{i}.exe"))
        }
        fn command(&self, i: usize) -> StoredValue {
            let raw = format!("\"{}\" \"%1\" %*", self.file(i).display());
            StoredValue {
                kind: if i == 0 { 2 } else { 1 },
                bytes: raw
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }
        }
        fn selector(&self, i: usize) -> MenuBackup {
            MenuBackup {
                location: self.location(i),
                verb_name: self.name(i),
                snapshot: MenuSnapshot {
                    user_root_values: vec![],
                    machine_root_values: None,
                    verb_values: vec![],
                    command_values: vec![text("", "placeholder")],
                },
            }
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                classes_path: format!(r"{}\User", self.base),
                machine_classes_path: format!(r"{}\Machine", self.base),
                menu_test_machine_user: true,
                ..Default::default()
            }
        }
        fn entry(&self, i: usize) -> RegistryEntry {
            let mut entry:RegistryEntry=serde_json::from_value(serde_json::json!({"id":self.name(i),"name":self.name(i),"category":"shell_menus","hive":"HKCU","view":"shared","keyPath":format!(r"{}\{}\command",self.location(i).path(),self.name(i)),"valueName":"","valueType":if i==0{"REG_EXPAND_SZ"}else{"REG_SZ"},"rawValue":self.command(i).text().unwrap(),"publisher":null,"version":null,"assessment":{"status":"review","code":"target_missing","explanation":"Owned missing menu command","target":self.file(i)},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"menuRepairable":true,"menuHidden":false})).unwrap();
            entry.menu_snapshot = Some(self.store().menu_snapshot(&self.selector(i)).unwrap());
            entry
        }
        fn counterpart(&self) {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(
                    r"{}\Machine\{}\{}",
                    self.base,
                    self.location(0).components().join("\\"),
                    self.name(0)
                ))
                .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.base);
        }
    }
    #[test]
    fn menu_individual_quick_and_selected_repairs_preserve_commands_and_restore_exact_visibility_after_restart(
    ) {
        for mode in ["single", "quick", "selected"] {
            let f = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let entries = [f.entry(0), f.entry(1)];
            let originals = [
                entries[0].menu_snapshot.clone().unwrap(),
                entries[1].menu_snapshot.clone().unwrap(),
            ];
            let mut manager =
                ChangeManager::new(f.store(), dir.path().join("backups"), LocalPathProbe);
            let ids = if mode == "single" {
                let p = manager.prepare_quarantine(&entries[0]).unwrap();
                manager.cancel();
                assert!(manager.apply(&p.token).is_err());
                let p = manager.prepare_quarantine(&entries[0]).unwrap();
                vec![manager.apply(&p.token).unwrap().backup_id]
            } else {
                let p = manager.prepare_clean(&entries, mode).unwrap();
                manager.cancel();
                assert!(manager.apply_clean(&p.token).is_err());
                let p = manager.prepare_clean(&entries, mode).unwrap();
                let result = manager.apply_clean(&p.token).unwrap();
                assert!(result.failed.is_none());
                assert_eq!(result.completed.len(), 2);
                result.completed.into_iter().map(|r| r.backup_id).collect()
            };
            drop(manager);
            let mut manager =
                ChangeManager::new(f.store(), dir.path().join("backups"), LocalPathProbe);
            for (i, id) in ids.iter().enumerate() {
                assert_eq!(
                    f.store().menu_snapshot(&f.selector(i)).unwrap(),
                    originals[i].hidden().unwrap()
                );
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(dir.path().join("backups").join(format!("{id}.json"))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["schemaVersion"], 16);
                assert_eq!(
                    record["original"],
                    serde_json::to_value(f.command(i)).unwrap()
                );
                let restore = manager.prepare_restore(id).unwrap();
                assert_eq!(restore.scope, "shell_menu");
                manager.apply(&restore.token).unwrap();
                assert_eq!(
                    f.store().menu_snapshot(&f.selector(i)).unwrap(),
                    originals[i]
                );
            }
        }
    }
    #[test]
    fn menu_repair_and_restore_block_files_counterparts_preferred_verbs_metadata_flags_missing_keys_and_bad_backups(
    ) {
        for restore in [false, true] {
            for scenario in 0..10 {
                let f = Fixture::new();
                let dir = tempfile::tempdir().unwrap();
                let backups = dir.path().join("backups");
                let mut manager = ChangeManager::new(f.store(), backups.clone(), LocalPathProbe);
                let mut plan = manager.prepare_quarantine(&f.entry(0)).unwrap();
                let mut id = None;
                if restore {
                    let result = manager.apply(&plan.token).unwrap();
                    id = Some(result.backup_id.clone());
                    plan = manager.prepare_restore(&result.backup_id).unwrap();
                }
                match scenario {
                    0 => std::fs::write(f.file(0), b"inert file").unwrap(),
                    1 => f.counterpart(),
                    2 => f
                        .key(0, "command")
                        .set_value("", &"changed command")
                        .unwrap(),
                    3 => f
                        .key(0, "")
                        .set_value("MUIVerb", &"changed display")
                        .unwrap(),
                    4 => {
                        f.key(0, "").create_subkey("ddeexec").unwrap();
                    }
                    5 => {
                        f.key(0, "").delete_subkey("command").unwrap();
                    }
                    6 => f
                        .key(0, "")
                        .set_value(PROGRAMMATIC_ONLY, &"changed flag")
                        .unwrap(),
                    7 => RegKey::predef(HKEY_CURRENT_USER)
                        .open_subkey_with_flags(format!(r"{}\User\*\shell", f.base), KEY_ALL_ACCESS)
                        .unwrap()
                        .set_value("", &"Other.Preferred")
                        .unwrap(),
                    8 => f
                        .key(0, "command")
                        .set_value("DelegateExecute", &"unknown")
                        .unwrap(),
                    9 => {
                        if let Some(id) = id {
                            let path = backups.join(format!("{id}.json"));
                            let mut r: serde_json::Value =
                                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                            r["menu"]["verbName"] = serde_json::json!("Other.Verb");
                            std::fs::write(path, serde_json::to_vec(&r).unwrap()).unwrap();
                        } else {
                            std::fs::write(&backups, b"not a directory").unwrap();
                        }
                    }
                    _ => unreachable!(),
                }
                assert!(
                    manager.apply(&plan.token).is_err(),
                    "restore={restore}, case={scenario}"
                );
                assert_eq!(
                    f.key(1, "command")
                        .get_raw_value("")
                        .unwrap()
                        .bytes
                        .as_ref(),
                    f.command(1).bytes
                );
                if scenario != 2 && scenario != 5 {
                    assert_eq!(
                        f.key(0, "command")
                            .get_raw_value("")
                            .unwrap()
                            .bytes
                            .as_ref(),
                        f.command(0).bytes
                    );
                }
            }
        }
    }
    #[test]
    fn menu_batch_stops_at_first_conflict_and_read_only_review_creates_no_backup() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let mut manager = ChangeManager::new(f.store(), dir.path().join("backups"), LocalPathProbe);
        let p = manager
            .prepare_clean(&[f.entry(0), f.entry(1)], "quick")
            .unwrap();
        f.key(1, "").set_value("MUIVerb", &"changed").unwrap();
        let result = manager.apply_clean(&p.token).unwrap();
        assert_eq!(result.completed.len(), 1);
        assert!(result.failed.is_some());
        let r = manager
            .prepare_restore(&result.completed[0].backup_id)
            .unwrap();
        manager.apply(&r.token).unwrap();
        struct ReadOnly(WindowsRegistryStore);
        impl RegistryStore for ReadOnly {
            fn read_menu(&self, a: &MenuBackup) -> Result<MenuSnapshot, String> {
                self.0.menu_snapshot(a)
            }
            fn check_menu_write_access(&self, _: &MenuBackup) -> Result<(), String> {
                Err("Existing menu write access required".into())
            }
            fn read(&self, _: &str) -> Result<Option<StoredValue>, String> {
                unreachable!()
            }
            fn compare_exchange(
                &self,
                _: &str,
                _: Option<&StoredValue>,
                _: Option<&StoredValue>,
            ) -> Result<(), String> {
                unreachable!()
            }
        }
        let backups = dir.path().join("denied");
        let mut manager = ChangeManager::new(ReadOnly(f.store()), backups.clone(), LocalPathProbe);
        assert!(manager
            .prepare_quarantine(&f.entry(0))
            .unwrap_err()
            .contains("write access"));
        assert!(!backups.exists());
    }
    #[test]
    fn restores_frozen_v0116_menu_backup_without_migration_or_command_changes() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let bytes = include_bytes!("../tests/fixtures/menu-backup-v16.json");
        let record: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let id = record["id"].as_str().unwrap();
        let original: StoredValue = serde_json::from_value(record["original"].clone()).unwrap();
        let verb = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"{}\User\*\shell\RustRegistry.LegacyMenu", f.base))
            .unwrap()
            .0;
        verb.set_value(PROGRAMMATIC_ONLY, &"").unwrap();
        let command = verb.create_subkey("command").unwrap().0;
        command
            .set_raw_value(
                "",
                &RegValue {
                    vtype: REG_SZ,
                    bytes: Cow::Borrowed(&original.bytes),
                },
            )
            .unwrap();
        let file = dir.path().join(format!("{id}.json"));
        std::fs::write(&file, bytes).unwrap();
        let mut m = ChangeManager::new(f.store(), dir.path().to_path_buf(), LocalPathProbe);
        let p = m.prepare_restore(id).unwrap();
        assert_eq!(p.scope, "shell_menu");
        m.apply(&p.token).unwrap();
        assert!(super::super::read_value(&verb, PROGRAMMATIC_ONLY)
            .unwrap()
            .is_none());
        assert_eq!(
            super::super::read_value(&command, "").unwrap(),
            Some(original)
        );
        assert_eq!(std::fs::read(file).unwrap(), bytes);
    }
}
