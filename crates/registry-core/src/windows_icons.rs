use super::{
    applications::{only_child, open, required, root, values},
    read_value, WindowsRegistryStore,
};
use crate::{
    analysis::LocalPathProbe, application_icons::*, applications::ApplicationSnapshot,
    changes::StoredValue,
};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};
pub(crate) fn open_icon_child(parent: &RegKey, path: &str) -> Result<Option<RegKey>, String> {
    open(parent, path, None, false)
}
impl WindowsRegistryStore {
    fn icon_parent(&self, app: &IconBackup, tx: Option<&Transaction>) -> Result<RegKey, String> {
        app.validate()?;
        let machine_hive = {
            #[cfg(test)]
            {
                if self.icon_test_machine_user {
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
        let machine = root(
            &RegKey::predef(machine_hive),
            &self.machine_classes_path,
            tx,
        )?;
        if let Some(apps) = open(&machine, "Applications", tx, false)? {
            if open(&apps, &app.executable, tx, false)?.is_some() {
                return Err("A machine application counterpart exists. Icon repair and restore are blocked.".into());
            }
        }
        let classes = root(&RegKey::predef(HKEY_CURRENT_USER), &self.classes_path, tx)?;
        let apps = required(&classes, "Applications", tx, false)?;
        required(&apps, &app.executable, tx, false)
    }
    fn icon_state_in(
        &self,
        app: &IconBackup,
        tx: Option<&Transaction>,
    ) -> Result<IconState, String> {
        let parent = self.icon_parent(app, tx)?;
        let children: Vec<String> = parent
            .enum_keys()
            .take(4)
            .collect::<Result<_, _>>()
            .map_err(|_| "Application structure could not be read.")?;
        if children.len() != 2
            || !["DefaultIcon", "shell"]
                .iter()
                .all(|name| children.iter().any(|v| v.eq_ignore_ascii_case(name)))
        {
            return Err("Only a simple application with DefaultIcon and one open command supports icon recovery.".into());
        }
        let icon = required(&parent, "DefaultIcon", tx, false)?;
        only_child(&icon, None)?;
        if values(&icon)?.iter().any(|v| !v.name.is_empty()) {
            return Err("Named icon metadata remains read-only.".into());
        }
        let shell = required(&parent, "shell", tx, false)?;
        only_child(&shell, Some("open"))?;
        let verb = required(&shell, "open", tx, false)?;
        only_child(&verb, Some("command"))?;
        let command = required(&verb, "command", tx, false)?;
        only_child(&command, None)?;
        let guard = ApplicationSnapshot {
            application_values: values(&parent)?,
            shell_values: values(&shell)?,
            verb_values: values(&verb)?,
            command_values: values(&command)?,
        };
        guard.validate()?;
        Ok(IconState {
            value: read_value(&icon, "")?,
            guard,
        })
    }
    pub(crate) fn icon_state(&self, app: &IconBackup) -> Result<IconState, String> {
        self.icon_state_in(app, None)
    }
    pub(crate) fn icon_write_access(&self, app: &IconBackup) -> Result<(), String> {
        required(&self.icon_parent(app, None)?, "DefaultIcon", None, true).map(|_| ())
    }
    pub(crate) fn exchange_icon(
        &self,
        app: &IconBackup,
        expected: &IconState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        app.validate()?;
        if expected.value.is_some() == replacement.is_some() || expected.guard != app.guard {
            return Err("Only exact icon removal or restoration is supported.".into());
        }
        let original = expected
            .value
            .as_ref()
            .or(replacement)
            .ok_or("Missing icon evidence.")?;
        verify_missing_icon(original, &LocalPathProbe)?;
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.icon_state_in(app, Some(&tx))? != *expected {
            return Err("Application or icon metadata changed. Nothing was overwritten.".into());
        }
        verify_missing_icon(original, &LocalPathProbe)?;
        let leaf = required(
            &self.icon_parent(app, Some(&tx))?,
            "DefaultIcon",
            Some(&tx),
            true,
        )?;
        match replacement {
            Some(value) => leaf.set_raw_value(
                "",
                &RegValue {
                    vtype: if value.kind == 1 {
                        REG_SZ
                    } else {
                        REG_EXPAND_SZ
                    },
                    bytes: Cow::Borrowed(&value.bytes),
                },
            ),
            None => leaf.delete_value(""),
        }
        .map_err(|e| format!("Icon reference update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Icon transaction did not commit: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{ChangeManager, RegistryStore},
        RegistryEntry,
    };
    struct Fixture {
        base: String,
        files: tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            let f = Self {
                base: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
                files: tempfile::tempdir().unwrap(),
            };
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\Machine", f.base))
                .unwrap();
            for i in 0..2 {
                let key = RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(format!(r"{}\User\Applications\{}", f.base, f.name(i)))
                    .unwrap()
                    .0;
                key.set_value("FriendlyAppName", &"Owned icon application")
                    .unwrap();
                key.create_subkey(r"shell\open\command")
                    .unwrap()
                    .0
                    .set_value("", &r#""C:\Preserved\application.exe" "%1" %*"#)
                    .unwrap();
                key.create_subkey("DefaultIcon")
                    .unwrap()
                    .0
                    .set_raw_value(
                        "",
                        &RegValue {
                            vtype: if i == 0 { REG_EXPAND_SZ } else { REG_SZ },
                            bytes: Cow::Owned(f.original(i).bytes),
                        },
                    )
                    .unwrap();
            }
            f
        }
        fn name(&self, i: usize) -> String {
            format!("OwnedIcon{i}.exe")
        }
        fn file(&self, i: usize) -> std::path::PathBuf {
            self.files.path().join(format!("missing{i}.ico"))
        }
        fn original(&self, i: usize) -> StoredValue {
            StoredValue {
                kind: if i == 0 { 2 } else { 1 },
                bytes: self
                    .file(i)
                    .to_str()
                    .unwrap()
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }
        }
        fn key(&self, i: usize, path: &str) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(
                    format!(r"{}\User\Applications\{}\{path}", self.base, self.name(i)),
                    KEY_ALL_ACCESS,
                )
                .unwrap()
        }
        fn selector(&self, i: usize) -> IconBackup {
            IconBackup {
                executable: self.name(i),
                guard: ApplicationSnapshot {
                    application_values: vec![],
                    shell_values: vec![],
                    verb_values: vec![],
                    command_values: vec![crate::changes::NamedValue {
                        name: String::new(),
                        value: StoredValue {
                            kind: 1,
                            bytes: "x\0".encode_utf16().flat_map(u16::to_le_bytes).collect(),
                        },
                    }],
                },
            }
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                classes_path: format!(r"{}\User", self.base),
                machine_classes_path: format!(r"{}\Machine", self.base),
                icon_test_machine_user: true,
                ..Default::default()
            }
        }
        fn entry(&self, i: usize) -> RegistryEntry {
            let mut e:RegistryEntry=serde_json::from_value(serde_json::json!({"id":self.name(i),"name":self.name(i),"category":"application_icons","hive":"HKCU","view":"shared","keyPath":format!(r"{APPLICATIONS_KEY}\{}\DefaultIcon",self.name(i)),"valueName":"","valueType":if i==0{"REG_EXPAND_SZ"}else{"REG_SZ"},"rawValue":self.file(i),"publisher":null,"version":null,"assessment":{"status":"review","code":"target_missing","explanation":"Owned missing icon","target":self.file(i)},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"iconRepairable":true})).unwrap();
            e.icon_state = Some(self.store().read_icon(&self.selector(i)).unwrap());
            e
        }
        fn counterpart(&self) {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(
                    r"{}\Machine\Applications\{}",
                    self.base,
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
    fn icon_single_quick_and_selected_repairs_keep_separate_backups_and_restore_exact_commands_and_bytes(
    ) {
        for mode in ["single", "quick", "selected"] {
            let f = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let entries = [f.entry(0), f.entry(1)];
            let original = [
                entries[0].icon_state.clone().unwrap(),
                entries[1].icon_state.clone().unwrap(),
            ];
            let mut manager =
                ChangeManager::new(f.store(), dir.path().join("backups"), LocalPathProbe);
            let ids = if mode == "single" {
                let p = manager.prepare_quarantine(&entries[0]).unwrap();
                vec![manager.apply(&p.token).unwrap().backup_id]
            } else {
                let p = manager.prepare_clean(&entries, mode).unwrap();
                assert_eq!(p.items.len(), 2);
                manager.cancel();
                assert!(manager.apply_clean(&p.token).is_err());
                let p = manager.prepare_clean(&entries, mode).unwrap();
                let result = manager.apply_clean(&p.token).unwrap();
                assert!(result.failed.is_none());
                result.completed.into_iter().map(|r| r.backup_id).collect()
            };
            drop(manager);
            let mut manager =
                ChangeManager::new(f.store(), dir.path().join("backups"), LocalPathProbe);
            for (i, id) in ids.iter().enumerate() {
                let state = f.store().read_icon(&f.selector(i)).unwrap();
                assert!(state.value.is_none());
                assert_eq!(state.guard, original[i].guard);
                let bytes =
                    std::fs::read(dir.path().join("backups").join(format!("{id}.json"))).unwrap();
                let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(record["schemaVersion"], 15);
                assert_eq!(
                    record["original"],
                    serde_json::to_value(f.original(i)).unwrap()
                );
                let plan = manager.prepare_restore(id).unwrap();
                assert_eq!(plan.scope, "application_icon");
                manager.apply(&plan.token).unwrap();
                assert_eq!(f.store().read_icon(&f.selector(i)).unwrap(), original[i]);
            }
        }
    }
    #[test]
    fn icon_repair_and_restore_fail_closed_on_files_counterparts_metadata_missing_keys_and_backup_corruption(
    ) {
        for restore in [false, true] {
            for scenario in 0..8 {
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
                    0 => std::fs::write(f.file(0), b"inert icon control").unwrap(),
                    1 => f.counterpart(),
                    2 => f
                        .key(0, r"shell\open\command")
                        .set_value("", &"Changed command")
                        .unwrap(),
                    3 => {
                        f.key(0, "").create_subkey("SupportedTypes").unwrap();
                    }
                    4 => f.key(0, "").delete_subkey("DefaultIcon").unwrap(),
                    5 => f
                        .key(0, "DefaultIcon")
                        .set_value("Named", &"preserve")
                        .unwrap(),
                    6 => f
                        .key(0, "DefaultIcon")
                        .set_value("", &"replacement")
                        .unwrap(),
                    7 => {
                        if let Some(id) = &id {
                            let p = backups.join(format!("{id}.json"));
                            let mut r: serde_json::Value =
                                serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
                            r["icon"]["executable"] = serde_json::json!("Other.exe");
                            std::fs::write(p, serde_json::to_vec(&r).unwrap()).unwrap();
                        } else {
                            std::fs::write(&backups, b"not a directory").unwrap();
                        }
                    }
                    _ => unreachable!(),
                }
                assert!(
                    manager.apply(&plan.token).is_err(),
                    "restore={restore} scenario={scenario}"
                );
                assert_eq!(
                    read_value(&f.key(1, "DefaultIcon"), "").unwrap(),
                    Some(f.original(1))
                );
                if scenario != 4 && scenario != 6 {
                    assert_eq!(
                        read_value(&f.key(0, "DefaultIcon"), "").unwrap(),
                        if restore { None } else { Some(f.original(0)) }
                    );
                }
            }
        }
    }
    #[test]
    fn icon_batch_stops_at_first_conflict_and_review_requires_existing_write_access() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let mut manager = ChangeManager::new(f.store(), dir.path().join("backups"), LocalPathProbe);
        let plan = manager
            .prepare_clean(&[f.entry(0), f.entry(1)], "quick")
            .unwrap();
        f.key(1, "")
            .set_value("FriendlyAppName", &"changed")
            .unwrap();
        let result = manager.apply_clean(&plan.token).unwrap();
        assert_eq!(result.completed.len(), 1);
        assert!(result.failed.is_some());
        let p = manager
            .prepare_restore(&result.completed[0].backup_id)
            .unwrap();
        manager.apply(&p.token).unwrap();
        struct ReadOnly(WindowsRegistryStore);
        impl RegistryStore for ReadOnly {
            fn read_icon(&self, a: &IconBackup) -> Result<IconState, String> {
                self.0.read_icon(a)
            }
            fn check_icon_write_access(&self, _: &IconBackup) -> Result<(), String> {
                Err("Existing write access required".into())
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
}
