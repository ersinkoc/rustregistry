use super::{
    interfaces::{open, required, values},
    read_value, WindowsRegistryStore,
};
use crate::{changes::StoredValue, com_redirects::*};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

impl WindowsRegistryStore {
    fn verify_redirection(
        &self,
        app: &RedirectionBackup,
        tx: Option<&Transaction>,
    ) -> Result<(), String> {
        app.validate()?;
        if self.prog_id_target_in(&app.target, tx)? {
            return Err("The target CLSID exists in a user or machine 32/64-bit view. Repair or restore is blocked.".into());
        }
        let machine_hive = {
            #[cfg(test)]
            {
                if self.redirection_test_machine_user {
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
        let user32 = {
            #[cfg(test)]
            {
                self.redirection_test_user32
                    .as_ref()
                    .unwrap_or(&self.com_path)
            }
            #[cfg(not(test))]
            {
                &self.com_path
            }
        };
        for (hive, path, view) in [
            (HKEY_CURRENT_USER, user32, KEY_WOW64_32KEY),
            (machine_hive, &self.machine_com_path, KEY_WOW64_64KEY),
            (machine_hive, &self.machine_com_path, KEY_WOW64_32KEY),
        ] {
            if let Some(root) = open(&RegKey::predef(hive), path, view, tx, false, false)? {
                if open(&root, &app.owner, view, tx, false, false)?.is_some() {
                    return Err("A 32-bit user or machine class counterpart exists. TreatAs fallback changes remain outside recovery scope.".into());
                }
            }
        }
        Ok(())
    }
    fn redirection_parent(
        &self,
        app: &RedirectionBackup,
        tx: Option<&Transaction>,
    ) -> Result<RegKey, String> {
        self.verify_redirection(app, tx)?;
        let root = required(
            &RegKey::predef(HKEY_CURRENT_USER),
            &self.com_path,
            tx,
            false,
            false,
        )?;
        required(&root, &app.owner, tx, false, false)
    }
    fn redirection_leaf(
        &self,
        app: &RedirectionBackup,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<RegKey, String> {
        required(
            &self.redirection_parent(app, tx)?,
            "TreatAs",
            tx,
            write,
            false,
        )
    }
    fn redirection_state_in(
        &self,
        app: &RedirectionBackup,
        tx: Option<&Transaction>,
    ) -> Result<RedirectionState, String> {
        let parent = self.redirection_parent(app, tx)?;
        let children = parent
            .enum_keys()
            .take(3)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "TreatAs class structure is unreadable.")?;
        if children.len() != 1 || !children[0].eq_ignore_ascii_case("TreatAs") {
            return Err("Only a description and one flat TreatAs child support recovery. Servers, AutoTreatAs, conversion or other activation metadata remain read-only.".into());
        }
        let leaf = required(&parent, "TreatAs", tx, false, false)?;
        if leaf.enum_keys().next().is_some() || values(&leaf)?.iter().any(|v| !v.name.is_empty()) {
            return Err("Named or nested TreatAs metadata remains read-only.".into());
        }
        let guard = RedirectionGuard {
            values: values(&parent)?,
        };
        guard.validate()?;
        let value = read_value(&leaf, "")?;
        if let Some(value) = &value {
            mapping_target(value)?;
        }
        Ok(RedirectionState { value, guard })
    }
    pub(crate) fn redirection_state(
        &self,
        app: &RedirectionBackup,
    ) -> Result<RedirectionState, String> {
        self.redirection_state_in(app, None)
    }
    pub(crate) fn redirection_write_access(&self, app: &RedirectionBackup) -> Result<(), String> {
        self.redirection_leaf(app, None, true).map(|_| ())
    }
    pub(crate) fn exchange_redirection(
        &self,
        app: &RedirectionBackup,
        expected: &RedirectionState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        app.validate()?;
        if expected.value.is_some() == replacement.is_some()
            || expected.guard != app.guard
            || mapping_target(
                expected
                    .value
                    .as_ref()
                    .or(replacement)
                    .ok_or("Missing TreatAs evidence.")?,
            )? != app.target
        {
            return Err(
                "Only exact missing-local-target TreatAs removal or restoration is supported."
                    .into(),
            );
        }
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.redirection_state_in(app, Some(&tx))? != *expected {
            return Err("TreatAs evidence changed. Nothing was overwritten.".into());
        }
        let leaf = self.redirection_leaf(app, Some(&tx), true)?;
        match replacement {
            Some(value) => leaf.set_raw_value(
                "",
                &RegValue {
                    vtype: REG_SZ,
                    bytes: Cow::Borrowed(&value.bytes),
                },
            ),
            None => leaf.delete_value(""),
        }
        .map_err(|e| format!("TreatAs update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("TreatAs transaction did not commit: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{ChangeManager, RegistryStore},
        PathProbe, ProbeResult, RegistryEntry, TargetKind,
    };
    struct NoProbe;
    impl PathProbe for NoProbe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            panic!("TreatAs must not probe files or activate classes")
        }
    }
    struct Fixture {
        base: String,
        owners: [String; 2],
        targets: [String; 2],
    }
    impl Fixture {
        fn new() -> Self {
            let f = Self {
                base: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
                owners: std::array::from_fn(|_| format!("{{{}}}", uuid::Uuid::new_v4())),
                targets: std::array::from_fn(|_| format!("{{{}}}", uuid::Uuid::new_v4())),
            };
            for scope in ["User\\CLSID", "User32", "Machine\\CLSID"] {
                RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(format!(r"{}\{scope}", f.base))
                    .unwrap();
            }
            for i in 0..2 {
                let parent = f.create(&format!(r"User\CLSID\{}", f.owners[i]));
                parent.set_value("", &"Owned class description").unwrap();
                parent
                    .create_subkey("TreatAs")
                    .unwrap()
                    .0
                    .set_raw_value(
                        "",
                        &RegValue {
                            vtype: REG_SZ,
                            bytes: Cow::Owned(f.original(i).bytes),
                        },
                    )
                    .unwrap();
            }
            f
        }
        fn create(&self, path: &str) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\{path}", self.base))
                .unwrap()
                .0
        }
        fn parent(&self, i: usize) -> RegKey {
            self.create(&format!(r"User\CLSID\{}", self.owners[i]))
        }
        fn leaf(&self, i: usize) -> RegKey {
            self.parent(i)
                .open_subkey_with_flags("TreatAs", KEY_ALL_ACCESS)
                .unwrap()
        }
        fn original(&self, i: usize) -> StoredValue {
            StoredValue {
                kind: 1,
                bytes: self.targets[i]
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }
        }
        fn selector(&self, i: usize) -> RedirectionBackup {
            RedirectionBackup {
                owner: self.owners[i].clone(),
                target: self.targets[i].clone(),
                guard: RedirectionGuard { values: vec![] },
            }
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                com_path: format!(r"{}\User\CLSID", self.base),
                machine_com_path: format!(r"{}\Machine\CLSID", self.base),
                redirection_test_machine_user: true,
                redirection_test_user32: Some(format!(r"{}\User32", self.base)),
                prog_ids_path: format!(r"{}\User", self.base),
                machine_prog_ids_path: format!(r"{}\Machine", self.base),
                prog_id_test_machine_user: true,
                ..Default::default()
            }
        }
        fn entry(&self, i: usize) -> RegistryEntry {
            let mut e:RegistryEntry=serde_json::from_value(serde_json::json!({"id":self.owners[i],"name":self.owners[i],"category":"com_redirections","hive":"HKCU","view":"64","keyPath":format!(r"{}\{}\TreatAs",crate::com::CLSID_KEY,self.owners[i]),"valueName":"","valueType":"REG_SZ","rawValue":self.targets[i],"publisher":null,"version":null,"assessment":{"status":"review","code":"redirection_clsid_missing","explanation":"Owned missing local target","target":self.targets[i]},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"redirectionRepairable":true})).unwrap();
            e.redirection_state = Some(self.store().read_redirection(&self.selector(i)).unwrap());
            e
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.base);
        }
    }
    #[test]
    fn redirection_single_quick_and_selected_changes_keep_individual_backups_and_restore_exact_bytes_after_restart(
    ) {
        for mode in ["single", "quick", "selected"] {
            let f = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let mut m = ChangeManager::new(f.store(), dir.path().join("backups"), NoProbe);
            let ids = if mode == "single" {
                let p = m.prepare_quarantine(&f.entry(0)).unwrap();
                m.cancel();
                assert!(m.apply(&p.token).is_err());
                let p = m.prepare_quarantine(&f.entry(0)).unwrap();
                vec![m.apply(&p.token).unwrap().backup_id]
            } else {
                let p = m.prepare_clean(&[f.entry(0), f.entry(1)], mode).unwrap();
                let r = m.apply_clean(&p.token).unwrap();
                assert!(r.failed.is_none());
                assert_eq!(r.completed.len(), 2);
                r.completed.into_iter().map(|r| r.backup_id).collect()
            };
            drop(m);
            let mut m = ChangeManager::new(f.store(), dir.path().join("backups"), NoProbe);
            for (i, id) in ids.iter().enumerate() {
                assert!(read_value(&f.leaf(i), "").unwrap().is_none());
                let bytes =
                    std::fs::read(dir.path().join("backups").join(format!("{id}.json"))).unwrap();
                let r: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(r["schemaVersion"], 17);
                assert_eq!(r["original"], serde_json::to_value(f.original(i)).unwrap());
                let p = m.prepare_restore(id).unwrap();
                assert_eq!(p.scope, "com_redirection");
                assert_eq!(p.registry_view, "64");
                m.apply(&p.token).unwrap();
                assert_eq!(read_value(&f.leaf(i), "").unwrap(), Some(f.original(i)));
                assert_eq!(
                    std::fs::read(dir.path().join("backups").join(format!("{id}.json"))).unwrap(),
                    bytes
                );
                assert_eq!(
                    f.parent(i).get_value::<String, _>("").unwrap(),
                    "Owned class description"
                );
            }
        }
    }
    #[test]
    fn redirection_repair_and_restore_refuse_targets_counterparts_activation_changes_missing_keys_and_corrupt_backups(
    ) {
        for restore in [false, true] {
            for scenario in 0..11 {
                let f = Fixture::new();
                let dir = tempfile::tempdir().unwrap();
                let backups = dir.path().join("backups");
                let mut m = ChangeManager::new(f.store(), backups.clone(), NoProbe);
                let mut p = m.prepare_quarantine(&f.entry(0)).unwrap();
                let mut id = None;
                if restore {
                    let r = m.apply(&p.token).unwrap();
                    id = Some(r.backup_id.clone());
                    p = m.prepare_restore(&r.backup_id).unwrap();
                }
                match scenario {
                    0 => {
                        f.create(&format!(r"User\CLSID\{}", f.targets[0]));
                    }
                    1 => {
                        f.create(&format!(r"Machine\CLSID\{}", f.targets[0]));
                    }
                    2 => {
                        f.create(&format!(r"Machine\CLSID\{}", f.owners[0]));
                    }
                    3 => {
                        f.create(&format!(r"User32\{}", f.owners[0]));
                    }
                    4 => f.parent(0).set_value("", &"Changed description").unwrap(),
                    5 => {
                        f.parent(0).create_subkey("AutoTreatAs").unwrap();
                    }
                    6 => f.leaf(0).set_value("Extra", &"unknown").unwrap(),
                    7 => f.parent(0).delete_subkey_all("TreatAs").unwrap(),
                    8 => f
                        .leaf(0)
                        .set_value("", &"{33333333-3333-4333-8333-333333333333}")
                        .unwrap(),
                    9 => f
                        .parent(0)
                        .set_value("AppID", &"unknown activation")
                        .unwrap(),
                    10 => {
                        if let Some(id) = id {
                            let path = backups.join(format!("{id}.json"));
                            let mut r: serde_json::Value =
                                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                            r["redirection"]["owner"] = serde_json::json!(f.owners[1]);
                            std::fs::write(path, serde_json::to_vec(&r).unwrap()).unwrap();
                        } else {
                            std::fs::write(&backups, b"not a directory").unwrap();
                        }
                    }
                    _ => unreachable!(),
                }
                assert!(
                    m.apply(&p.token).is_err(),
                    "restore={restore}, scenario={scenario}"
                );
                assert_eq!(read_value(&f.leaf(1), "").unwrap(), Some(f.original(1)));
                if scenario != 7 && scenario != 8 {
                    assert_eq!(
                        read_value(&f.leaf(0), "").unwrap(),
                        if restore { None } else { Some(f.original(0)) }
                    );
                }
            }
        }
    }
    #[test]
    fn redirection_batch_stops_at_conflict_and_denied_review_has_no_backup_or_mutation() {
        let f = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let mut m = ChangeManager::new(f.store(), dir.path().join("backups"), NoProbe);
        let p = m
            .prepare_clean(&[f.entry(0), f.entry(1)], "selected")
            .unwrap();
        f.parent(1).set_value("", &"Changed").unwrap();
        let r = m.apply_clean(&p.token).unwrap();
        assert_eq!(r.completed.len(), 1);
        assert!(r.failed.is_some());
        assert_eq!(read_value(&f.leaf(1), "").unwrap(), Some(f.original(1)));
        let p = m.prepare_restore(&r.completed[0].backup_id).unwrap();
        m.apply(&p.token).unwrap();
        struct ReadOnly(WindowsRegistryStore);
        impl RegistryStore for ReadOnly {
            fn read_redirection(&self, a: &RedirectionBackup) -> Result<RedirectionState, String> {
                self.0.read_redirection(a)
            }
            fn check_redirection_write_access(&self, _: &RedirectionBackup) -> Result<(), String> {
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
        let mut m = ChangeManager::new(ReadOnly(f.store()), backups.clone(), NoProbe);
        assert!(m
            .prepare_quarantine(&f.entry(0))
            .unwrap_err()
            .contains("write access"));
        assert!(!backups.exists());
        assert_eq!(read_value(&f.leaf(0), "").unwrap(), Some(f.original(0)));
    }
}
