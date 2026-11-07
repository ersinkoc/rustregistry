use super::{
    interfaces::{open, required, values},
    read_value, WindowsRegistryStore,
};
use crate::changes::StoredValue;
use crate::com_proxies::*;
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

impl WindowsRegistryStore {
    fn verify_proxy_orphan(
        &self,
        app: &ProxyBackup,
        tx: Option<&Transaction>,
    ) -> Result<(), String> {
        app.validate()?;
        if self.prog_id_target_in(&app.clsid, tx)? {
            return Err("The proxy CLSID exists in a user or machine 32/64-bit view. Repair or restore is blocked.".into());
        }
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            if let Some(root) = open(
                &RegKey::predef(self.interface_machine_hive()),
                &self.machine_interfaces_path,
                view,
                tx,
                false,
                false,
            )? {
                if open(&root, &app.iid, view, tx, false, false)?.is_some() {
                    return Err("A machine interface counterpart exists. Proxy fallback changes remain outside recovery scope.".into());
                }
            }
        }
        Ok(())
    }
    fn proxy_parent(&self, app: &ProxyBackup, tx: Option<&Transaction>) -> Result<RegKey, String> {
        self.verify_proxy_orphan(app, tx)?;
        let root = required(
            &RegKey::predef(HKEY_CURRENT_USER),
            &self.interfaces_path,
            tx,
            false,
            false,
        )?;
        required(&root, &app.iid, tx, false, false)
    }
    fn proxy_leaf(
        &self,
        app: &ProxyBackup,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<RegKey, String> {
        required(
            &self.proxy_parent(app, tx)?,
            "ProxyStubClsid32",
            tx,
            write,
            false,
        )
    }
    fn proxy_state_in(
        &self,
        app: &ProxyBackup,
        tx: Option<&Transaction>,
    ) -> Result<ProxyState, String> {
        let parent = self.proxy_parent(app, tx)?;
        let children: Vec<String> = parent
            .enum_keys()
            .take(4)
            .collect::<Result<_, _>>()
            .map_err(|_| "Proxy interface structure could not be read.")?;
        if !children
            .iter()
            .any(|v| v.eq_ignore_ascii_case("ProxyStubClsid32"))
            || children.iter().any(|v| {
                !["ProxyStubClsid32", "TypeLib"]
                    .iter()
                    .any(|name| v.eq_ignore_ascii_case(name))
            })
        {
            return Err("Complex interface children remain outside proxy recovery scope.".into());
        }
        let leaf = required(&parent, "ProxyStubClsid32", tx, false, false)?;
        if leaf.enum_keys().next().is_some() || values(&leaf)?.iter().any(|v| !v.name.is_empty()) {
            return Err("Nested or named proxy metadata remains read-only.".into());
        }
        let type_lib_values = if let Some(library) =
            open(&parent, "TypeLib", KEY_WOW64_64KEY, tx, false, false)?
        {
            if library.enum_keys().next().is_some() {
                return Err("Nested TypeLib metadata remains outside proxy recovery scope.".into());
            }
            Some(values(&library)?)
        } else {
            None
        };
        let guard = ProxyGuard {
            values: values(&parent)?,
            type_lib_values,
        };
        guard.validate()?;
        let value = read_value(&leaf, "")?;
        if let Some(value) = &value {
            mapping_clsid(value)?;
        }
        Ok(ProxyState { value, guard })
    }
    pub(crate) fn proxy_state(&self, app: &ProxyBackup) -> Result<ProxyState, String> {
        self.proxy_state_in(app, None)
    }
    pub(crate) fn proxy_write_access(&self, app: &ProxyBackup) -> Result<(), String> {
        self.proxy_leaf(app, None, true).map(|_| ())
    }
    pub(crate) fn exchange_proxy(
        &self,
        app: &ProxyBackup,
        expected: &ProxyState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        app.validate()?;
        if expected.value.is_some() == replacement.is_some()
            || expected.guard != app.guard
            || mapping_clsid(
                expected
                    .value
                    .as_ref()
                    .or(replacement)
                    .ok_or("Missing proxy mapping evidence.")?,
            )? != app.clsid
        {
            return Err("Only exact orphaned proxy removal or restoration is supported.".into());
        }
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.proxy_state_in(app, Some(&tx))? != *expected {
            return Err("Proxy or TypeLib metadata changed. Nothing was overwritten.".into());
        }
        let leaf = self.proxy_leaf(app, Some(&tx), true)?;
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
        .map_err(|e| format!("Proxy reference update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Proxy transaction did not commit: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{ChangeManager, RegistryStore},
        PathProbe, ProbeResult, RegistryEntry, TargetKind,
    };
    struct NoFileProbe;
    impl PathProbe for NoFileProbe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            panic!("COM proxy recovery must not probe files")
        }
    }
    struct Fixture {
        base: String,
        ids: [String; 2],
    }
    impl Fixture {
        fn new() -> Self {
            let fixture = Self {
                base: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
                ids: [
                    format!("{{{}}}", uuid::Uuid::new_v4()),
                    format!("{{{}}}", uuid::Uuid::new_v4()),
                ],
            };
            for scope in [
                "User",
                "Machine",
                "UserClasses\\CLSID",
                "MachineClasses\\CLSID",
            ] {
                RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(format!(r"{}\{scope}", fixture.base))
                    .unwrap();
            }
            for index in 0..2 {
                let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(format!(r"{}\User\{}", fixture.base, fixture.name(index)))
                    .unwrap();
                key.set_value("", &"Owned COM proxy description").unwrap();
                let original = fixture.original(index);
                key.create_subkey("ProxyStubClsid32")
                    .unwrap()
                    .0
                    .set_raw_value(
                        "",
                        &RegValue {
                            vtype: if original.kind == 1 {
                                REG_SZ
                            } else {
                                REG_EXPAND_SZ
                            },
                            bytes: Cow::Owned(original.bytes),
                        },
                    )
                    .unwrap();
                let library = key.create_subkey("TypeLib").unwrap().0;
                library
                    .set_value("", &"{33333333-3333-4333-8333-333333333333}")
                    .unwrap();
                library.set_value("Version", &"1.0").unwrap();
            }
            fixture
        }
        fn name(&self, index: usize) -> String {
            format!(
                "{{{}}}",
                if index == 0 {
                    "11111111-1111-4111-8111-111111111111"
                } else {
                    "22222222-2222-4222-8222-222222222222"
                }
            )
        }
        fn original(&self, index: usize) -> StoredValue {
            StoredValue {
                kind: if index == 0 { 2 } else { 1 },
                bytes: self.ids[index]
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }
        }
        fn key(&self, index: usize, path: &str) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(
                    format!(
                        r"{}\User\{}{}",
                        self.base,
                        self.name(index),
                        if path.is_empty() {
                            String::new()
                        } else {
                            format!(r"\{path}")
                        }
                    ),
                    KEY_ALL_ACCESS,
                )
                .unwrap()
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                interfaces_path: format!(r"{}\User", self.base),
                machine_interfaces_path: format!(r"{}\Machine", self.base),
                interface_libraries_path: format!(r"{}\UserLibraries", self.base),
                machine_interface_libraries_path: format!(r"{}\MachineLibraries", self.base),
                interface_test_machine_user: true,
                prog_ids_path: format!(r"{}\UserClasses", self.base),
                machine_prog_ids_path: format!(r"{}\MachineClasses", self.base),
                prog_id_test_machine_user: true,
                ..Default::default()
            }
        }
        fn selector(&self, index: usize) -> ProxyBackup {
            ProxyBackup {
                iid: self.name(index),
                clsid: self.ids[index].clone(),
                guard: ProxyGuard {
                    values: vec![],
                    type_lib_values: None,
                },
            }
        }
        fn entry(&self, index: usize) -> RegistryEntry {
            let mut entry:RegistryEntry=serde_json::from_value(serde_json::json!({"id":self.name(index),"name":self.name(index),"category":"com_proxies","hive":"HKCU","view":"64","keyPath":format!(r"{INTERFACES_KEY}\{}\ProxyStubClsid32",self.name(index)),"valueName":"","valueType":if index==0{"REG_EXPAND_SZ"}else{"REG_SZ"},"rawValue":self.ids[index],"publisher":null,"version":null,"assessment":{"status":"review","code":"proxy_clsid_missing","explanation":"Owned orphan","target":self.ids[index]},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"proxyRepairable":true})).unwrap();
            entry.proxy_state = Some(self.store().read_proxy(&self.selector(index)).unwrap());
            entry
        }
        fn target(&self, machine: bool) {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(
                    r"{}\{}\{}",
                    self.base,
                    if machine {
                        "MachineClasses\\CLSID"
                    } else {
                        "UserClasses\\CLSID"
                    },
                    self.ids[0]
                ))
                .unwrap();
        }
        fn counterpart(&self) {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\Machine\{}", self.base, self.name(0)))
                .unwrap();
        }
        fn assert_other(&self) {
            assert_eq!(
                read_value(&self.key(1, "ProxyStubClsid32"), "").unwrap(),
                Some(self.original(1))
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.base);
        }
    }
    #[test]
    fn restores_unchanged_v0114_proxy_backup_without_migration() {
        let fixture = Fixture::new();
        let directory = tempfile::tempdir().unwrap();
        let id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let leaf = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"{}\User\{{{id}}}\ProxyStubClsid32", fixture.base))
            .unwrap()
            .0;
        let bytes = include_bytes!("../tests/fixtures/proxy-backup-v14.json");
        let file = directory.path().join(format!("{id}.json"));
        std::fs::write(&file, bytes).unwrap();
        let mut manager =
            ChangeManager::new(fixture.store(), directory.path().to_path_buf(), NoFileProbe);
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "com_proxy");
        manager.apply(&plan.token).unwrap();
        let record: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            read_value(&leaf, "").unwrap(),
            Some(serde_json::from_value(record["original"].clone()).unwrap())
        );
        assert_eq!(std::fs::read(file).unwrap(), bytes);
        fixture.assert_other();
    }
    #[test]
    fn one_interface_change_per_batch_preserves_independent_restore_in_both_orders() {
        use crate::interfaces::{InterfaceBackup, InterfaceGuard};
        for mode in ["quick", "selected"] {
            for proxy_first in [true, false] {
                let fixture = Fixture::new();
                let mut library = fixture.entry(0);
                library.id.push_str("-library");
                library.category = crate::Category::Interfaces;
                library.key_path = format!(r"{INTERFACES_KEY}\{}\TypeLib", fixture.name(0));
                library.value_type = "REG_SZ".into();
                library.raw_value = "{33333333-3333-4333-8333-333333333333}".into();
                library.assessment.code = "interface_library_missing".into();
                library.proxy_repairable = false;
                library.proxy_state = None;
                library.interface_repairable = true;
                let selector = InterfaceBackup {
                    iid: fixture.name(0),
                    library_id: library.raw_value.clone(),
                    guard: InterfaceGuard {
                        values: vec![],
                        type_lib_values: vec![],
                        proxy_values: None,
                    },
                };
                library.interface_state = Some(fixture.store().read_interface(&selector).unwrap());
                let proxy = fixture.entry(0);
                let entries = if proxy_first {
                    [proxy, library]
                } else {
                    [library, proxy]
                };
                let directory = tempfile::tempdir().unwrap();
                let mut manager = ChangeManager::new(
                    fixture.store(),
                    directory.path().join("backups"),
                    NoFileProbe,
                );
                let plan = manager.prepare_clean(&entries, mode).unwrap();
                assert_eq!(plan.items.len(), 1);
                assert_eq!(plan.skipped.len(), 1);
                let result = manager.apply_clean(&plan.token).unwrap();
                assert_eq!(result.completed.len(), 1);
                assert!(result.failed.is_none());
                let restore = manager
                    .prepare_restore(&result.completed[0].backup_id)
                    .unwrap();
                manager.apply(&restore.token).unwrap();
                assert_eq!(
                    read_value(&fixture.key(0, "ProxyStubClsid32"), "").unwrap(),
                    Some(fixture.original(0))
                );
                assert_eq!(
                    fixture
                        .key(0, "TypeLib")
                        .get_value::<String, _>("")
                        .unwrap(),
                    "{33333333-3333-4333-8333-333333333333}"
                );
                fixture.assert_other();
            }
        }
    }
    #[test]
    fn proxy_quick_and_selected_clean_keep_separate_backups_and_restore_exact_types_bytes_and_metadata(
    ) {
        for mode in ["quick", "selected"] {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let entries = [fixture.entry(0), fixture.entry(1)];
            let initial = [
                entries[0].proxy_state.clone().unwrap(),
                entries[1].proxy_state.clone().unwrap(),
            ];
            assert!(entries.iter().all(crate::changes::is_repair_candidate));
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), NoFileProbe);
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            assert_eq!(plan.items.len(), 2);
            assert!(plan
                .items
                .iter()
                .all(|p| p.preserved_values == 3 && p.scope == "com_proxy"));
            assert!(!backups.exists());
            manager.cancel();
            assert!(manager.apply_clean(&plan.token).is_err());
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            let result = manager.apply_clean(&plan.token).unwrap();
            assert_eq!(result.completed.len(), 2);
            assert!(result.failed.is_none());
            for (index, original) in initial.iter().enumerate() {
                let state = fixture
                    .store()
                    .read_proxy(&fixture.selector(index))
                    .unwrap();
                assert!(state.value.is_none());
                assert_eq!(state.guard, original.guard);
            }
            drop(manager);
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), NoFileProbe);
            assert!(manager
                .inventory()
                .unwrap()
                .backups
                .iter()
                .all(|b| b.state == "restore_available" && b.scope == "com_proxy"));
            for (index, result) in result.completed.iter().enumerate() {
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(backups.join(format!("{}.json", result.backup_id))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["schemaVersion"], 14);
                assert_eq!(record["proxy"]["clsid"], fixture.ids[index]);
                assert_eq!(
                    record["original"],
                    serde_json::to_value(fixture.original(index)).unwrap()
                );
                let restore = manager.prepare_restore(&result.backup_id).unwrap();
                manager.apply(&restore.token).unwrap();
                assert_eq!(
                    fixture
                        .store()
                        .read_proxy(&fixture.selector(index))
                        .unwrap(),
                    initial[index]
                );
            }
        }
    }
    #[test]
    fn proxy_repair_blocks_new_targets_counterparts_metadata_children_missing_keys_and_backup_failure(
    ) {
        for scenario in 0..12 {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), NoFileProbe);
            let plan = manager.prepare_quarantine(&fixture.entry(0)).unwrap();
            match scenario {
                0 => fixture.target(false),
                1 => fixture.target(true),
                2 => fixture.counterpart(),
                3 => fixture
                    .key(0, "")
                    .set_value("", &"changed description")
                    .unwrap(),
                4 => {
                    fixture.key(0, "").create_subkey("CurVer").unwrap();
                }
                5 => fixture
                    .key(0, "ProxyStubClsid32")
                    .set_value("Named", &"preserve")
                    .unwrap(),
                6 => fixture
                    .key(0, "")
                    .delete_subkey("ProxyStubClsid32")
                    .unwrap(),
                7 => std::fs::write(&backups, b"not a directory").unwrap(),
                8 => fixture
                    .key(0, "ProxyStubClsid32")
                    .set_value("", &"{22222222-2222-4222-8222-222222222222}")
                    .unwrap(),
                9 => fixture
                    .key(0, "TypeLib")
                    .set_value("Version", &"2.0")
                    .unwrap(),
                10 => fixture
                    .key(0, "TypeLib")
                    .set_value("", &"{44444444-4444-4444-8444-444444444444}")
                    .unwrap(),
                11 => {
                    fixture.key(0, "").create_subkey("BaseInterface").unwrap();
                }
                _ => unreachable!(),
            }
            assert!(manager.apply(&plan.token).is_err(), "scenario {scenario}");
            fixture.assert_other();
            if scenario != 6 && scenario != 8 {
                assert_eq!(
                    read_value(&fixture.key(0, "ProxyStubClsid32"), "").unwrap(),
                    Some(fixture.original(0))
                );
            } else if scenario == 6 {
                assert!(fixture.key(0, "").open_subkey("ProxyStubClsid32").is_err());
            } else {
                assert_eq!(
                    fixture
                        .key(0, "ProxyStubClsid32")
                        .get_value::<String, _>("")
                        .unwrap(),
                    "{22222222-2222-4222-8222-222222222222}"
                );
            }
        }
    }
    #[test]
    fn proxy_restore_blocks_new_values_classes_metadata_missing_keys_and_tampered_backup_scope() {
        for scenario in 0..14 {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), NoFileProbe);
            let plan = manager.prepare_quarantine(&fixture.entry(0)).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            let restore = manager.prepare_restore(&result.backup_id).unwrap();
            match scenario {
                0 => fixture
                    .key(0, "ProxyStubClsid32")
                    .set_value("", &"{22222222-2222-4222-8222-222222222222}")
                    .unwrap(),
                1 => fixture.target(false),
                2 => fixture.target(true),
                3 => fixture.counterpart(),
                4 => fixture
                    .key(0, "")
                    .set_value("", &"changed description")
                    .unwrap(),
                5 => fixture
                    .key(0, "")
                    .delete_subkey("ProxyStubClsid32")
                    .unwrap(),
                6..=9 => {
                    let path = backups.join(format!("{}.json", result.backup_id));
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    match scenario {
                        6 => record["proxy"]["iid"] = serde_json::json!(r"Bad\Path"),
                        7 => {
                            record["proxy"]["clsid"] =
                                serde_json::json!("{33333333-3333-4333-8333-333333333333}")
                        }
                        8 => {
                            record["proxy"]["guard"]["values"][0]["name"] =
                                serde_json::json!("Unknown")
                        }
                        9 => record["original"]["kind"] = serde_json::json!(1),
                        _ => unreachable!(),
                    }
                    std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                10 => fixture
                    .key(0, "TypeLib")
                    .set_value("Version", &"2.0")
                    .unwrap(),
                11 => fixture
                    .key(0, "TypeLib")
                    .set_value("Unknown", &"preserve")
                    .unwrap(),
                12 => {
                    fixture
                        .key(0, "ProxyStubClsid32")
                        .create_subkey("Nested")
                        .unwrap();
                }
                13 => fixture.key(0, "").delete_subkey("TypeLib").unwrap(),
                _ => unreachable!(),
            }
            assert!(
                manager.apply(&restore.token).is_err(),
                "scenario {scenario}"
            );
            fixture.assert_other();
            if scenario == 0 {
                assert_eq!(
                    fixture
                        .key(0, "ProxyStubClsid32")
                        .get_value::<String, _>("")
                        .unwrap(),
                    "{22222222-2222-4222-8222-222222222222}"
                );
            } else if scenario != 5 {
                assert!(read_value(&fixture.key(0, "ProxyStubClsid32"), "")
                    .unwrap()
                    .is_none());
            } else {
                assert!(fixture.key(0, "").open_subkey("ProxyStubClsid32").is_err());
            }
        }
    }
    #[test]
    fn proxy_batch_stops_at_conflict_and_completed_mapping_remains_independently_restorable() {
        let fixture = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let mut manager =
            ChangeManager::new(fixture.store(), dir.path().join("backups"), NoFileProbe);
        let plan = manager
            .prepare_clean(&[fixture.entry(0), fixture.entry(1)], "quick")
            .unwrap();
        fixture
            .key(1, "")
            .set_value("", &"changed description")
            .unwrap();
        let result = manager.apply_clean(&plan.token).unwrap();
        assert_eq!(result.completed.len(), 1);
        assert!(result.failed.is_some());
        assert_eq!(result.not_attempted, 0);
        fixture.assert_other();
        let restore = manager
            .prepare_restore(&result.completed[0].backup_id)
            .unwrap();
        manager.apply(&restore.token).unwrap();
        assert_eq!(
            read_value(&fixture.key(0, "ProxyStubClsid32"), "").unwrap(),
            Some(fixture.original(0))
        );
    }
    #[test]
    fn proxy_review_checks_existing_write_access_before_creating_a_backup() {
        struct ReadOnly(WindowsRegistryStore);
        impl RegistryStore for ReadOnly {
            fn read_proxy(&self, app: &ProxyBackup) -> Result<ProxyState, String> {
                self.0.read_proxy(app)
            }
            fn check_proxy_write_access(&self, _: &ProxyBackup) -> Result<(), String> {
                Err("Existing registry write access is required.".into())
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
        let fixture = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        let mut manager =
            ChangeManager::new(ReadOnly(fixture.store()), backups.clone(), NoFileProbe);
        assert!(manager
            .prepare_quarantine(&fixture.entry(0))
            .unwrap_err()
            .contains("write access"));
        assert!(!backups.exists());
        assert_eq!(
            read_value(&fixture.key(0, "ProxyStubClsid32"), "").unwrap(),
            Some(fixture.original(0))
        );
        fixture.assert_other();
    }
}
