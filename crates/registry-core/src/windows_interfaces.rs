use super::{read_value, WindowsRegistryStore};
use crate::{
    changes::{NamedValue, StoredValue},
    interfaces::*,
};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

fn open(
    parent: &RegKey,
    path: &str,
    view: u32,
    tx: Option<&Transaction>,
    write: bool,
    classes_alias: bool,
) -> Result<Option<RegKey>, String> {
    // Interface and TypeLib roots and children are always opened without following links.
    let options = if classes_alias {
        0
    } else {
        REG_OPTION_OPEN_LINK
    };
    let access = KEY_READ | view | if write { KEY_SET_VALUE } else { 0 };
    let result = if let Some(tx) = tx {
        parent.open_subkey_transacted_with_options_flags(path, tx, options, access)
    } else {
        parent.open_subkey_with_options_flags(path, options, access)
    };
    match result {
        Ok(key) => {
            if read_value(&key, "SymbolicLinkValue")?.is_some_and(|v| v.kind == 6) {
                return Err(
                    "Untrusted interface or TypeLib registry links remain outside recovery scope."
                        .into(),
                );
            }
            Ok(Some(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "Interface or TypeLib evidence is inaccessible (Windows error {}).",
            error.raw_os_error().unwrap_or(0)
        )),
    }
}
fn required(
    parent: &RegKey,
    path: &str,
    tx: Option<&Transaction>,
    write: bool,
    classes_alias: bool,
) -> Result<RegKey, String> {
    open(parent, path, KEY_WOW64_64KEY, tx, write, classes_alias)?
        .ok_or("An existing Interface TypeLib key is missing; it will not be recreated.".into())
}
pub(crate) fn open_interface_child(
    parent: &RegKey,
    path: &str,
    view: u32,
) -> Result<Option<RegKey>, String> {
    open(parent, path, view, None, false, false)
}
fn values(key: &RegKey) -> Result<Vec<NamedValue>, String> {
    let mut values = vec![];
    let mut bytes = 0;
    for item in key.enum_values() {
        let (name, value) =
            item.map_err(|_| "Interface TypeLib metadata could not be read completely.")?;
        bytes += value.bytes.len();
        if values.len() >= 8 || bytes > 16384 {
            return Err("Interface TypeLib metadata exceeds backup bounds.".into());
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
    Ok(values)
}
impl WindowsRegistryStore {
    fn interface_machine_hive(&self) -> winreg::HKEY {
        #[cfg(test)]
        if self.interface_test_machine_user {
            return HKEY_CURRENT_USER;
        }
        HKEY_LOCAL_MACHINE
    }
    fn interface_target_in(&self, clsid: &str, tx: Option<&Transaction>) -> Result<bool, String> {
        crate::com::validate_clsid(clsid)?;
        for (hive, classes) in [
            (HKEY_CURRENT_USER, &self.interface_libraries_path),
            (
                self.interface_machine_hive(),
                &self.machine_interface_libraries_path,
            ),
        ] {
            // TypeLib is shared on supported Windows. Never follow its 32-bit compatibility link.
            if let Some(root) = open(
                &RegKey::predef(hive),
                classes,
                KEY_WOW64_64KEY,
                tx,
                false,
                false,
            )? {
                if open(&root, clsid, KEY_WOW64_64KEY, tx, false, false)?.is_some() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    pub(crate) fn interface_target_exists(&self, clsid: &str) -> Result<bool, String> {
        self.interface_target_in(clsid, None)
    }
    fn verify_interface_orphan(
        &self,
        app: &InterfaceBackup,
        tx: Option<&Transaction>,
    ) -> Result<(), String> {
        app.validate()?;
        if self.interface_target_in(&app.library_id, tx)? {
            return Err("The referenced TypeLib exists in a user or machine hive. Repair or restore is blocked.".into());
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
                    return Err("A machine interface counterpart exists. Registration fallback changes remain outside recovery scope.".into());
                }
            }
        }
        Ok(())
    }
    fn interface_leaf(
        &self,
        app: &InterfaceBackup,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<RegKey, String> {
        self.verify_interface_orphan(app, tx)?;
        let classes = required(
            &RegKey::predef(HKEY_CURRENT_USER),
            &self.interfaces_path,
            tx,
            false,
            false,
        )?;
        let interface = required(&classes, &app.iid, tx, false, false)?;
        required(&interface, "TypeLib", tx, write, false)
    }
    fn interface_state_in(
        &self,
        app: &InterfaceBackup,
        tx: Option<&Transaction>,
    ) -> Result<InterfaceState, String> {
        self.verify_interface_orphan(app, tx)?;
        let classes = required(
            &RegKey::predef(HKEY_CURRENT_USER),
            &self.interfaces_path,
            tx,
            false,
            false,
        )?;
        let interface = required(&classes, &app.iid, tx, false, false)?;
        let children: Vec<String> = interface
            .enum_keys()
            .take(4)
            .collect::<Result<_, _>>()
            .map_err(|_| "Interface structure could not be read.")?;
        if !children.iter().any(|v| v.eq_ignore_ascii_case("TypeLib"))
            || children.iter().any(|v| {
                !["TypeLib", "ProxyStubClsid32"]
                    .iter()
                    .any(|name| v.eq_ignore_ascii_case(name))
            })
        {
            return Err("Complex interface registration children remain read-only.".into());
        }
        let leaf = required(&interface, "TypeLib", tx, false, false)?;
        if leaf.enum_keys().next().is_some() {
            return Err("Nested or unreadable TypeLib references remain read-only.".into());
        }
        let proxy_values = if let Some(proxy) = open(
            &interface,
            "ProxyStubClsid32",
            KEY_WOW64_64KEY,
            tx,
            false,
            false,
        )? {
            if proxy.enum_keys().next().is_some() {
                return Err("Nested proxy metadata remains read-only.".into());
            }
            Some(values(&proxy)?)
        } else {
            None
        };
        let guard = InterfaceGuard {
            values: values(&interface)?,
            type_lib_values: values(&leaf)?
                .into_iter()
                .filter(|v| !v.name.is_empty())
                .collect(),
            proxy_values,
        };
        guard.validate()?;
        let value = read_value(&leaf, "")?;
        if let Some(value) = &value {
            mapping_library(value)?;
        }
        Ok(InterfaceState { value, guard })
    }
    pub(crate) fn interface_state(&self, app: &InterfaceBackup) -> Result<InterfaceState, String> {
        self.interface_state_in(app, None)
    }
    pub(crate) fn interface_write_access(&self, app: &InterfaceBackup) -> Result<(), String> {
        self.interface_leaf(app, None, true).map(|_| ())
    }
    pub(crate) fn exchange_interface(
        &self,
        app: &InterfaceBackup,
        expected: &InterfaceState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        app.validate()?;
        if expected.value.is_some() == replacement.is_some()
            || expected.guard != app.guard
            || mapping_library(
                expected
                    .value
                    .as_ref()
                    .or(replacement)
                    .ok_or("Missing Interface TypeLib mapping evidence.")?,
            )? != app.library_id
        {
            return Err(
                "Only exact orphaned Interface TypeLib mapping removal or restoration is supported.".into(),
            );
        }
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.interface_state_in(app, Some(&tx))? != *expected {
            return Err("Interface TypeLib metadata changed. Nothing was overwritten.".into());
        }
        let leaf = self.interface_leaf(app, Some(&tx), true)?;
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
        .map_err(|e| format!("Interface TypeLib mapping update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Interface TypeLib transaction did not commit: {e}"))
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
            panic!("Interface TypeLib recovery must not probe files")
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
            for scope in ["User", "Machine", "UserLibraries", "MachineLibraries"] {
                RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(format!(r"{}\{scope}", fixture.base))
                    .unwrap();
            }
            for index in 0..2 {
                let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(format!(r"{}\User\{}", fixture.base, fixture.name(index)))
                    .unwrap();
                key.set_value("", &"Owned Interface TypeLib description")
                    .unwrap();
                let original = fixture.original(index);
                key.create_subkey("TypeLib")
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
                key.open_subkey_with_flags("TypeLib", KEY_ALL_ACCESS)
                    .unwrap()
                    .set_value("Version", &"1.0")
                    .unwrap();
                key.create_subkey("ProxyStubClsid32")
                    .unwrap()
                    .0
                    .set_value("", &"{33333333-3333-4333-8333-333333333333}")
                    .unwrap();
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
                ..Default::default()
            }
        }
        fn selector(&self, index: usize) -> InterfaceBackup {
            InterfaceBackup {
                iid: self.name(index),
                library_id: self.ids[index].clone(),
                guard: InterfaceGuard {
                    values: vec![],
                    type_lib_values: vec![],
                    proxy_values: None,
                },
            }
        }
        fn entry(&self, index: usize) -> RegistryEntry {
            let mut entry:RegistryEntry=serde_json::from_value(serde_json::json!({"id":self.name(index),"name":self.name(index),"category":"interfaces","hive":"HKCU","view":"64","keyPath":format!(r"{INTERFACES_KEY}\{}\TypeLib",self.name(index)),"valueName":"","valueType":if index==0{"REG_EXPAND_SZ"}else{"REG_SZ"},"rawValue":self.ids[index],"publisher":null,"version":null,"assessment":{"status":"review","code":"interface_library_missing","explanation":"Owned orphan","target":self.ids[index]},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"interfaceRepairable":true})).unwrap();
            entry.interface_state =
                Some(self.store().read_interface(&self.selector(index)).unwrap());
            entry
        }
        fn target(&self, machine: bool) {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(
                    r"{}\{}\{}",
                    self.base,
                    if machine {
                        "MachineLibraries"
                    } else {
                        "UserLibraries"
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
                read_value(&self.key(1, "TypeLib"), "").unwrap(),
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
    fn interface_quick_and_selected_clean_keep_separate_backups_and_restore_exact_types_bytes_and_metadata(
    ) {
        for mode in ["quick", "selected"] {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let entries = [fixture.entry(0), fixture.entry(1)];
            let initial = [
                entries[0].interface_state.clone().unwrap(),
                entries[1].interface_state.clone().unwrap(),
            ];
            assert!(entries.iter().all(crate::changes::is_repair_candidate));
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), NoFileProbe);
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            assert_eq!(plan.items.len(), 2);
            assert!(plan
                .items
                .iter()
                .all(|p| p.preserved_values == 3 && p.scope == "interface"));
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
                    .read_interface(&fixture.selector(index))
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
                .all(|b| b.state == "restore_available" && b.scope == "interface"));
            for (index, result) in result.completed.iter().enumerate() {
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(backups.join(format!("{}.json", result.backup_id))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["schemaVersion"], 13);
                assert_eq!(record["interface"]["libraryId"], fixture.ids[index]);
                assert_eq!(
                    record["original"],
                    serde_json::to_value(fixture.original(index)).unwrap()
                );
                let restore = manager.prepare_restore(&result.backup_id).unwrap();
                manager.apply(&restore.token).unwrap();
                assert_eq!(
                    fixture
                        .store()
                        .read_interface(&fixture.selector(index))
                        .unwrap(),
                    initial[index]
                );
            }
        }
    }
    #[test]
    fn interface_repair_blocks_new_targets_counterparts_metadata_children_missing_keys_and_backup_failure(
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
                    .key(0, "TypeLib")
                    .set_value("Named", &"preserve")
                    .unwrap(),
                6 => fixture.key(0, "").delete_subkey("TypeLib").unwrap(),
                7 => std::fs::write(&backups, b"not a directory").unwrap(),
                8 => fixture
                    .key(0, "TypeLib")
                    .set_value("", &"{22222222-2222-4222-8222-222222222222}")
                    .unwrap(),
                9 => fixture
                    .key(0, "TypeLib")
                    .set_value("Version", &"2.0")
                    .unwrap(),
                10 => fixture
                    .key(0, "ProxyStubClsid32")
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
                    read_value(&fixture.key(0, "TypeLib"), "").unwrap(),
                    Some(fixture.original(0))
                );
            } else if scenario == 6 {
                assert!(fixture.key(0, "").open_subkey("TypeLib").is_err());
            } else {
                assert_eq!(
                    fixture
                        .key(0, "TypeLib")
                        .get_value::<String, _>("")
                        .unwrap(),
                    "{22222222-2222-4222-8222-222222222222}"
                );
            }
        }
    }
    #[test]
    fn interface_restore_blocks_new_values_classes_metadata_missing_keys_and_tampered_backup_scope()
    {
        for scenario in 0..10 {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), NoFileProbe);
            let plan = manager.prepare_quarantine(&fixture.entry(0)).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            let restore = manager.prepare_restore(&result.backup_id).unwrap();
            match scenario {
                0 => fixture
                    .key(0, "TypeLib")
                    .set_value("", &"{22222222-2222-4222-8222-222222222222}")
                    .unwrap(),
                1 => fixture.target(false),
                2 => fixture.target(true),
                3 => fixture.counterpart(),
                4 => fixture
                    .key(0, "")
                    .set_value("", &"changed description")
                    .unwrap(),
                5 => fixture.key(0, "").delete_subkey("TypeLib").unwrap(),
                6..=9 => {
                    let path = backups.join(format!("{}.json", result.backup_id));
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    match scenario {
                        6 => record["interface"]["iid"] = serde_json::json!(r"Bad\Path"),
                        7 => {
                            record["interface"]["libraryId"] =
                                serde_json::json!("{33333333-3333-4333-8333-333333333333}")
                        }
                        8 => {
                            record["interface"]["guard"]["values"][0]["name"] =
                                serde_json::json!("Unknown")
                        }
                        9 => record["original"]["kind"] = serde_json::json!(1),
                        _ => unreachable!(),
                    }
                    std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
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
                        .key(0, "TypeLib")
                        .get_value::<String, _>("")
                        .unwrap(),
                    "{22222222-2222-4222-8222-222222222222}"
                );
            } else if scenario != 5 {
                assert!(read_value(&fixture.key(0, "TypeLib"), "")
                    .unwrap()
                    .is_none());
            } else {
                assert!(fixture.key(0, "").open_subkey("TypeLib").is_err());
            }
        }
    }
    #[test]
    fn interface_batch_stops_at_conflict_and_completed_mapping_remains_independently_restorable() {
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
            read_value(&fixture.key(0, "TypeLib"), "").unwrap(),
            Some(fixture.original(0))
        );
    }
    #[test]
    fn interface_review_checks_existing_write_access_before_creating_a_backup() {
        struct ReadOnly(WindowsRegistryStore);
        impl RegistryStore for ReadOnly {
            fn read_interface(&self, app: &InterfaceBackup) -> Result<InterfaceState, String> {
                self.0.read_interface(app)
            }
            fn check_interface_write_access(&self, _: &InterfaceBackup) -> Result<(), String> {
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
            read_value(&fixture.key(0, "TypeLib"), "").unwrap(),
            Some(fixture.original(0))
        );
        fixture.assert_other();
    }
}
