use super::{read_value, WindowsRegistryStore};
use crate::{
    changes::{NamedValue, StoredValue},
    prog_ids::*,
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
    // Only the fixed Classes root uses its Windows-owned HKCU alias. Every
    // caller-supplied ProgID and CLSID component is opened without following links.
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
                    "Untrusted ProgID or CLSID registry links remain outside recovery scope."
                        .into(),
                );
            }
            Ok(Some(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "ProgID or CLSID evidence is inaccessible (Windows error {}).",
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
        .ok_or("An existing ProgID key is missing; it will not be recreated.".into())
}
pub(crate) fn open_prog_id_child(parent: &RegKey, path: &str) -> Result<Option<RegKey>, String> {
    open(parent, path, KEY_WOW64_64KEY, None, false, false)
}
fn values(key: &RegKey) -> Result<Vec<NamedValue>, String> {
    let mut values = vec![];
    let mut bytes = 0;
    for item in key.enum_values() {
        let (name, value) = item.map_err(|_| "ProgID metadata could not be read completely.")?;
        bytes += value.bytes.len();
        if values.len() >= 8 || bytes > 16384 {
            return Err("ProgID metadata exceeds backup bounds.".into());
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
    fn prog_id_machine_hive(&self) -> winreg::HKEY {
        #[cfg(test)]
        if self.prog_id_test_machine_user {
            return HKEY_CURRENT_USER;
        }
        HKEY_LOCAL_MACHINE
    }
    pub(super) fn prog_id_target_in(
        &self,
        clsid: &str,
        tx: Option<&Transaction>,
    ) -> Result<bool, String> {
        crate::com::validate_clsid(clsid)?;
        for (hive, classes) in [
            (HKEY_CURRENT_USER, &self.prog_ids_path),
            (self.prog_id_machine_hive(), &self.machine_prog_ids_path),
        ] {
            for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
                // Open the full CLSID path in the intended view so shared
                // Classes roots do not accidentally collapse redirected targets.
                if let Some(root) = open(
                    &RegKey::predef(hive),
                    &format!(r"{classes}\CLSID"),
                    view,
                    tx,
                    false,
                    false,
                )? {
                    if open(&root, clsid, view, tx, false, false)?.is_some() {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
    pub(crate) fn prog_id_target_exists(&self, clsid: &str) -> Result<bool, String> {
        self.prog_id_target_in(clsid, None)
    }
    fn verify_prog_id_orphan(
        &self,
        app: &ProgIdBackup,
        tx: Option<&Transaction>,
    ) -> Result<(), String> {
        app.validate()?;
        if self.prog_id_target_in(&app.clsid, tx)? {
            return Err("The referenced CLSID exists in a user or machine 32/64-bit view. Repair or restore is blocked.".into());
        }
        let machine = required(
            &RegKey::predef(self.prog_id_machine_hive()),
            &self.machine_prog_ids_path,
            tx,
            false,
            true,
        )?;
        if open(&machine, &app.prog_id, KEY_WOW64_64KEY, tx, false, false)?.is_some() {
            return Err("A same-named machine ProgID exists. Changing registration fallback is outside recovery scope.".into());
        }
        Ok(())
    }
    fn prog_id_leaf(
        &self,
        app: &ProgIdBackup,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<RegKey, String> {
        self.verify_prog_id_orphan(app, tx)?;
        let classes = required(
            &RegKey::predef(HKEY_CURRENT_USER),
            &self.prog_ids_path,
            tx,
            false,
            true,
        )?;
        let prog_id = required(&classes, &app.prog_id, tx, false, false)?;
        required(&prog_id, "CLSID", tx, write, false)
    }
    fn prog_id_state_in(
        &self,
        app: &ProgIdBackup,
        tx: Option<&Transaction>,
    ) -> Result<ProgIdState, String> {
        self.verify_prog_id_orphan(app, tx)?;
        let classes = required(
            &RegKey::predef(HKEY_CURRENT_USER),
            &self.prog_ids_path,
            tx,
            false,
            true,
        )?;
        let prog_id = required(&classes, &app.prog_id, tx, false, false)?;
        let children: Vec<_> = prog_id
            .enum_keys()
            .take(3)
            .collect::<Result<_, _>>()
            .map_err(|_| "ProgID structure could not be read.")?;
        if children.len() != 1 || !children[0].eq_ignore_ascii_case("CLSID") {
            return Err(
                "ProgIDs with CurVer, shell, or other registration children remain read-only."
                    .into(),
            );
        }
        let leaf = required(&prog_id, "CLSID", tx, false, false)?;
        if leaf.enum_keys().next().is_some() {
            return Err("Nested or unreadable ProgID CLSID mappings remain read-only.".into());
        }
        let guard = ProgIdGuard {
            values: values(&prog_id)?,
        };
        guard.validate()?;
        let value = read_value(&leaf, "")?;
        if values(&leaf)?.iter().any(|v| !v.name.is_empty()) {
            return Err("Named ProgID CLSID metadata remains read-only.".into());
        }
        if let Some(value) = &value {
            mapping_clsid(value)?;
        }
        Ok(ProgIdState { value, guard })
    }
    pub(crate) fn prog_id_state(&self, app: &ProgIdBackup) -> Result<ProgIdState, String> {
        self.prog_id_state_in(app, None)
    }
    pub(crate) fn prog_id_write_access(&self, app: &ProgIdBackup) -> Result<(), String> {
        self.prog_id_leaf(app, None, true).map(|_| ())
    }
    pub(crate) fn exchange_prog_id(
        &self,
        app: &ProgIdBackup,
        expected: &ProgIdState,
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
                    .ok_or("Missing ProgID mapping evidence.")?,
            )? != app.clsid
        {
            return Err(
                "Only exact orphaned ProgID mapping removal or restoration is supported.".into(),
            );
        }
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.prog_id_state_in(app, Some(&tx))? != *expected {
            return Err("ProgID metadata changed. Nothing was overwritten.".into());
        }
        let leaf = self.prog_id_leaf(app, Some(&tx), true)?;
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
        .map_err(|e| format!("ProgID mapping update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("ProgID transaction did not commit: {e}"))
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
            panic!("ProgID recovery must not probe files")
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
            for scope in ["User", "Machine"] {
                RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(format!(r"{}\{scope}\CLSID", fixture.base))
                    .unwrap();
            }
            for index in 0..2 {
                let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey(format!(r"{}\User\{}", fixture.base, fixture.name(index)))
                    .unwrap();
                key.set_value("", &"Owned ProgID description").unwrap();
                let original = fixture.original(index);
                key.create_subkey("CLSID")
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
            }
            fixture
        }
        fn name(&self, index: usize) -> &str {
            if index == 0 {
                "RustRegistry.One.1"
            } else {
                "RustRegistry.Two.1"
            }
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
                prog_ids_path: format!(r"{}\User", self.base),
                machine_prog_ids_path: format!(r"{}\Machine", self.base),
                prog_id_test_machine_user: true,
                ..Default::default()
            }
        }
        fn selector(&self, index: usize) -> ProgIdBackup {
            ProgIdBackup {
                prog_id: self.name(index).into(),
                clsid: self.ids[index].clone(),
                guard: ProgIdGuard { values: vec![] },
            }
        }
        fn entry(&self, index: usize) -> RegistryEntry {
            let mut entry:RegistryEntry=serde_json::from_value(serde_json::json!({"id":self.name(index),"name":self.name(index),"category":"prog_ids","hive":"HKCU","view":"shared","keyPath":format!(r"{PROG_IDS_KEY}\{}\CLSID",self.name(index)),"valueName":"","valueType":if index==0{"REG_EXPAND_SZ"}else{"REG_SZ"},"rawValue":self.ids[index],"publisher":null,"version":null,"assessment":{"status":"review","code":"clsid_missing","explanation":"Owned orphan","target":self.ids[index]},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"progIdRepairable":true})).unwrap();
            entry.prog_id_state = Some(self.store().read_prog_id(&self.selector(index)).unwrap());
            entry
        }
        fn target(&self, machine: bool) {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(
                    r"{}\{}\CLSID\{}",
                    self.base,
                    if machine { "Machine" } else { "User" },
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
                read_value(&self.key(1, "CLSID"), "").unwrap(),
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
    fn restores_unchanged_v0112_prog_id_backup_without_migration() {
        let fixture = Fixture::new();
        let directory = tempfile::tempdir().unwrap();
        let id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let leaf = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(
                r"{}\User\RustRegistry.Legacy.1\CLSID",
                fixture.base
            ))
            .unwrap()
            .0;
        let bytes = include_bytes!("../tests/fixtures/prog-id-backup-v12.json");
        let file = directory.path().join(format!("{id}.json"));
        std::fs::write(&file, bytes).unwrap();
        let mut manager =
            ChangeManager::new(fixture.store(), directory.path().to_path_buf(), NoFileProbe);
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "prog_id");
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
    fn prog_id_quick_and_selected_clean_keep_separate_backups_and_restore_exact_types_bytes_and_metadata(
    ) {
        for mode in ["quick", "selected"] {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let entries = [fixture.entry(0), fixture.entry(1)];
            let initial = [
                entries[0].prog_id_state.clone().unwrap(),
                entries[1].prog_id_state.clone().unwrap(),
            ];
            assert!(entries.iter().all(crate::changes::is_repair_candidate));
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), NoFileProbe);
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            assert_eq!(plan.items.len(), 2);
            assert!(plan
                .items
                .iter()
                .all(|p| p.preserved_values == 1 && p.scope == "prog_id"));
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
                    .read_prog_id(&fixture.selector(index))
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
                .all(|b| b.state == "restore_available" && b.scope == "prog_id"));
            for (index, result) in result.completed.iter().enumerate() {
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(backups.join(format!("{}.json", result.backup_id))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["schemaVersion"], 12);
                assert_eq!(record["progId"]["clsid"], fixture.ids[index]);
                assert_eq!(
                    record["original"],
                    serde_json::to_value(fixture.original(index)).unwrap()
                );
                let restore = manager.prepare_restore(&result.backup_id).unwrap();
                manager.apply(&restore.token).unwrap();
                assert_eq!(
                    fixture
                        .store()
                        .read_prog_id(&fixture.selector(index))
                        .unwrap(),
                    initial[index]
                );
            }
        }
    }
    #[test]
    fn prog_id_repair_blocks_new_targets_counterparts_metadata_children_missing_keys_and_backup_failure(
    ) {
        for scenario in 0..9 {
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
                    .key(0, "CLSID")
                    .set_value("Named", &"preserve")
                    .unwrap(),
                6 => fixture.key(0, "").delete_subkey("CLSID").unwrap(),
                7 => std::fs::write(&backups, b"not a directory").unwrap(),
                8 => fixture
                    .key(0, "CLSID")
                    .set_value("", &"{22222222-2222-4222-8222-222222222222}")
                    .unwrap(),
                _ => unreachable!(),
            }
            assert!(manager.apply(&plan.token).is_err(), "scenario {scenario}");
            fixture.assert_other();
            if scenario != 6 && scenario != 8 {
                assert_eq!(
                    read_value(&fixture.key(0, "CLSID"), "").unwrap(),
                    Some(fixture.original(0))
                );
            } else if scenario == 6 {
                assert!(fixture.key(0, "").open_subkey("CLSID").is_err());
            } else {
                assert_eq!(
                    fixture.key(0, "CLSID").get_value::<String, _>("").unwrap(),
                    "{22222222-2222-4222-8222-222222222222}"
                );
            }
        }
    }
    #[test]
    fn prog_id_restore_blocks_new_values_classes_metadata_missing_keys_and_tampered_backup_scope() {
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
                    .key(0, "CLSID")
                    .set_value("", &"{22222222-2222-4222-8222-222222222222}")
                    .unwrap(),
                1 => fixture.target(false),
                2 => fixture.target(true),
                3 => fixture.counterpart(),
                4 => fixture
                    .key(0, "")
                    .set_value("", &"changed description")
                    .unwrap(),
                5 => fixture.key(0, "").delete_subkey("CLSID").unwrap(),
                6..=9 => {
                    let path = backups.join(format!("{}.json", result.backup_id));
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    match scenario {
                        6 => record["progId"]["progId"] = serde_json::json!(r"Bad\Path"),
                        7 => {
                            record["progId"]["clsid"] =
                                serde_json::json!("{33333333-3333-4333-8333-333333333333}")
                        }
                        8 => {
                            record["progId"]["guard"]["values"][0]["name"] =
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
                    fixture.key(0, "CLSID").get_value::<String, _>("").unwrap(),
                    "{22222222-2222-4222-8222-222222222222}"
                );
            } else if scenario != 5 {
                assert!(read_value(&fixture.key(0, "CLSID"), "").unwrap().is_none());
            } else {
                assert!(fixture.key(0, "").open_subkey("CLSID").is_err());
            }
        }
    }
    #[test]
    fn prog_id_batch_stops_at_conflict_and_completed_mapping_remains_independently_restorable() {
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
            read_value(&fixture.key(0, "CLSID"), "").unwrap(),
            Some(fixture.original(0))
        );
    }
    #[test]
    fn prog_id_review_checks_existing_write_access_before_creating_a_backup() {
        struct ReadOnly(WindowsRegistryStore);
        impl RegistryStore for ReadOnly {
            fn read_prog_id(&self, app: &ProgIdBackup) -> Result<ProgIdState, String> {
                self.0.read_prog_id(app)
            }
            fn check_prog_id_write_access(&self, _: &ProgIdBackup) -> Result<(), String> {
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
            read_value(&fixture.key(0, "CLSID"), "").unwrap(),
            Some(fixture.original(0))
        );
        fixture.assert_other();
    }
}
