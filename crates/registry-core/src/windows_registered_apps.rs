use super::{read_value, WindowsRegistryStore};
use crate::{changes::StoredValue, registered_apps::*};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue, HKEY};

// Walk one component at a time with OPEN_LINK: missing keys are evidence only
// after every existing ancestor was readable and confirmed not to be a link.
pub(crate) fn open_registration_path(
    hive: HKEY,
    path: &str,
    flag: u32,
    tx: Option<&Transaction>,
    write: bool,
) -> Result<Option<RegKey>, String> {
    let mut key = RegKey::predef(hive);
    let parts: Vec<_> = path.split('\\').collect();
    for (index, part) in parts.iter().enumerate() {
        let access = KEY_READ
            | flag
            | if write && index + 1 == parts.len() {
                KEY_SET_VALUE
            } else {
                0
            };
        let next = if let Some(tx) = tx {
            key.open_subkey_transacted_with_options_flags(part, tx, REG_OPTION_OPEN_LINK, access)
        } else {
            key.open_subkey_with_options_flags(part, REG_OPTION_OPEN_LINK, access)
        };
        key = match next {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("Application registry evidence is inaccessible (Windows error {}). Nothing was changed.", error.raw_os_error().unwrap_or(0))),
        };
        if read_value(&key, "SymbolicLinkValue")?.is_some_and(|v| v.kind == 6) {
            return Err("Registry links remain outside application registration recovery.".into());
        }
    }
    Ok(Some(key))
}

impl WindowsRegistryStore {
    fn registration_root(&self, tx: Option<&Transaction>, write: bool) -> Result<RegKey, String> {
        let key = open_registration_path(HKEY_CURRENT_USER, &self.registered_app_path, 0, tx, write)?
            .ok_or("The existing current-user RegisteredApplications key is required; it will not be recreated.")?;
        Ok(key)
    }

    fn verify_registration_missing(
        &self,
        name: &str,
        original: &StoredValue,
        tx: Option<&Transaction>,
    ) -> Result<(), String> {
        validate_registration_name(name)?;
        let path = capabilities_path(original)?;
        if open_registration_path(HKEY_CURRENT_USER, &path, 0, tx, false)?.is_some() {
            return Err("The application's Capabilities key exists. Recovery is blocked.".into());
        }
        #[cfg(test)]
        let (machine_hive, machine_path) = if let Some(prefix) = &self.registered_app_test_machine {
            (HKEY_CURRENT_USER, format!(r"{prefix}\{path}"))
        } else {
            (HKEY_LOCAL_MACHINE, path.clone())
        };
        #[cfg(not(test))]
        let (machine_hive, machine_path) = (HKEY_LOCAL_MACHINE, path.clone());
        // RegisteredApplications is shared. Read its native path once so the
        // 32-bit compatibility link is neither followed nor mistaken for an
        // application-owned link. Capabilities targets may still be redirected.
        if let Some(root) = open_registration_path(
            machine_hive,
            &self.machine_registered_app_path,
            KEY_WOW64_64KEY,
            tx,
            false,
        )? {
            if read_value(&root, name)?.is_some() {
                return Err("A machine application registration with this name exists. Recovery is blocked.".into());
            }
        }
        for flag in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            if open_registration_path(machine_hive, &machine_path, flag, tx, false)?.is_some() {
                return Err(
                    "Machine Capabilities exist for this path. Recovery is blocked.".into(),
                );
            }
        }
        Ok(())
    }

    pub(crate) fn registration_value(
        &self,
        name: &str,
        original: &StoredValue,
    ) -> Result<Option<StoredValue>, String> {
        self.verify_registration_missing(name, original, None)?;
        read_value(&self.registration_root(None, false)?, name)
    }
    pub(crate) fn registration_write_access(&self) -> Result<(), String> {
        self.registration_root(None, true).map(|_| ())
    }
    pub(crate) fn exchange_registration(
        &self,
        name: &str,
        original: &StoredValue,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        if expected.is_some() == replacement.is_some() || expected.or(replacement) != Some(original)
        {
            return Err(
                "Only exact application registration removal or restoration is supported.".into(),
            );
        }
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        self.verify_registration_missing(name, original, Some(&tx))?;
        let key = self.registration_root(Some(&tx), true)?;
        if read_value(&key, name)?.as_ref() != expected {
            return Err("The application registration changed. No value was overwritten.".into());
        }
        match replacement {
            Some(value) => key.set_raw_value(
                name,
                &RegValue {
                    vtype: REG_SZ,
                    bytes: Cow::Borrowed(&value.bytes),
                },
            ),
            None => key.delete_value(name),
        }
        .map_err(|e| format!("Application registration change failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Application registration transaction was not committed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{ChangeManager, RegistryStore},
        LocalPathProbe, RegistryEntry,
    };
    #[test]
    fn machine_counterpart_checks_read_the_shared_registration_root_without_following_compatibility_links(
    ) {
        let id = uuid::Uuid::new_v4();
        let path = format!(r"Software\RustRegistryTests\{id}\Capabilities");
        let original = StoredValue {
            kind: 1,
            bytes: path
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        WindowsRegistryStore::default()
            .verify_registration_missing(&format!("RustRegistry-Test-{id}"), &original, None)
            .unwrap();
    }
    struct Fixture {
        base: String,
        root: String,
        machine: String,
        prefix: String,
    }
    impl Fixture {
        fn new() -> Self {
            let base = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
            let fixture = Self {
                root: format!(r"{base}\Registrations"),
                machine: format!(r"{base}\MachineRegistrations"),
                prefix: format!(r"{base}\Machine"),
                base,
            };
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&fixture.machine)
                .unwrap();
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&fixture.root)
                .unwrap();
            for name in ["One", "Two"] {
                let value = fixture.original(name);
                key.set_raw_value(
                    name,
                    &RegValue {
                        vtype: REG_SZ,
                        bytes: Cow::Owned(value.bytes),
                    },
                )
                .unwrap();
            }
            key.set_value("UnsupportedControl", &7u32).unwrap();
            key.create_subkey("PackagedApps")
                .unwrap()
                .0
                .set_value("OwnedControl", &"preserve subtree")
                .unwrap();
            fixture
        }
        fn target(&self, name: &str) -> String {
            format!(r"{}\{}\Capabilities", self.base, name)
        }
        fn original(&self, name: &str) -> StoredValue {
            StoredValue {
                kind: 1,
                bytes: self
                    .target(name)
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }
        }
        fn key(&self) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(&self.root, KEY_ALL_ACCESS)
                .unwrap()
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                registered_app_path: self.root.clone(),
                machine_registered_app_path: self.machine.clone(),
                registered_app_test_machine: Some(self.prefix.clone()),
                ..Default::default()
            }
        }
        fn entry(&self, name: &str) -> RegistryEntry {
            let mut entry: RegistryEntry = serde_json::from_value(serde_json::json!({
                "id":name,"name":name,"category":"registered_applications","hive":"HKCU","keyPath":REGISTERED_APPS_KEY,"view":"shared","valueName":name,"valueType":"REG_SZ","rawValue":self.target(name),"publisher":null,"version":null,
                "assessment":{"status":"review","code":"capabilities_missing","explanation":"Owned fixture","target":self.target(name)},
                "appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":true
            })).unwrap();
            entry.snapshot = Some(self.original(name));
            entry
        }
        fn create_target(&self, machine: bool) {
            let target = if machine {
                format!(r"{}\{}", self.prefix, self.target("One"))
            } else {
                self.target("One")
            };
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(target)
                .unwrap();
        }
        fn assert_control(&self) {
            assert_eq!(
                self.key()
                    .get_value::<u32, _>("UnsupportedControl")
                    .unwrap(),
                7
            );
            assert_eq!(
                self.key()
                    .open_subkey("PackagedApps")
                    .unwrap()
                    .get_value::<String, _>("OwnedControl")
                    .unwrap(),
                "preserve subtree"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.base);
        }
    }

    #[test]
    fn restores_unchanged_v0110_registration_backup_without_migration() {
        let fixture = Fixture::new();
        let directory = tempfile::tempdir().unwrap();
        let bytes = include_bytes!("../tests/fixtures/registered-app-backup-v10.json");
        let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let file = directory.path().join(format!("{id}.json"));
        std::fs::write(&file, bytes).unwrap();
        let mut manager = ChangeManager::new(
            fixture.store(),
            directory.path().to_path_buf(),
            LocalPathProbe,
        );
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "registered_app");
        manager.apply(&plan.token).unwrap();
        let record: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            read_value(&fixture.key(), "RustRegistryLegacyRegisteredApplication").unwrap(),
            Some(serde_json::from_value(record["original"].clone()).unwrap())
        );
        assert_eq!(std::fs::read(file).unwrap(), bytes);
        fixture.assert_control();
    }

    #[test]
    fn registrations_quick_and_selected_clean_keep_separate_backups_and_restore_exact_bytes_after_restart(
    ) {
        for mode in ["quick", "selected"] {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let entries = [fixture.entry("One"), fixture.entry("Two")];
            assert!(entries.iter().all(crate::changes::is_repair_candidate));
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            assert_eq!(plan.items.len(), 2);
            assert!(plan.skipped.is_empty());
            assert!(!backups.exists());
            manager.cancel();
            assert!(manager.apply_clean(&plan.token).is_err());
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            let result = manager.apply_clean(&plan.token).unwrap();
            assert!(result.failed.is_none());
            assert_eq!(result.completed.len(), 2);
            fixture.assert_control();
            for entry in &entries {
                assert!(fixture.key().get_raw_value(&entry.name).is_err());
            }
            drop(manager);
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            assert!(manager
                .inventory()
                .unwrap()
                .backups
                .iter()
                .all(|b| b.scope == "registered_app" && b.state == "restore_available"));
            for (index, result) in result.completed.iter().enumerate() {
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(backups.join(format!("{}.json", result.backup_id))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["schemaVersion"], 10);
                assert_eq!(
                    record["registeredApp"]["capabilitiesPath"],
                    fixture.target(&entries[index].name)
                );
                assert_eq!(
                    record["original"],
                    serde_json::to_value(fixture.original(&entries[index].name)).unwrap()
                );
                let plan = manager.prepare_restore(&result.backup_id).unwrap();
                manager.apply(&plan.token).unwrap();
                assert_eq!(
                    read_value(&fixture.key(), &entries[index].name).unwrap(),
                    Some(fixture.original(&entries[index].name))
                );
            }
            fixture.assert_control();
        }
    }

    #[test]
    fn registration_repair_blocks_new_capabilities_machine_counterparts_changed_values_missing_keys_and_backup_failure(
    ) {
        for scenario in 0..6 {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager.prepare_quarantine(&fixture.entry("One")).unwrap();
            match scenario {
                0 => fixture.create_target(false),
                1 => fixture.create_target(true),
                2 => {
                    RegKey::predef(HKEY_CURRENT_USER)
                        .open_subkey_with_flags(&fixture.machine, KEY_SET_VALUE)
                        .unwrap()
                        .set_value("One", &"preserve machine")
                        .unwrap();
                }
                3 => fixture.key().set_value("One", &"changed").unwrap(),
                4 => RegKey::predef(HKEY_CURRENT_USER)
                    .delete_subkey_all(&fixture.root)
                    .unwrap(),
                5 => std::fs::write(&backups, b"not a directory").unwrap(),
                _ => unreachable!(),
            }
            assert!(manager.apply(&plan.token).is_err(), "scenario {scenario}");
            if scenario != 4 {
                assert!(fixture.key().get_raw_value("One").is_ok());
                fixture.assert_control();
            } else {
                assert!(RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(&fixture.root)
                    .is_err());
            }
        }
    }

    #[test]
    fn registration_restore_blocks_replacements_new_targets_machine_duplicates_and_tampered_backup_scope(
    ) {
        for scenario in 0..7 {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager.prepare_quarantine(&fixture.entry("One")).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            let restore = manager.prepare_restore(&result.backup_id).unwrap();
            match scenario {
                0 => fixture.key().set_value("One", &"new registration").unwrap(),
                1 => fixture.create_target(false),
                2 => fixture.create_target(true),
                3 => {
                    RegKey::predef(HKEY_CURRENT_USER)
                        .open_subkey_with_flags(&fixture.machine, KEY_SET_VALUE)
                        .unwrap()
                        .set_value("One", &"machine")
                        .unwrap();
                }
                4..=6 => {
                    let path = backups.join(format!("{}.json", result.backup_id));
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    if scenario == 4 {
                        record["original"]["kind"] = serde_json::json!(2);
                    } else if scenario == 5 {
                        record["registeredApp"]["capabilitiesPath"] =
                            serde_json::json!(r"Software\Microsoft\Capabilities");
                    } else {
                        record["valueName"] = serde_json::json!("Other");
                    }
                    std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                manager.apply(&restore.token).is_err(),
                "scenario {scenario}"
            );
            if scenario == 0 {
                assert_eq!(
                    fixture.key().get_value::<String, _>("One").unwrap(),
                    "new registration"
                );
            } else {
                assert!(fixture.key().get_raw_value("One").is_err());
            }
            fixture.assert_control();
        }
    }

    #[test]
    fn registration_batch_stops_on_conflict_and_completed_value_remains_restorable() {
        let fixture = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let mut manager =
            ChangeManager::new(fixture.store(), dir.path().join("backups"), LocalPathProbe);
        let plan = manager
            .prepare_clean(&[fixture.entry("One"), fixture.entry("Two")], "quick")
            .unwrap();
        fixture.key().set_value("Two", &"changed").unwrap();
        let result = manager.apply_clean(&plan.token).unwrap();
        assert_eq!(result.completed.len(), 1);
        assert!(result.failed.is_some());
        assert!(fixture.key().get_raw_value("One").is_err());
        assert_eq!(
            fixture.key().get_value::<String, _>("Two").unwrap(),
            "changed"
        );
        let restore = manager
            .prepare_restore(&result.completed[0].backup_id)
            .unwrap();
        manager.apply(&restore.token).unwrap();
        assert_eq!(
            read_value(&fixture.key(), "One").unwrap(),
            Some(fixture.original("One"))
        );
        fixture.assert_control();
    }

    #[test]
    fn registration_review_checks_existing_write_access_before_backup_or_mutation() {
        struct ReadOnly(WindowsRegistryStore);
        impl RegistryStore for ReadOnly {
            fn read_registered_app(
                &self,
                name: &str,
                value: &StoredValue,
            ) -> Result<Option<StoredValue>, String> {
                self.0.read_registered_app(name, value)
            }
            fn check_registered_app_write_access(&self) -> Result<(), String> {
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
            ChangeManager::new(ReadOnly(fixture.store()), backups.clone(), LocalPathProbe);
        assert!(manager
            .prepare_quarantine(&fixture.entry("One"))
            .unwrap_err()
            .contains("write access"));
        assert!(!backups.exists());
        assert_eq!(
            read_value(&fixture.key(), "One").unwrap(),
            Some(fixture.original("One"))
        );
    }
}
