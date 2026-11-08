use super::{read_value, WindowsRegistryStore};
use crate::{changes::StoredValue, shared_dlls::*};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

impl WindowsRegistryStore {
    fn shared_dll_key(&self, tx: Option<&Transaction>, write: bool) -> Result<RegKey, String> {
        #[cfg(test)]
        let hive = if self.shared_dll_test_user {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        };
        #[cfg(not(test))]
        let hive = HKEY_LOCAL_MACHINE;
        let parent = RegKey::predef(hive);
        let flags = KEY_READ | KEY_WOW64_64KEY | if write { KEY_SET_VALUE } else { 0 };
        let result = if let Some(tx) = tx {
            parent.open_subkey_transacted_with_options_flags(
                &self.shared_dll_path,
                tx,
                REG_OPTION_OPEN_LINK,
                flags,
            )
        } else {
            parent.open_subkey_with_options_flags(
                &self.shared_dll_path,
                REG_OPTION_OPEN_LINK,
                flags,
            )
        };
        let key = result.map_err(|error| format!("The existing 64-bit SharedDLLs key cannot be opened{} (Windows error {}). Existing Windows write access is required for changes; no elevation or permission changes are requested automatically.", if write { " for writing" } else { "" }, error.raw_os_error().unwrap_or(0)))?;
        if read_value(&key, "SymbolicLinkValue")?.is_some_and(|v| v.kind == 6)
            || key.enum_keys().next().is_some()
        {
            return Err(
                "Linked, nested, or unreadable SharedDLLs keys remain outside repair scope.".into(),
            );
        }
        Ok(key)
    }
    pub(crate) fn shared_dll_value(&self, path: &str) -> Result<Option<StoredValue>, String> {
        validate_shared_dll_path(path)?;
        read_value(&self.shared_dll_key(None, false)?, path)
    }
    pub(crate) fn shared_dll_write_access(&self) -> Result<(), String> {
        self.shared_dll_key(None, true).map(|_| ())
    }
    pub(crate) fn exchange_shared_dll(
        &self,
        path: &str,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        validate_shared_dll_path(path)?;
        if expected.is_some() == replacement.is_some() {
            return Err(
                "Only removal or exact restoration of one zero-count value is supported.".into(),
            );
        }
        for value in [expected, replacement].into_iter().flatten() {
            validate_zero_count(value)?;
        }
        let tx = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        let key = self.shared_dll_key(Some(&tx), true)?;
        if read_value(&key, path)?.as_ref() != expected {
            return Err("The shared DLL counter changed. No value was overwritten.".into());
        }
        verify_missing_shared_dll(
            path,
            expected
                .or(replacement)
                .ok_or("Missing reference-count evidence.")?,
            &crate::LocalPathProbe,
        )?;
        match replacement {
            Some(value) => key.set_raw_value(
                path,
                &RegValue {
                    vtype: REG_DWORD,
                    bytes: Cow::Borrowed(&value.bytes),
                },
            ),
            None => key.delete_value(path),
        }
        .map_err(|error| {
            format!(
                "The shared DLL reference change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        tx.commit().map_err(|error| format!("Windows did not commit the shared DLL reference change (Windows error {}). The backup is preserved.", error.raw_os_error().unwrap_or(0)))
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
        key: String,
        directory: tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            let fixture = Self {
                key: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
                directory: tempfile::tempdir().unwrap(),
            };
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&fixture.key)
                .unwrap();
            for name in ["one.dll", "two.dll"] {
                key.set_value(fixture.path(name), &0u32).unwrap();
            }
            key.set_value(fixture.path("positive.dll"), &5u32).unwrap();
            key.set_value(fixture.path("malformed.dll"), &"0").unwrap();
            fixture
        }
        fn path(&self, name: &str) -> String {
            self.directory.path().join(name).display().to_string()
        }
        fn key(&self) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(&self.key, KEY_ALL_ACCESS)
                .unwrap()
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                shared_dll_path: self.key.clone(),
                shared_dll_test_user: true,
                ..Default::default()
            }
        }
        fn entry(&self, name: &str) -> RegistryEntry {
            let path = self.path(name);
            RegistryEntry {
                id: path.clone(),
                name: name.into(),
                category: Category::SharedDlls,
                hive: "HKLM".into(),
                key_path: SHARED_DLLS_KEY.into(),
                view: "64".into(),
                value_name: path.clone(),
                value_type: "REG_DWORD".into(),
                raw_value: "Reference count: 0".into(),
                publisher: None,
                version: None,
                assessment: Assessment {
                    status: EntryStatus::Review,
                    code: "target_missing".into(),
                    explanation: "Owned missing DLL".into(),
                    target: Some(path.clone()),
                },
                snapshot: self.store().read_shared_dll(&path).unwrap(),
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
                application_snapshot: None,
                application_repairable: false,
                application_hidden: false,
                shared_dll_repairable: true,
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
        fn assert_controls(&self) {
            assert_eq!(
                self.key()
                    .get_value::<u32, _>(self.path("positive.dll"))
                    .unwrap(),
                5
            );
            assert_eq!(
                self.key()
                    .get_value::<String, _>(self.path("malformed.dll"))
                    .unwrap(),
                "0"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.key);
        }
    }

    #[test]
    fn restores_unchanged_v019_shared_dll_backup_without_migration() {
        let fixture = Fixture::new();
        let directory = tempfile::tempdir().unwrap();
        let bytes = include_bytes!("../tests/fixtures/shared-dll-backup-v9.json");
        let id = "99999999-9999-4999-8999-999999999999";
        let file = directory.path().join(format!("{id}.json"));
        std::fs::write(&file, bytes).unwrap();
        let mut manager = ChangeManager::new(
            fixture.store(),
            directory.path().to_path_buf(),
            LocalPathProbe,
        );
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "shared_dll");
        manager.apply(&plan.token).unwrap();
        assert_eq!(
            fixture
                .key()
                .get_value::<u32, _>(r"C:\RustRegistryMissing\legacy-shared-dll.dll")
                .unwrap(),
            0
        );
        assert_eq!(std::fs::read(file).unwrap(), bytes);
        fixture.assert_controls();
    }

    #[test]
    fn shared_dll_quick_and_selected_batches_back_up_two_values_in_one_key_and_restore_after_restart(
    ) {
        for mode in ["quick", "selected"] {
            let fixture = Fixture::new();
            let directory = tempfile::tempdir().unwrap();
            let backups = directory.path().join("backups");
            let entries = [fixture.entry("one.dll"), fixture.entry("two.dll")];
            assert!(entries.iter().all(crate::changes::is_repair_candidate));
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            assert_eq!(plan.items.len(), 2);
            assert!(plan.skipped.is_empty());
            assert_eq!(plan.items[0].scope, "shared_dll");
            assert_eq!(plan.items[0].original_value, "0");
            assert_eq!(plan.items[0].registry_view, "64");
            assert!(!backups.exists());
            manager.cancel();
            assert!(manager.apply_clean(&plan.token).is_err());
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            let result = manager.apply_clean(&plan.token).unwrap();
            assert!(result.failed.is_none());
            assert_eq!(result.completed.len(), 2);
            for (index, item) in result.completed.iter().enumerate() {
                assert!(fixture
                    .store()
                    .read_shared_dll(&entries[index].value_name)
                    .unwrap()
                    .is_none());
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(backups.join(format!("{}.json", item.backup_id))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["schemaVersion"], 9);
                assert_eq!(
                    record["original"],
                    serde_json::json!({"kind":4,"bytes":[0,0,0,0]})
                );
                assert_eq!(record["sharedDll"]["path"], entries[index].value_name);
                assert_eq!(record["sharedDll"]["view"], "64");
            }
            fixture.assert_controls();
            drop(manager);
            let mut manager = ChangeManager::new(fixture.store(), backups, LocalPathProbe);
            assert!(manager
                .inventory()
                .unwrap()
                .backups
                .iter()
                .all(|b| b.scope == "shared_dll"
                    && b.state == "restore_available"
                    && b.registry_view == "64"));
            for item in result.completed {
                let plan = manager.prepare_restore(&item.backup_id).unwrap();
                manager.apply(&plan.token).unwrap();
            }
            for entry in &entries {
                assert_eq!(
                    fixture.store().read_shared_dll(&entry.value_name).unwrap(),
                    entry.snapshot
                );
            }
            fixture.assert_controls();
        }
    }

    #[test]
    fn shared_dll_repair_refuses_new_counts_reappearing_files_nested_or_missing_keys_and_backup_failure(
    ) {
        for scenario in 0..6 {
            let fixture = Fixture::new();
            let directory = tempfile::tempdir().unwrap();
            let backups = directory.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager
                .prepare_quarantine(&fixture.entry("one.dll"))
                .unwrap();
            match scenario {
                0 => fixture
                    .key()
                    .set_value(fixture.path("one.dll"), &7u32)
                    .unwrap(),
                1 => fixture
                    .key()
                    .set_value(fixture.path("one.dll"), &"preserve unsupported value")
                    .unwrap(),
                2 => std::fs::write(fixture.path("one.dll"), b"never loaded or modified").unwrap(),
                3 => {
                    fixture.key().create_subkey("Unexpected").unwrap();
                }
                4 => RegKey::predef(HKEY_CURRENT_USER)
                    .delete_subkey_all(&fixture.key)
                    .unwrap(),
                5 => std::fs::write(backups, b"not a directory").unwrap(),
                _ => unreachable!(),
            }
            assert!(manager.apply(&plan.token).is_err(), "scenario {scenario}");
            if scenario == 4 {
                assert!(RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(&fixture.key)
                    .is_err());
            } else {
                assert!(fixture.key().get_raw_value(fixture.path("one.dll")).is_ok());
                fixture.assert_controls();
            }
            if scenario == 0 {
                assert_eq!(
                    fixture
                        .key()
                        .get_value::<u32, _>(fixture.path("one.dll"))
                        .unwrap(),
                    7
                );
            }
            if scenario == 2 {
                assert_eq!(
                    std::fs::read(fixture.path("one.dll")).unwrap(),
                    b"never loaded or modified"
                );
            }
        }
    }

    #[test]
    fn shared_dll_restore_refuses_new_values_files_structure_and_corrupted_scope_after_review() {
        for scenario in 0..7 {
            let fixture = Fixture::new();
            let directory = tempfile::tempdir().unwrap();
            let backups = directory.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager
                .prepare_quarantine(&fixture.entry("one.dll"))
                .unwrap();
            let result = manager.apply(&plan.token).unwrap();
            let restore = manager.prepare_restore(&result.backup_id).unwrap();
            match scenario {
                0 => fixture
                    .key()
                    .set_value(fixture.path("one.dll"), &9u32)
                    .unwrap(),
                1 => std::fs::write(fixture.path("one.dll"), b"never loaded or modified").unwrap(),
                2 => {
                    fixture.key().create_subkey("Unexpected").unwrap();
                }
                3 => RegKey::predef(HKEY_CURRENT_USER)
                    .delete_subkey_all(&fixture.key)
                    .unwrap(),
                4..=6 => {
                    let path = backups.join(format!("{}.json", result.backup_id));
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    match scenario {
                        4 => {
                            record["sharedDll"]["path"] =
                                serde_json::json!(fixture.path("other.dll"))
                        }
                        5 => record["sharedDll"]["view"] = serde_json::json!("32"),
                        _ => record["original"]["bytes"] = serde_json::json!([1, 0, 0, 0]),
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
                    fixture
                        .key()
                        .get_value::<u32, _>(fixture.path("one.dll"))
                        .unwrap(),
                    9
                );
            }
            if scenario == 3 {
                assert!(RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(&fixture.key)
                    .is_err());
            } else {
                fixture.assert_controls();
            }
        }
    }

    #[test]
    fn shared_dll_review_checks_write_access_before_creating_any_backup() {
        struct ReadOnly;
        impl RegistryStore for ReadOnly {
            fn read(&self, _: &str) -> Result<Option<StoredValue>, String> {
                Err("Unused".into())
            }
            fn compare_exchange(
                &self,
                _: &str,
                _: Option<&StoredValue>,
                _: Option<&StoredValue>,
            ) -> Result<(), String> {
                Err("Unused".into())
            }
            fn read_shared_dll(&self, _: &str) -> Result<Option<StoredValue>, String> {
                Ok(Some(StoredValue {
                    kind: 4,
                    bytes: vec![0; 4],
                }))
            }
            fn check_shared_dll_write_access(&self) -> Result<(), String> {
                Err("Existing Windows write access is required.".into())
            }
        }
        let fixture = Fixture::new();
        let directory = tempfile::tempdir().unwrap();
        let backups = directory.path().join("backups");
        let mut manager = ChangeManager::new(ReadOnly, backups.clone(), LocalPathProbe);
        let error = manager
            .prepare_quarantine(&fixture.entry("one.dll"))
            .unwrap_err();
        assert!(error.contains("write access"));
        assert!(!backups.exists());
        assert_eq!(
            fixture
                .key()
                .get_value::<u32, _>(fixture.path("one.dll"))
                .unwrap(),
            0
        );
    }
}
