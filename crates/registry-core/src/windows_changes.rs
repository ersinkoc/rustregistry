use crate::changes::{validate_value_name, RegistryStore, StoredValue, STARTUP_KEY};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

pub struct WindowsRegistryStore {
    path: String,
}
impl Default for WindowsRegistryStore {
    fn default() -> Self {
        Self {
            path: STARTUP_KEY.into(),
        }
    }
}
fn read_value(key: &RegKey, name: &str) -> Result<Option<StoredValue>, String> {
    match key.get_raw_value(name) {
        Ok(value) => Ok(Some(StoredValue {
            kind: value.vtype as u32,
            bytes: value.bytes.into_owned(),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "Cannot read the startup value (Windows error {}).",
            error.raw_os_error().unwrap_or(0)
        )),
    }
}
impl RegistryStore for WindowsRegistryStore {
    fn read(&self, name: &str) -> Result<Option<StoredValue>, String> {
        validate_value_name(name)?;
        let hive = RegKey::predef(HKEY_CURRENT_USER);
        match hive.open_subkey_with_flags(&self.path, KEY_QUERY_VALUE) {
            Ok(key) => read_value(&key, name),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!(
                "Cannot read the current user's Run key (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )),
        }
    }
    fn compare_exchange(
        &self,
        name: &str,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        validate_value_name(name)?;
        if expected.is_none() && replacement.is_none() {
            return Err("No supported change was requested.".into());
        }
        for value in [expected, replacement].into_iter().flatten() {
            value.text()?;
        }
        let transaction = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_transacted_with_flags(
                &self.path,
                &transaction,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
            )
            .map_err(|error| {
                format!(
                    "Cannot open the existing Run key for a protected change (Windows error {}).",
                    error.raw_os_error().unwrap_or(0)
                )
            })?;
        if read_value(&key, name)?.as_ref() != expected {
            return Err(
                "The startup value changed. No existing value was overwritten or removed.".into(),
            );
        }
        match replacement {
            Some(value) => key.set_raw_value(
                name,
                &RegValue {
                    bytes: Cow::Borrowed(&value.bytes),
                    vtype: if value.kind == 1 {
                        REG_SZ
                    } else {
                        REG_EXPAND_SZ
                    },
                },
            ),
            None => key.delete_value(name),
        }
        .map_err(|error| {
            format!(
                "The protected change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        transaction.commit().map_err(|error| {
            format!(
                "Windows did not commit the change (Windows error {}). The backup is preserved.",
                error.raw_os_error().unwrap_or(0)
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        path: String,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.path);
        }
    }
    #[test]
    fn real_windows_transaction_round_trip_and_conflict_use_an_isolated_test_key() {
        let fixture = Fixture {
            path: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
        };
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&fixture.path)
            .unwrap();
        let original = StoredValue {
            kind: 2,
            bytes: "%LOCALAPPDATA%\\Missing\\app.exe\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        key.set_raw_value(
            "Fixture",
            &RegValue {
                bytes: Cow::Borrowed(&original.bytes),
                vtype: REG_EXPAND_SZ,
            },
        )
        .unwrap();
        drop(key);
        // The production constructor always uses STARTUP_KEY. Only this private
        // unit test substitutes its own disposable, non-startup registry key.
        let store = WindowsRegistryStore {
            path: fixture.path.clone(),
        };
        assert_eq!(store.read("Fixture").unwrap(), Some(original.clone()));
        store
            .compare_exchange("Fixture", Some(&original), None)
            .unwrap();
        assert!(store.read("Fixture").unwrap().is_none());
        store
            .compare_exchange("Fixture", None, Some(&original))
            .unwrap();
        assert_eq!(store.read("Fixture").unwrap(), Some(original.clone()));
        assert!(store
            .compare_exchange("Fixture", None, Some(&original))
            .is_err());
        let wrong = StoredValue {
            kind: 1,
            bytes: original.bytes.clone(),
        };
        assert!(store
            .compare_exchange("Fixture", Some(&wrong), None)
            .is_err());
        assert_eq!(store.read("Fixture").unwrap(), Some(original));
    }

    #[test]
    fn full_backup_disable_restart_and_restore_preserves_real_registry_bytes() {
        use crate::{
            changes::ChangeManager, Assessment, Category, EntryStatus, LocalPathProbe,
            RegistryEntry,
        };
        let fixture = Fixture {
            path: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
        };
        let directory = tempfile::tempdir().unwrap();
        let command = format!(
            "\"{}\"",
            directory.path().join("missing-application.exe").display()
        );
        let original = StoredValue {
            kind: 2,
            bytes: format!("{command}\0\0")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&fixture.path)
            .unwrap();
        key.set_raw_value(
            "Fixture",
            &RegValue {
                bytes: Cow::Borrowed(&original.bytes),
                vtype: REG_EXPAND_SZ,
            },
        )
        .unwrap();
        drop(key);
        let entry = RegistryEntry {
            id: "fixture".into(),
            name: "Fixture".into(),
            category: Category::Startup,
            hive: "HKCU".into(),
            key_path: STARTUP_KEY.into(),
            view: "shared".into(),
            value_name: "Fixture".into(),
            value_type: "REG_EXPAND_SZ".into(),
            raw_value: command,
            publisher: None,
            version: None,
            assessment: Assessment {
                status: EntryStatus::Review,
                code: "target_missing".into(),
                explanation: "Fixture target missing".into(),
                target: None,
            },
            snapshot: Some(original.clone()),
        };
        let mut manager = ChangeManager::new(
            WindowsRegistryStore {
                path: fixture.path.clone(),
            },
            directory.path().join("backups"),
            LocalPathProbe,
        );
        let preview = manager.prepare_quarantine(&entry).unwrap();
        let changed = manager.apply(&preview.token).unwrap();
        assert_eq!(
            manager.inventory().unwrap().backups[0].state,
            "restore_available"
        );
        drop(manager);
        let mut reopened = ChangeManager::new(
            WindowsRegistryStore {
                path: fixture.path.clone(),
            },
            directory.path().join("backups"),
            LocalPathProbe,
        );
        let restore = reopened.prepare_restore(&changed.backup_id).unwrap();
        reopened.apply(&restore.token).unwrap();
        let reader = WindowsRegistryStore {
            path: fixture.path.clone(),
        };
        assert_eq!(reader.read("Fixture").unwrap(), Some(original));
    }
}
