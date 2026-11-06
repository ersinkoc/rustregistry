use crate::changes::{
    validate_app_path_name, validate_value_name, AppPathGuard, AppPathState, NamedValue,
    RegistryStore, StoredValue, APP_PATHS_KEY, STARTUP_KEY,
};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

pub struct WindowsRegistryStore {
    path: String,
    app_paths_path: String,
}
impl Default for WindowsRegistryStore {
    fn default() -> Self {
        Self {
            path: STARTUP_KEY.into(),
            app_paths_path: APP_PATHS_KEY.into(),
        }
    }
}

pub(crate) fn read_app_path_guard(key: &RegKey) -> Result<AppPathGuard, String> {
    if key.enum_keys().next().is_some() {
        return Err(
            "App Paths entries with child keys or unreadable metadata cannot be repaired.".into(),
        );
    }
    let mut values = Vec::new();
    let mut size = 0;
    for item in key.enum_values() {
        let (name, value) =
            item.map_err(|_| "App Paths metadata could not be read completely.".to_string())?;
        if name.is_empty() {
            continue;
        }
        size += value.bytes.len();
        if values.len() >= 32 || size > 16_384 {
            return Err("App Paths metadata exceeds the supported backup limits.".into());
        }
        values.push(NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        });
    }
    values.sort_by_key(|value| value.name.to_lowercase());
    let guard = AppPathGuard { values };
    guard.validate()?;
    Ok(guard)
}

fn read_app_state(key: &RegKey) -> Result<AppPathState, String> {
    Ok(AppPathState {
        value: read_value(key, "")?,
        guard: read_app_path_guard(key)?,
    })
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
    fn read_app_path(&self, executable: &str) -> Result<AppPathState, String> {
        validate_app_path_name(executable)?;
        let path = format!("{}\\{}", self.app_paths_path, executable);
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_options_flags(path, REG_OPTION_OPEN_LINK, KEY_READ).map_err(|error| format!("Cannot read the existing current-user App Paths entry (Windows error {}). Its key is never recreated automatically.", error.raw_os_error().unwrap_or(0)))?;
        read_app_state(&key)
    }

    fn compare_exchange_app_path(
        &self,
        executable: &str,
        expected: &AppPathState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        validate_app_path_name(executable)?;
        expected.guard.validate()?;
        if expected.value.is_none() && replacement.is_none() {
            return Err("No App Paths change was requested.".into());
        }
        for value in [expected.value.as_ref(), replacement].into_iter().flatten() {
            value.text()?;
        }
        if self.read_app_path(executable)? != *expected {
            return Err(
                "The App Paths entry changed before its transaction. Nothing was changed.".into(),
            );
        }
        let transaction = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        let path = format!("{}\\{}", self.app_paths_path, executable);
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_transacted_with_flags(path, &transaction, KEY_READ | KEY_SET_VALUE).map_err(|error| format!("Cannot open the existing App Paths entry for a protected change (Windows error {}).", error.raw_os_error().unwrap_or(0)))?;
        if read_app_state(&key)? != *expected {
            return Err(
                "The App Paths value or its metadata changed. Nothing was overwritten or removed."
                    .into(),
            );
        }
        match replacement {
            Some(value) => key.set_raw_value(
                "",
                &RegValue {
                    bytes: Cow::Borrowed(&value.bytes),
                    vtype: if value.kind == 1 {
                        REG_SZ
                    } else {
                        REG_EXPAND_SZ
                    },
                },
            ),
            None => key.delete_value(""),
        }
        .map_err(|error| {
            format!(
                "The App Paths change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        transaction.commit().map_err(|error| format!("Windows did not commit the App Paths change (Windows error {}). The backup is preserved.", error.raw_os_error().unwrap_or(0)))
    }
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
            app_paths_path: format!("{}\\App Paths", fixture.path),
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
            app_path_guard: None,
            app_path_repairable: false,
        };
        let mut manager = ChangeManager::new(
            WindowsRegistryStore {
                path: fixture.path.clone(),
                app_paths_path: format!("{}\\App Paths", fixture.path),
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
                app_paths_path: format!("{}\\App Paths", fixture.path),
            },
            directory.path().join("backups"),
            LocalPathProbe,
        );
        let restore = reopened.prepare_restore(&changed.backup_id).unwrap();
        reopened.apply(&restore.token).unwrap();
        let reader = WindowsRegistryStore {
            path: fixture.path.clone(),
            app_paths_path: format!("{}\\App Paths", fixture.path),
        };
        assert_eq!(reader.read("Fixture").unwrap(), Some(original));
    }

    #[test]
    fn app_paths_transaction_repair_and_restart_restore_preserve_other_metadata() {
        use crate::{
            changes::ChangeManager, Assessment, Category, EntryStatus, LocalPathProbe,
            RegistryEntry,
        };
        let fixture = Fixture {
            path: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
        };
        let directory = tempfile::tempdir().unwrap();
        let app_paths = format!("{}\\App Paths", fixture.path);
        let child_path = format!("{app_paths}\\broken.exe");
        let original = StoredValue {
            kind: 1,
            bytes: format!("{}\0\0", directory.path().join("missing.exe").display())
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&child_path)
            .unwrap();
        key.set_raw_value(
            "",
            &RegValue {
                bytes: Cow::Borrowed(&original.bytes),
                vtype: REG_SZ,
            },
        )
        .unwrap();
        key.set_value("Path", &"%LOCALAPPDATA%\\Example").unwrap();
        key.set_value("UseUrl", &1u32).unwrap();
        let guard = read_app_path_guard(&key).unwrap();
        drop(key);
        let store = || WindowsRegistryStore {
            path: format!("{}\\Run", fixture.path),
            app_paths_path: app_paths.clone(),
        };
        let entry = RegistryEntry {
            id: "fixture".into(),
            name: "broken.exe".into(),
            category: Category::AppPaths,
            hive: "HKCU".into(),
            key_path: format!("{APP_PATHS_KEY}\\broken.exe"),
            view: "shared".into(),
            value_name: String::new(),
            value_type: "REG_SZ".into(),
            raw_value: original.text().unwrap(),
            publisher: None,
            version: None,
            assessment: Assessment {
                status: EntryStatus::Review,
                code: "target_missing".into(),
                explanation: "Missing fixture".into(),
                target: None,
            },
            snapshot: Some(original.clone()),
            app_path_guard: Some(guard.clone()),
            app_path_repairable: true,
        };
        let mut manager =
            ChangeManager::new(store(), directory.path().join("backups"), LocalPathProbe);
        let plan = manager.prepare_quarantine(&entry).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        assert_eq!(
            store().read_app_path("broken.exe").unwrap(),
            AppPathState {
                value: None,
                guard: guard.clone()
            }
        );
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(&child_path, KEY_READ | KEY_SET_VALUE)
            .unwrap();
        key.set_value("UseUrl", &0u32).unwrap();
        assert!(manager.prepare_restore(&result.backup_id).is_err());
        key.set_value("UseUrl", &1u32).unwrap();
        drop(key);
        drop(manager);
        let mut reopened =
            ChangeManager::new(store(), directory.path().join("backups"), LocalPathProbe);
        let restore = reopened.prepare_restore(&result.backup_id).unwrap();
        reopened.apply(&restore.token).unwrap();
        let expected = store().read_app_path("broken.exe").unwrap();
        assert_eq!(expected.value, Some(original));
        assert_eq!(expected.guard, guard);
        // A concurrently changed default must not be overwritten by restore.
        assert!(store()
            .compare_exchange_app_path(
                "broken.exe",
                &AppPathState {
                    value: None,
                    guard: expected.guard.clone()
                },
                expected.value.as_ref()
            )
            .is_err());
        // Nested registration metadata is explicitly outside the mutation scope.
        let (nested, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!("{child_path}\\Nested"))
            .unwrap();
        drop(nested);
        assert!(store().read_app_path("broken.exe").is_err());
        assert!(store()
            .compare_exchange_app_path("broken.exe", &expected, None)
            .is_err());
    }
}
