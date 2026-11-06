use super::{read_value, WindowsRegistryStore};
use crate::{
    changes::{NamedValue, StoredValue},
    com::*,
};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

fn open(
    parent: &RegKey,
    path: &str,
    transaction: Option<&Transaction>,
    write: bool,
) -> Result<Option<RegKey>, String> {
    let flags = KEY_READ | KEY_WOW64_64KEY | if write { KEY_SET_VALUE } else { 0 };
    let result = if let Some(transaction) = transaction {
        parent.open_subkey_transacted_with_options_flags(
            path,
            transaction,
            REG_OPTION_OPEN_LINK,
            flags,
        )
    } else {
        parent.open_subkey_with_options_flags(path, REG_OPTION_OPEN_LINK, flags)
    };
    match result {
        Ok(key) => {
            if read_value(&key, "SymbolicLinkValue")?.is_some_and(|v| v.kind == 6) {
                return Err("COM registry links are outside repair scope.".into());
            }
            Ok(Some(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "COM metadata could not be read (Windows error {}).",
            error.raw_os_error().unwrap_or(0)
        )),
    }
}
fn values(key: &RegKey) -> Result<Vec<NamedValue>, String> {
    let mut result = Vec::new();
    let mut size = 0;
    for item in key.enum_values() {
        let (name, value) =
            item.map_err(|_| "COM metadata could not be read completely.".to_string())?;
        size += value.bytes.len();
        if result.len() >= 64 || size > 32_768 {
            return Err("COM metadata exceeds the supported backup limit.".into());
        }
        result.push(NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        });
    }
    result.sort_by_key(|item| item.name.to_ascii_lowercase());
    crate::associations::validate_values(&result)?;
    Ok(result)
}
impl WindowsRegistryStore {
    fn com_state_in(
        &self,
        clsid: &str,
        transaction: Option<&Transaction>,
    ) -> Result<ComState, String> {
        validate_clsid(clsid)?;
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        let root = open(&user, &self.com_path, transaction, false)?
            .ok_or("The current-user COM root is missing. It is never recreated automatically.")?;
        let machine = open(&machine, &self.machine_com_path, transaction, false)?
            .ok_or("The machine COM root could not be verified.")?;
        if open(&machine, clsid, transaction, false)?.is_some() {
            return Err("A machine-wide registration exists for this COM class. Repair or restore is blocked to avoid changing activation fallback.".into());
        }
        let class = open(&root, clsid, transaction, false)?
            .ok_or("The COM class key is missing. It is never recreated automatically.")?;
        let children: Vec<String> = class
            .enum_keys()
            .take(3)
            .collect::<Result<_, _>>()
            .map_err(|_| "COM child keys could not be completely read.".to_string())?;
        if children.len() != 1 || !children[0].eq_ignore_ascii_case(INPROC_SERVER) {
            return Err(
                "COM classes with alternate, nested, or unknown activation keys remain read-only."
                    .into(),
            );
        }
        let server = open(&class, INPROC_SERVER, transaction, false)?
            .ok_or("The existing DLL mapping key is missing.")?;
        if server.enum_keys().next().is_some() {
            return Err("Nested or unreadable COM server keys remain read-only.".into());
        }
        let mut server_values = values(&server)?;
        server_values.retain(|item| !item.name.is_empty());
        let guard = ComGuard {
            class_values: values(&class)?,
            server_values,
        };
        guard.validate()?;
        let value = read_value(&server, "")?;
        if let Some(value) = &value {
            value.text()?;
        }
        Ok(ComState { value, guard })
    }
    pub(crate) fn com_state(&self, clsid: &str) -> Result<ComState, String> {
        self.com_state_in(clsid, None)
    }
    pub(crate) fn exchange_com(
        &self,
        clsid: &str,
        expected: &ComState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        validate_clsid(clsid)?;
        expected.guard.validate()?;
        if expected.value.is_none() && replacement.is_none() {
            return Err("No COM mapping change was requested.".into());
        }
        for value in [expected.value.as_ref(), replacement].into_iter().flatten() {
            value.text()?;
        }
        if self.com_state(clsid)? != *expected {
            return Err("COM metadata changed. Nothing was changed.".into());
        }
        let transaction = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        if self.com_state_in(clsid, Some(&transaction))? != *expected {
            return Err(
                "The COM mapping changed before its transaction. Nothing was overwritten.".into(),
            );
        }
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let root = open(&user, &self.com_path, Some(&transaction), false)?
            .ok_or("The COM root disappeared.")?;
        let class =
            open(&root, clsid, Some(&transaction), false)?.ok_or("The COM class disappeared.")?;
        let key = open(&class, INPROC_SERVER, Some(&transaction), true)?
            .ok_or("The DLL mapping key disappeared.")?;
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
                "The COM mapping change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        transaction.commit().map_err(|error| format!("Windows did not commit the COM mapping change (Windows error {}). The backup is preserved.", error.raw_os_error().unwrap_or(0)))
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
        path: String,
        clsid: String,
        directory: tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            let token = uuid::Uuid::new_v4();
            let fixture = Self {
                path: format!(r"Software\RustRegistryTests\{token}"),
                clsid: format!("{{{token}}}"),
                directory: tempfile::tempdir().unwrap(),
            };
            let (class, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!("{}\\CLSID\\{}", fixture.path, fixture.clsid))
                .unwrap();
            class.set_value("", &"RustRegistry COM fixture").unwrap();
            let (server, _) = class.create_subkey(INPROC_SERVER).unwrap();
            let bytes = format!(
                "{}\0\0",
                fixture
                    .directory
                    .path()
                    .join("missing-server.dll")
                    .display()
            )
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
            server
                .set_raw_value(
                    "",
                    &RegValue {
                        vtype: REG_EXPAND_SZ,
                        bytes: Cow::Owned(bytes),
                    },
                )
                .unwrap();
            server.set_value("ThreadingModel", &"Both").unwrap();
            fixture
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                com_path: format!("{}\\CLSID", self.path),
                ..Default::default()
            }
        }
        fn class(&self) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(
                    format!("{}\\CLSID\\{}", self.path, self.clsid),
                    KEY_ALL_ACCESS,
                )
                .unwrap()
        }
        fn server(&self) -> RegKey {
            self.class()
                .open_subkey_with_flags(INPROC_SERVER, KEY_ALL_ACCESS)
                .unwrap()
        }
        fn entry(&self) -> RegistryEntry {
            let state = self.store().read_com(&self.clsid).unwrap();
            RegistryEntry {
                id: "fixture".into(),
                name: "RustRegistry COM fixture".into(),
                category: Category::Com,
                hive: "HKCU".into(),
                key_path: format!("{CLSID_KEY}\\{}\\{INPROC_SERVER}", self.clsid),
                view: "64".into(),
                value_name: String::new(),
                value_type: "REG_EXPAND_SZ".into(),
                raw_value: state.value.as_ref().unwrap().text().unwrap(),
                publisher: None,
                version: None,
                assessment: Assessment {
                    status: EntryStatus::Review,
                    code: "target_missing".into(),
                    explanation: "Missing fixture DLL".into(),
                    target: None,
                },
                snapshot: None,
                app_path_guard: None,
                app_path_repairable: false,
                uninstall_snapshot: None,
                uninstall_repairable: false,
                uninstall_hidden: false,
                association_state: None,
                association_repairable: false,
                com_repairable: true,
                com_state: Some(state),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.path);
        }
    }

    #[test]
    fn real_com_backup_disable_restart_restore_preserves_exact_bytes_and_metadata() {
        let fixture = Fixture::new();
        let backup_directory = tempfile::tempdir().unwrap();
        let entry = fixture.entry();
        let original = entry.com_state.clone().unwrap();
        let mut manager = ChangeManager::new(
            fixture.store(),
            backup_directory.path().join("backups"),
            LocalPathProbe,
        );
        let review = manager.prepare_quarantine(&entry).unwrap();
        assert_eq!(review.scope, "com");
        assert_eq!(review.registry_view, "64");
        assert_eq!(fixture.store().read_com(&fixture.clsid).unwrap(), original);
        assert!(!backup_directory.path().join("backups").exists());
        manager.cancel();
        assert!(manager.apply(&review.token).is_err());
        let plan = manager.prepare_quarantine(&entry).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let changed = fixture.store().read_com(&fixture.clsid).unwrap();
        assert!(changed.value.is_none());
        assert_eq!(changed.guard, original.guard);
        let path = backup_directory
            .path()
            .join("backups")
            .join(format!("{}.json", result.backup_id));
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(record["schemaVersion"], 5);
        assert_eq!(
            record["original"],
            serde_json::to_value(original.value.as_ref().unwrap()).unwrap()
        );
        drop(manager);
        let mut manager = ChangeManager::new(
            fixture.store(),
            backup_directory.path().join("backups"),
            LocalPathProbe,
        );
        assert_eq!(
            manager.inventory().unwrap().backups[0].state,
            "restore_available"
        );
        let restore = manager.prepare_restore(&result.backup_id).unwrap();
        manager.apply(&restore.token).unwrap();
        assert_eq!(fixture.store().read_com(&fixture.clsid).unwrap(), original);
    }

    #[test]
    fn com_repair_blocks_stale_mapping_alternate_activation_reappearing_dll_and_failed_backup() {
        for scenario in 0..7 {
            let fixture = Fixture::new();
            let directory = tempfile::tempdir().unwrap();
            let backups = directory.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let entry = fixture.entry();
            let plan = manager.prepare_quarantine(&entry).unwrap();
            match scenario {
                0 => fixture.server().set_value("", &"conflict.dll").unwrap(),
                1 => fixture
                    .server()
                    .set_value("ThreadingModel", &"Apartment")
                    .unwrap(),
                2 => {
                    fixture.class().create_subkey("TreatAs").unwrap();
                }
                3 => {
                    fixture.server().create_subkey("1.0").unwrap();
                }
                4 => fixture.class().set_value("AppID", &fixture.clsid).unwrap(),
                5 => std::fs::write(
                    fixture.directory.path().join("missing-server.dll"),
                    b"test fixture, never loaded",
                )
                .unwrap(),
                6 => std::fs::write(backups, b"not a directory").unwrap(),
                _ => unreachable!(),
            }
            assert!(manager.apply(&plan.token).is_err(), "scenario {scenario}");
            assert!(fixture.server().get_raw_value("").is_ok());
            if scenario == 0 {
                assert_eq!(
                    fixture.server().get_value::<String, _>("").unwrap(),
                    "conflict.dll"
                );
            }
        }
    }

    #[test]
    fn com_restore_refuses_overwrites_metadata_changes_missing_keys_and_corrupt_backup() {
        for scenario in 0..5 {
            let fixture = Fixture::new();
            let directory = tempfile::tempdir().unwrap();
            let mut manager = ChangeManager::new(
                fixture.store(),
                directory.path().join("backups"),
                LocalPathProbe,
            );
            let plan = manager.prepare_quarantine(&fixture.entry()).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            match scenario {
                0 => fixture
                    .server()
                    .set_value("", &"keep existing.dll")
                    .unwrap(),
                1 => fixture
                    .server()
                    .set_value("ThreadingModel", &"Apartment")
                    .unwrap(),
                2 => {
                    fixture.class().create_subkey("LocalServer32").unwrap();
                }
                3 => fixture.class().delete_subkey(INPROC_SERVER).unwrap(),
                4 => {
                    let path = directory
                        .path()
                        .join("backups")
                        .join(format!("{}.json", result.backup_id));
                    let mut data: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    data["com"]["clsid"] =
                        serde_json::json!("{22222222-2222-4222-8222-222222222222}");
                    std::fs::write(path, serde_json::to_vec(&data).unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                manager.prepare_restore(&result.backup_id).is_err(),
                "scenario {scenario}"
            );
            if scenario == 0 {
                assert_eq!(
                    fixture.server().get_value::<String, _>("").unwrap(),
                    "keep existing.dll"
                );
            }
        }
    }
}
