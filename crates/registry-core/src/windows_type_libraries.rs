use super::{read_value, WindowsRegistryStore};
use crate::{
    changes::{NamedValue, StoredValue},
    type_libraries::*,
};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

pub(crate) fn open_type_lib(
    parent: &RegKey,
    path: &str,
    tx: Option<&Transaction>,
    write: bool,
) -> Result<Option<RegKey>, String> {
    let access = KEY_READ | KEY_WOW64_64KEY | if write { KEY_SET_VALUE } else { 0 };
    let result = if let Some(tx) = tx {
        parent.open_subkey_transacted_with_options_flags(path, tx, REG_OPTION_OPEN_LINK, access)
    } else {
        parent.open_subkey_with_options_flags(path, REG_OPTION_OPEN_LINK, access)
    };
    match result {
        Ok(key) => {
            if read_value(&key, "SymbolicLinkValue")?.is_some_and(|v| v.kind == 6) {
                return Err("Type library registry links remain outside recovery scope.".into());
            }
            Ok(Some(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "Type library evidence could not be read (Windows error {}).",
            error.raw_os_error().unwrap_or(0)
        )),
    }
}
fn required(
    parent: &RegKey,
    path: &str,
    tx: Option<&Transaction>,
    write: bool,
) -> Result<RegKey, String> {
    open_type_lib(parent, path, tx, write)?
        .ok_or("An existing type library key is missing; it will not be recreated.".into())
}
fn children(key: &RegKey) -> Result<Vec<String>, String> {
    let names: Vec<_> = key
        .enum_keys()
        .take(9)
        .collect::<Result<_, _>>()
        .map_err(|_| "Type library children could not be fully read.")?;
    if names.len() > 8 {
        return Err("Complex type library registrations remain read-only.".into());
    }
    Ok(names)
}
fn values(key: &RegKey) -> Result<Vec<NamedValue>, String> {
    let mut result = Vec::new();
    let mut bytes = 0;
    for item in key.enum_values() {
        let (name, value) = item.map_err(|_| "Type library metadata could not be read.")?;
        bytes += value.bytes.len();
        if result.len() >= 8 || bytes > 16384 {
            return Err("Type library metadata exceeds backup bounds.".into());
        }
        result.push(NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        });
    }
    result.sort_by_key(|v| v.name.to_ascii_lowercase());
    Ok(result)
}
impl WindowsRegistryStore {
    fn type_lib_roots(&self, tx: Option<&Transaction>) -> Result<(RegKey, RegKey), String> {
        let user = required(
            &RegKey::predef(HKEY_CURRENT_USER),
            &self.type_lib_path,
            tx,
            false,
        )?;
        #[cfg(test)]
        let machine_hive = if self.type_lib_test_machine_user {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        };
        #[cfg(not(test))]
        let machine_hive = HKEY_LOCAL_MACHINE;
        let machine = required(
            &RegKey::predef(machine_hive),
            &self.machine_type_lib_path,
            tx,
            false,
        )?;
        Ok((user, machine))
    }
    fn type_lib_leaf(
        &self,
        app: &TypeLibBackup,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<RegKey, String> {
        app.validate()?;
        let (user, machine) = self.type_lib_roots(tx)?;
        if open_type_lib(&machine, &app.library_id, tx, false)?.is_some() {
            return Err("A machine registration exists for this type library; changing fallback is outside recovery scope.".into());
        }
        let library = required(&user, &app.library_id, tx, false)?;
        let version = required(&library, &app.version, tx, false)?;
        let locale = required(&version, "0", tx, false)?;
        required(&locale, "win64", tx, write)
    }
    fn type_lib_state_in(
        &self,
        app: &TypeLibBackup,
        tx: Option<&Transaction>,
    ) -> Result<TypeLibState, String> {
        app.validate()?;
        let (user, machine) = self.type_lib_roots(tx)?;
        if open_type_lib(&machine, &app.library_id, tx, false)?.is_some() {
            return Err("A machine registration exists for this type library; changing fallback is outside recovery scope.".into());
        }
        let library = required(&user, &app.library_id, tx, false)?;
        let versions = children(&library)?;
        if versions.len() != 1 || !versions[0].eq_ignore_ascii_case(&app.version) {
            return Err("Only one-version neutral type libraries support recovery.".into());
        }
        let version = required(&library, &app.version, tx, false)?;
        let version_children = children(&version)?;
        if !version_children.iter().any(|n| n == "0")
            || version_children.iter().any(|n| {
                n != "0" && !n.eq_ignore_ascii_case("FLAGS") && !n.eq_ignore_ascii_case("HELPDIR")
            })
        {
            return Err(
                "Multiple locales or unknown type library metadata remain read-only.".into(),
            );
        }
        let locale = required(&version, "0", tx, false)?;
        let platforms = children(&locale)?;
        if !platforms.iter().any(|n| n.eq_ignore_ascii_case("win64"))
            || platforms
                .iter()
                .any(|n| !n.eq_ignore_ascii_case("win32") && !n.eq_ignore_ascii_case("win64"))
        {
            return Err("Unsupported type library platform structure.".into());
        }
        let leaf = required(&locale, "win64", tx, false)?;
        if !children(&leaf)?.is_empty() {
            return Err("Nested type library platform keys remain read-only.".into());
        }
        let value = read_value(&leaf, "")?;
        let mut leaf_values = values(&leaf)?;
        leaf_values.retain(|v| !v.name.is_empty());
        let mut nodes = vec![
            TypeLibNode {
                path: String::new(),
                values: values(&library)?,
            },
            TypeLibNode {
                path: app.version.clone(),
                values: values(&version)?,
            },
            TypeLibNode {
                path: format!(r"{}\0", app.version),
                values: values(&locale)?,
            },
            TypeLibNode {
                path: format!(r"{}\0\win64", app.version),
                values: leaf_values,
            },
        ];
        for (parent, name, path) in [
            (&version, "FLAGS", format!(r"{}\FLAGS", app.version)),
            (&version, "HELPDIR", format!(r"{}\HELPDIR", app.version)),
            (&locale, "win32", format!(r"{}\0\win32", app.version)),
        ] {
            if let Some(key) = open_type_lib(parent, name, tx, false)? {
                if !children(&key)?.is_empty() {
                    return Err("Nested type library metadata remains read-only.".into());
                }
                nodes.push(TypeLibNode {
                    path,
                    values: values(&key)?,
                });
            }
        }
        nodes.sort_by_key(|n| n.path.to_ascii_lowercase());
        let guard = TypeLibGuard { nodes };
        guard.validate(&app.version)?;
        if let Some(value) = &value {
            value.text()?;
        }
        Ok(TypeLibState { value, guard })
    }
    pub(crate) fn type_lib_state(&self, app: &TypeLibBackup) -> Result<TypeLibState, String> {
        self.type_lib_state_in(app, None)
    }
    pub(crate) fn type_lib_write_access(&self, app: &TypeLibBackup) -> Result<(), String> {
        self.type_lib_leaf(app, None, true).map(|_| ())
    }
    pub(crate) fn exchange_type_lib(
        &self,
        app: &TypeLibBackup,
        expected: &TypeLibState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        app.validate()?;
        if expected.value.is_some() == replacement.is_some() || expected.guard != app.guard {
            return Err(
                "Only exact type library mapping removal or restoration supports recovery.".into(),
            );
        }
        verify_missing_library(
            expected
                .value
                .as_ref()
                .or(replacement)
                .ok_or("Missing type library evidence.")?,
            &crate::LocalPathProbe,
        )?;
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.type_lib_state_in(app, Some(&tx))? != *expected {
            return Err("Type library metadata changed. Nothing was overwritten.".into());
        }
        let key = self.type_lib_leaf(app, Some(&tx), true)?;
        verify_missing_library(
            expected
                .value
                .as_ref()
                .or(replacement)
                .ok_or("Missing type library evidence.")?,
            &crate::LocalPathProbe,
        )?;
        match replacement {
            Some(value) => key.set_raw_value(
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
            None => key.delete_value(""),
        }
        .map_err(|e| format!("Type library mapping update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Type library transaction did not commit: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{ChangeManager, RegistryStore},
        LocalPathProbe, RegistryEntry,
    };
    pub(super) struct Fixture {
        base: String,
        ids: [String; 2],
        files: tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            let token = uuid::Uuid::new_v4();
            let fixture = Self {
                base: format!(r"Software\RustRegistryTests\{token}"),
                ids: [
                    format!("{{{}}}", uuid::Uuid::new_v4()),
                    format!("{{{}}}", uuid::Uuid::new_v4()),
                ],
                files: tempfile::tempdir().unwrap(),
            };
            let (root, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\User", fixture.base))
                .unwrap();
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\Machine", fixture.base))
                .unwrap();
            for (index, id) in fixture.ids.iter().enumerate() {
                let (library, _) = root.create_subkey(id).unwrap();
                library.set_value("", &"Owned type library").unwrap();
                let (version, _) = library.create_subkey("1.0").unwrap();
                version
                    .set_value("", &"Owned type library version")
                    .unwrap();
                version
                    .create_subkey("FLAGS")
                    .unwrap()
                    .0
                    .set_value("", &"0")
                    .unwrap();
                version
                    .create_subkey("HELPDIR")
                    .unwrap()
                    .0
                    .set_value("", &r"C:\Original Help")
                    .unwrap();
                let (locale, _) = version.create_subkey("0").unwrap();
                locale
                    .create_subkey("win32")
                    .unwrap()
                    .0
                    .set_value("", &r"%DO_NOT_RESOLVE%\preserve-win32.dll")
                    .unwrap();
                let original = fixture.original(index);
                locale
                    .create_subkey("win64")
                    .unwrap()
                    .0
                    .set_raw_value(
                        "",
                        &RegValue {
                            vtype: REG_EXPAND_SZ,
                            bytes: Cow::Owned(original.bytes),
                        },
                    )
                    .unwrap();
            }
            fixture
        }
        fn file(&self, index: usize) -> String {
            self.files
                .path()
                .join(if index == 0 {
                    "missing.tlb"
                } else {
                    "missing.olb"
                })
                .display()
                .to_string()
        }
        fn original(&self, index: usize) -> StoredValue {
            StoredValue {
                kind: 2,
                bytes: self
                    .file(index)
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
                        self.ids[index],
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
                type_lib_path: format!(r"{}\User", self.base),
                machine_type_lib_path: format!(r"{}\Machine", self.base),
                type_lib_test_machine_user: true,
                ..Default::default()
            }
        }
        fn selector(&self, index: usize) -> TypeLibBackup {
            TypeLibBackup::selector(&self.ids[index], "1.0")
        }
        fn entry(&self, index: usize) -> RegistryEntry {
            let mut entry:RegistryEntry=serde_json::from_value(serde_json::json!({"id":self.ids[index],"name":self.ids[index],"category":"type_libraries","hive":"HKCU","view":"shared","keyPath":format!(r"{TYPE_LIB_KEY}\{}\1.0\0\win64",self.ids[index]),"valueName":"","valueType":"REG_EXPAND_SZ","rawValue":self.file(index),"publisher":null,"version":null,"assessment":{"status":"review","code":"target_missing","explanation":"Owned missing library","target":self.file(index)},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"typeLibraryRepairable":true})).unwrap();
            entry.type_library_state = Some(
                self.store()
                    .read_type_library(&self.selector(index))
                    .unwrap(),
            );
            entry
        }
        fn machine_counterpart(&self) {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\Machine\{}", self.base, self.ids[0]))
                .unwrap();
        }
        fn assert_other(&self) {
            assert_eq!(
                read_value(&self.key(1, r"1.0\0\win64"), "").unwrap(),
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
    fn type_library_quick_and_selected_clean_back_up_restart_and_restore_exact_mappings_and_metadata(
    ) {
        for mode in ["quick", "selected"] {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let entries = [fixture.entry(0), fixture.entry(1)];
            let initial: [TypeLibState; 2] = [
                entries[0].type_library_state.clone().unwrap(),
                entries[1].type_library_state.clone().unwrap(),
            ];
            assert!(entries.iter().all(crate::changes::is_repair_candidate));
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            assert_eq!(plan.items.len(), 2);
            assert!(plan.items.iter().all(|item| item.preserved_values == 5));
            assert!(plan.skipped.is_empty());
            assert!(!backups.exists());
            manager.cancel();
            assert!(manager.apply_clean(&plan.token).is_err());
            let plan = manager.prepare_clean(&entries, mode).unwrap();
            let result = manager.apply_clean(&plan.token).unwrap();
            assert!(result.failed.is_none());
            assert_eq!(result.completed.len(), 2);
            for (index, original) in initial.iter().enumerate() {
                let state = fixture
                    .store()
                    .read_type_library(&fixture.selector(index))
                    .unwrap();
                assert!(state.value.is_none());
                assert_eq!(state.guard, original.guard);
            }
            drop(manager);
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            assert!(manager
                .inventory()
                .unwrap()
                .backups
                .iter()
                .all(|b| b.scope == "type_library" && b.state == "restore_available"));
            for (index, result) in result.completed.iter().enumerate() {
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(backups.join(format!("{}.json", result.backup_id))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["schemaVersion"], 11);
                assert_eq!(record["typeLibrary"]["platform"], "win64");
                assert_eq!(record["typeLibrary"]["locale"], "0");
                assert_eq!(
                    record["original"],
                    serde_json::to_value(fixture.original(index)).unwrap()
                );
                let restore = manager.prepare_restore(&result.backup_id).unwrap();
                manager.apply(&restore.token).unwrap();
                assert_eq!(
                    fixture
                        .store()
                        .read_type_library(&fixture.selector(index))
                        .unwrap(),
                    initial[index]
                );
            }
        }
    }

    #[test]
    fn type_library_repair_blocks_files_counterparts_changed_metadata_unknown_structure_missing_keys_and_backup_failure(
    ) {
        for scenario in 0..10 {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager.prepare_quarantine(&fixture.entry(0)).unwrap();
            match scenario {
                0 => std::fs::write(fixture.file(0), b"inert; never load").unwrap(),
                1 => fixture.machine_counterpart(),
                2 => fixture
                    .key(0, r"1.0\0\win32")
                    .set_value("", &"changed win32 metadata")
                    .unwrap(),
                3 => fixture
                    .key(0, "1.0")
                    .set_value("", &"changed description")
                    .unwrap(),
                4 => {
                    fixture.key(0, "").create_subkey("2.0").unwrap();
                }
                5 => {
                    fixture.key(0, "1.0").create_subkey("409").unwrap();
                }
                6 => {
                    fixture
                        .key(0, r"1.0\0\win64")
                        .create_subkey("Unexpected")
                        .unwrap();
                }
                7 => fixture.key(0, r"1.0\0").delete_subkey("win64").unwrap(),
                8 => std::fs::write(&backups, b"not a directory").unwrap(),
                9 => fixture
                    .key(0, r"1.0\0\win64")
                    .set_value("Unknown", &"preserve")
                    .unwrap(),
                _ => unreachable!(),
            }
            assert!(manager.apply(&plan.token).is_err(), "scenario {scenario}");
            fixture.assert_other();
            if scenario != 7 {
                assert_eq!(
                    read_value(&fixture.key(0, r"1.0\0\win64"), "").unwrap(),
                    Some(fixture.original(0))
                );
            } else {
                assert!(fixture.key(0, r"1.0\0").open_subkey("win64").is_err());
            }
            if scenario == 0 {
                assert_eq!(
                    std::fs::read(fixture.file(0)).unwrap(),
                    b"inert; never load"
                );
            }
        }
    }

    #[test]
    fn type_library_restore_refuses_replacement_new_files_metadata_missing_keys_and_corrupted_backup_selectors(
    ) {
        for scenario in 0..10 {
            let fixture = Fixture::new();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let plan = manager.prepare_quarantine(&fixture.entry(0)).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            let restore = manager.prepare_restore(&result.backup_id).unwrap();
            match scenario {
                0 => fixture
                    .key(0, r"1.0\0\win64")
                    .set_value("", &"new mapping")
                    .unwrap(),
                1 => std::fs::write(fixture.file(0), b"inert; never load").unwrap(),
                2 => fixture.machine_counterpart(),
                3 => fixture
                    .key(0, r"1.0\HELPDIR")
                    .set_value("", &"changed help metadata")
                    .unwrap(),
                4 => fixture
                    .key(0, r"1.0\0\win32")
                    .set_value("", &"changed win32")
                    .unwrap(),
                5 => fixture.key(0, r"1.0\0").delete_subkey("win64").unwrap(),
                6..=9 => {
                    let path = backups.join(format!("{}.json", result.backup_id));
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    match scenario {
                        6 => record["typeLibrary"]["platform"] = serde_json::json!("win32"),
                        7 => record["typeLibrary"]["version"] = serde_json::json!("2.0"),
                        8 => {
                            record["typeLibrary"]["guard"]["nodes"][0]["path"] =
                                serde_json::json!("Unexpected")
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
                        .key(0, r"1.0\0\win64")
                        .get_value::<String, _>("")
                        .unwrap(),
                    "new mapping"
                );
            } else if scenario != 5 {
                assert!(read_value(&fixture.key(0, r"1.0\0\win64"), "")
                    .unwrap()
                    .is_none());
            } else {
                assert!(fixture.key(0, r"1.0\0").open_subkey("win64").is_err());
            }
        }
    }

    #[test]
    fn type_library_batch_stops_at_conflict_and_keeps_completed_mapping_individually_restorable() {
        let fixture = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let mut manager =
            ChangeManager::new(fixture.store(), dir.path().join("backups"), LocalPathProbe);
        let plan = manager
            .prepare_clean(&[fixture.entry(0), fixture.entry(1)], "quick")
            .unwrap();
        fixture
            .key(1, r"1.0\FLAGS")
            .set_value("", &"changed")
            .unwrap();
        let result = manager.apply_clean(&plan.token).unwrap();
        assert_eq!(result.completed.len(), 1);
        assert!(result.failed.is_some());
        assert_eq!(result.not_attempted, 0);
        assert!(read_value(&fixture.key(0, r"1.0\0\win64"), "")
            .unwrap()
            .is_none());
        fixture.assert_other();
        let restore = manager
            .prepare_restore(&result.completed[0].backup_id)
            .unwrap();
        manager.apply(&restore.token).unwrap();
        assert_eq!(
            read_value(&fixture.key(0, r"1.0\0\win64"), "").unwrap(),
            Some(fixture.original(0))
        );
    }

    #[test]
    fn type_library_review_requires_existing_write_access_before_any_backup_or_mutation() {
        struct ReadOnly(WindowsRegistryStore);
        impl RegistryStore for ReadOnly {
            fn read_type_library(&self, app: &TypeLibBackup) -> Result<TypeLibState, String> {
                self.0.read_type_library(app)
            }
            fn check_type_library_write_access(&self, _: &TypeLibBackup) -> Result<(), String> {
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
            .prepare_quarantine(&fixture.entry(0))
            .unwrap_err()
            .contains("write access"));
        assert!(!backups.exists());
        fixture.assert_other();
        assert_eq!(
            read_value(&fixture.key(0, r"1.0\0\win64"), "").unwrap(),
            Some(fixture.original(0))
        );
    }
}
