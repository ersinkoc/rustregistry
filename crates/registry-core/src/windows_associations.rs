use super::{read_value, WindowsRegistryStore};
use crate::associations::*;
use crate::changes::{NamedValue, StoredValue};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

fn open(
    parent: &RegKey,
    path: &str,
    transaction: Option<&Transaction>,
    write: bool,
) -> Result<Option<RegKey>, String> {
    let flags = KEY_READ | if write { KEY_SET_VALUE } else { 0 };
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
                return Err("Registry links are outside file association repair scope.".into());
            }
            Ok(Some(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "File association metadata could not be read (Windows error {}).",
            error.raw_os_error().unwrap_or(0)
        )),
    }
}

// HKCU Software\Classes is itself a Windows-managed link to the user's Classes hive.
// Follow that fixed root mapping; do not follow links below it.
fn classes_root(
    parent: &RegKey,
    path: &str,
    transaction: Option<&Transaction>,
) -> Result<RegKey, String> {
    let result = if let Some(transaction) = transaction {
        parent.open_subkey_transacted_with_flags(path, transaction, KEY_READ)
    } else {
        parent.open_subkey_with_flags(path, KEY_READ)
    };
    result.map_err(|_| "The Classes root could not be read completely.".into())
}

fn values(key: &RegKey, flat: bool) -> Result<Vec<NamedValue>, String> {
    if flat && key.enum_keys().next().is_some() {
        return Err("Nested or unreadable Open with metadata is outside repair scope.".into());
    }
    let mut result = Vec::new();
    let mut size = 0;
    for item in key.enum_values() {
        let (name, value) = item
            .map_err(|_| "File association metadata could not be completely read.".to_string())?;
        size += value.bytes.len();
        if result.len() >= 64 || size > 32_768 {
            return Err("File association metadata exceeds the backup limit.".into());
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
    validate_values(&result)?;
    Ok(result)
}

impl WindowsRegistryStore {
    pub(crate) fn association_registered(&self, progid: &str) -> Result<bool, String> {
        validate_progid(progid)?;
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        let user = classes_root(&user, &self.classes_path, None)?;
        let machine = classes_root(&machine, &self.machine_classes_path, None)?;
        // These allowed direct ProgID names and extension keys are shared on supported Windows.
        let user_exists = open(&user, progid, None, false)?.is_some();
        let machine_exists = open(&machine, progid, None, false)?.is_some();
        Ok(user_exists || machine_exists)
    }

    fn association_state_in(
        &self,
        extension: &str,
        progid: &str,
        transaction: Option<&Transaction>,
    ) -> Result<AssociationState, String> {
        validate_extension(extension)?;
        validate_progid(progid)?;
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
        let classes = classes_root(&user, &self.classes_path, transaction)?;
        let machine_classes = classes_root(&machine, &self.machine_classes_path, transaction)?;
        // Check both registrations, rather than assuming the merged view is complete.
        if open(&classes, progid, transaction, false)?.is_some()
            || open(&machine_classes, progid, transaction, false)?.is_some()
        {
            return Err("The application registration exists now. This suggestion cannot be repaired or restored from stale evidence.".into());
        }
        let ext = open(&classes, extension, transaction, false)?
            .ok_or("The extension key is missing. It is never recreated automatically.")?;
        let suggestions = open(&ext, OPEN_WITH, transaction, false)?
            .ok_or("The Open with key is missing. It is never recreated automatically.")?;
        let mut others = values(&suggestions, true)?;
        let value = read_value(&suggestions, progid)?;
        if let Some(value) = &value {
            validate_suggestion(value)?;
        }
        others.retain(|item| !item.name.eq_ignore_ascii_case(progid));
        let machine_ext = open(&machine_classes, extension, transaction, false)?;
        if let Some(machine_ext) = &machine_ext {
            if let Some(list) = open(machine_ext, OPEN_WITH, transaction, false)? {
                if read_value(&list, progid)?.is_some() {
                    return Err("A machine-wide suggestion with the same identifier exists. It remains read-only.".into());
                }
            }
        }
        let file_exts = open(&user, &self.file_exts_path, transaction, false)?;
        let user_extension = file_exts
            .as_ref()
            .map(|root| open(root, extension, transaction, false))
            .transpose()?
            .flatten();
        let user_choice = user_extension
            .as_ref()
            .map(|root| open(root, "UserChoice", transaction, false))
            .transpose()?
            .flatten();
        let guard = AssociationGuard {
            suggestions: others,
            extension_values: values(&ext, false)?,
            machine_extension_values: machine_ext
                .as_ref()
                .map(|key| values(key, false))
                .transpose()?,
            user_choice: user_choice
                .as_ref()
                .map(|key| values(key, true))
                .transpose()?,
        };
        guard.validate(progid)?;
        Ok(AssociationState { value, guard })
    }

    pub(crate) fn association_state(
        &self,
        extension: &str,
        progid: &str,
    ) -> Result<AssociationState, String> {
        self.association_state_in(extension, progid, None)
    }

    pub(crate) fn exchange_association(
        &self,
        extension: &str,
        progid: &str,
        expected: &AssociationState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        expected.guard.validate(progid)?;
        for value in [expected.value.as_ref(), replacement].into_iter().flatten() {
            validate_suggestion(value)?;
        }
        if expected.value.is_none() && replacement.is_none() {
            return Err("No suggestion change was requested.".into());
        }
        if self.association_state(extension, progid)? != *expected {
            return Err("The file association changed. Nothing was changed.".into());
        }
        let transaction = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        if self.association_state_in(extension, progid, Some(&transaction))? != *expected {
            return Err(
                "The file association changed before its transaction. Nothing was overwritten."
                    .into(),
            );
        }
        // Reopen each existing parent without following registry links. Only this final handle has write access.
        let user = RegKey::predef(HKEY_CURRENT_USER);
        let classes = classes_root(&user, &self.classes_path, Some(&transaction))?;
        let ext = open(&classes, extension, Some(&transaction), false)?
            .ok_or("Extension key missing.")?;
        let key =
            open(&ext, OPEN_WITH, Some(&transaction), true)?.ok_or("Open with key missing.")?;
        match replacement {
            Some(value) => key.set_raw_value(
                progid,
                &RegValue {
                    bytes: Cow::Borrowed(&value.bytes),
                    vtype: if value.kind == 0 { REG_NONE } else { REG_SZ },
                },
            ),
            None => key.delete_value(progid),
        }
        .map_err(|error| {
            format!(
                "The Open with change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        transaction.commit().map_err(|error| format!("Windows did not commit the Open with change (Windows error {}). The backup is preserved.", error.raw_os_error().unwrap_or(0)))
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
        extension: String,
        progid: String,
    }
    impl Fixture {
        fn new(kind: u32) -> Self {
            let token = uuid::Uuid::new_v4().simple().to_string();
            let result = Self {
                path: format!(r"Software\RustRegistryTests\{token}"),
                extension: format!(".rr{token}"),
                progid: format!("RustRegistry.Test.{token}"),
            };
            let root = RegKey::predef(HKEY_CURRENT_USER);
            let (ext, _) = root
                .create_subkey(format!("{}\\Classes\\{}", result.path, result.extension))
                .unwrap();
            ext.set_value("", &"RustRegistry.KeepDefault").unwrap();
            ext.set_value("RustRegistryFixture", &token).unwrap();
            let (list, _) = ext.create_subkey(OPEN_WITH).unwrap();
            list.set_raw_value(
                &result.progid,
                &RegValue {
                    vtype: if kind == 0 { REG_NONE } else { REG_SZ },
                    bytes: Cow::Owned(if kind == 0 { vec![] } else { vec![0, 0] }),
                },
            )
            .unwrap();
            list.set_raw_value(
                "RustRegistry.KeepSuggestion",
                &RegValue {
                    vtype: REG_NONE,
                    bytes: Cow::Owned(vec![]),
                },
            )
            .unwrap();
            let (choice, _) = root
                .create_subkey(format!(
                    "{}\\FileExts\\{}\\UserChoice",
                    result.path, result.extension
                ))
                .unwrap();
            choice
                .set_value("ProgId", &"RustRegistry.OtherDefault")
                .unwrap();
            choice
                .set_value(
                    "Hash",
                    &"Isolated test evidence; never a real Windows selection",
                )
                .unwrap();
            result
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                classes_path: format!("{}\\Classes", self.path),
                file_exts_path: format!("{}\\FileExts", self.path),
                ..Default::default()
            }
        }
        fn list(&self) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(
                    format!("{}\\Classes\\{}\\{OPEN_WITH}", self.path, self.extension),
                    KEY_ALL_ACCESS,
                )
                .unwrap()
        }
        fn entry(&self) -> RegistryEntry {
            let state = self
                .store()
                .read_association(&self.extension, &self.progid)
                .unwrap();
            RegistryEntry {
                id: "fixture".into(),
                name: format!("{} · {}", self.extension, self.progid),
                category: Category::FileAssociations,
                hive: "HKCU".into(),
                key_path: format!("{CLASSES_KEY}\\{}\\{OPEN_WITH}", self.extension),
                view: "shared".into(),
                value_name: self.progid.clone(),
                value_type: if state.value.as_ref().unwrap().kind == 0 {
                    "REG_NONE"
                } else {
                    "REG_SZ"
                }
                .into(),
                raw_value: "(empty)".into(),
                publisher: None,
                version: None,
                assessment: Assessment {
                    status: EntryStatus::Review,
                    code: "progid_missing".into(),
                    explanation: "Fixture registration missing".into(),
                    target: None,
                },
                snapshot: None,
                app_path_guard: None,
                app_path_repairable: false,
                uninstall_snapshot: None,
                uninstall_repairable: false,
                uninstall_hidden: false,
                association_state: Some(state),
                association_repairable: true,
                com_state: None,
                com_repairable: false,
                service_state: None,
                application_snapshot: None,
                application_repairable: false,
                application_hidden: false,
                shared_dll_repairable: false,
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
                service_repairable: false,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.path);
        }
    }

    #[test]
    fn suggestion_backup_repair_restart_restore_preserve_exact_type_metadata_and_defaults() {
        for kind in [0, 1] {
            let fixture = Fixture::new(kind);
            let directory = tempfile::tempdir().unwrap();
            let entry = fixture.entry();
            let original = entry.association_state.clone().unwrap();
            let mut manager = ChangeManager::new(
                fixture.store(),
                directory.path().join("backups"),
                LocalPathProbe,
            );
            let review = manager.prepare_quarantine(&entry).unwrap();
            assert_eq!(review.scope, "association");
            assert_eq!(
                fixture
                    .store()
                    .read_association(&fixture.extension, &fixture.progid)
                    .unwrap(),
                original
            );
            assert!(!directory.path().join("backups").exists());
            manager.cancel();
            assert!(manager.apply(&review.token).is_err());
            let plan = manager.prepare_quarantine(&entry).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            let repaired = fixture
                .store()
                .read_association(&fixture.extension, &fixture.progid)
                .unwrap();
            assert!(repaired.value.is_none());
            assert_eq!(repaired.guard, original.guard);
            let backup_path = directory
                .path()
                .join("backups")
                .join(format!("{}.json", result.backup_id));
            let backup: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&backup_path).unwrap()).unwrap();
            assert_eq!(backup["schemaVersion"], 4);
            assert_eq!(
                backup["original"],
                serde_json::to_value(original.value.as_ref().unwrap()).unwrap()
            );
            drop(manager);
            let mut manager = ChangeManager::new(
                fixture.store(),
                directory.path().join("backups"),
                LocalPathProbe,
            );
            assert_eq!(
                manager.inventory().unwrap().backups[0].state,
                "restore_available"
            );
            let restore = manager.prepare_restore(&result.backup_id).unwrap();
            manager.apply(&restore.token).unwrap();
            assert_eq!(
                fixture
                    .store()
                    .read_association(&fixture.extension, &fixture.progid)
                    .unwrap(),
                original
            );
        }
    }

    #[test]
    fn suggestion_repair_blocks_stale_values_new_registrations_defaults_children_and_backup_failure(
    ) {
        for scenario in 0..6 {
            let fixture = Fixture::new(0);
            let directory = tempfile::tempdir().unwrap();
            let entry = fixture.entry();
            let backups = directory.path().join("backups");
            let mut manager = ChangeManager::new(fixture.store(), backups.clone(), LocalPathProbe);
            let review = manager.prepare_quarantine(&entry).unwrap();
            let root = RegKey::predef(HKEY_CURRENT_USER);
            match scenario {
                0 => fixture
                    .list()
                    .set_value(&fixture.progid, &"conflict")
                    .unwrap(),
                1 => {
                    root.create_subkey(format!("{}\\Classes\\{}", fixture.path, fixture.progid))
                        .unwrap();
                }
                2 => {
                    let (key, _) = root
                        .create_subkey(format!("{}\\Classes\\{}", fixture.path, fixture.extension))
                        .unwrap();
                    key.set_value("", &fixture.progid).unwrap();
                }
                3 => {
                    fixture.list().create_subkey("Nested").unwrap();
                }
                4 => std::fs::write(&backups, b"not a directory").unwrap(),
                5 => {
                    let (key, _) = root
                        .create_subkey(format!(
                            "{}\\FileExts\\{}\\UserChoice",
                            fixture.path, fixture.extension
                        ))
                        .unwrap();
                    key.set_value("ProgId", &fixture.progid).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(manager.apply(&review.token).is_err(), "scenario {scenario}");
            assert!(fixture.list().get_raw_value(&fixture.progid).is_ok());
        }
    }

    #[test]
    fn suggestion_restore_refuses_conflicts_selection_changes_tampering_and_missing_keys() {
        for scenario in 0..5 {
            let fixture = Fixture::new(1);
            let directory = tempfile::tempdir().unwrap();
            let mut manager = ChangeManager::new(
                fixture.store(),
                directory.path().join("backups"),
                LocalPathProbe,
            );
            let plan = manager.prepare_quarantine(&fixture.entry()).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            let root = RegKey::predef(HKEY_CURRENT_USER);
            match scenario {
                0 => fixture
                    .list()
                    .set_value(&fixture.progid, &"keep existing")
                    .unwrap(),
                1 => fixture
                    .list()
                    .set_value("RustRegistry.KeepSuggestion", &"changed")
                    .unwrap(),
                2 => {
                    let (key, _) = root
                        .create_subkey(format!(
                            "{}\\FileExts\\{}\\UserChoice",
                            fixture.path, fixture.extension
                        ))
                        .unwrap();
                    key.set_value("ProgId", &"Other.Selection").unwrap();
                }
                3 => {
                    let path = directory
                        .path()
                        .join("backups")
                        .join(format!("{}.json", result.backup_id));
                    let mut data: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                    data["association"]["extension"] = serde_json::json!(".different");
                    std::fs::write(path, serde_json::to_vec(&data).unwrap()).unwrap();
                }
                4 => root
                    .delete_subkey_all(format!(
                        "{}\\Classes\\{}\\{OPEN_WITH}",
                        fixture.path, fixture.extension
                    ))
                    .unwrap(),
                _ => unreachable!(),
            }
            assert!(
                manager.prepare_restore(&result.backup_id).is_err(),
                "scenario {scenario}"
            );
            if scenario == 0 {
                assert_eq!(
                    fixture
                        .list()
                        .get_value::<String, _>(&fixture.progid)
                        .unwrap(),
                    "keep existing"
                );
            }
        }
    }
}
