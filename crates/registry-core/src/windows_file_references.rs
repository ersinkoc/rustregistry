use super::{open_registration_path, read_value, WindowsRegistryStore};
use crate::{changes::StoredValue, file_references::*};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

impl WindowsRegistryStore {
    fn file_reference_root(
        &self,
        location: FileReferenceLocation,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<RegKey, String> {
        #[cfg(test)]
        let fake = self
            .file_reference_test_root
            .as_ref()
            .map(|p| format!(r"{p}\{:?}", location));
        #[cfg(test)]
        let (hive, path) = if let Some(path) = fake.as_deref() {
            (HKEY_CURRENT_USER, path)
        } else {
            (
                if location.font() {
                    HKEY_CURRENT_USER
                } else {
                    HKEY_LOCAL_MACHINE
                },
                location.path(),
            )
        };
        #[cfg(not(test))]
        let (hive, path) = (
            if location.font() {
                HKEY_CURRENT_USER
            } else {
                HKEY_LOCAL_MACHINE
            },
            location.path(),
        );
        open_registration_path(
            hive,
            path,
            if location.view() == "32" {
                KEY_WOW64_32KEY
            } else {
                KEY_WOW64_64KEY
            },
            tx,
            write,
        )?
        .ok_or("The existing font/help key is missing; no key will be recreated.".into())
    }
    fn verify_font_counterpart(
        &self,
        app: &FileReferenceBackup,
        tx: Option<&Transaction>,
    ) -> Result<(), String> {
        if !app.location.font() {
            return Ok(());
        }
        #[cfg(test)]
        let fake = self
            .file_reference_test_root
            .as_ref()
            .map(|p| format!(r"{p}\MachineFonts"));
        #[cfg(test)]
        let (hive, path) = if let Some(path) = fake.as_deref() {
            (HKEY_CURRENT_USER, path)
        } else {
            (HKEY_LOCAL_MACHINE, FONTS_KEY)
        };
        #[cfg(not(test))]
        let (hive, path) = (HKEY_LOCAL_MACHINE, FONTS_KEY);
        if let Some(root) = open_registration_path(hive, path, KEY_WOW64_64KEY, tx, false)? {
            let identities = font_identities(&app.name);
            for (index, item) in root.enum_values().enumerate() {
                if index >= 10000 {
                    return Err("Machine font-name evidence exceeds the verification limit.".into());
                }
                let (name, _) = item.map_err(|_| "Machine font-name evidence is unreadable.")?;
                if font_identities(&name)
                    .iter()
                    .any(|n| identities.contains(n))
                {
                    return Err("A matching machine font name exists. Per-user fallback changes remain outside repair scope.".into());
                }
            }
        }
        Ok(())
    }
    fn file_reference_in(
        &self,
        app: &FileReferenceBackup,
        tx: Option<&Transaction>,
    ) -> Result<Option<StoredValue>, String> {
        app.validate()?;
        self.verify_font_counterpart(app, tx)?;
        read_value(
            &self.file_reference_root(app.location, tx, false)?,
            &app.name,
        )
    }
    pub(crate) fn file_reference_state(
        &self,
        app: &FileReferenceBackup,
    ) -> Result<Option<StoredValue>, String> {
        self.file_reference_in(app, None)
    }
    pub(crate) fn file_reference_access(&self, app: &FileReferenceBackup) -> Result<(), String> {
        app.validate()?;
        self.verify_font_counterpart(app, None)?;
        self.file_reference_root(app.location, None, true)
            .map(|_| ())
    }
    pub(crate) fn exchange_file_reference(
        &self,
        app: &FileReferenceBackup,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        app.validate()?;
        if expected.is_some() == replacement.is_some() {
            return Err(
                "Only exact removal or restoration of one font/help mapping is supported.".into(),
            );
        }
        let original = expected
            .or(replacement)
            .ok_or("Original file reference is absent.")?;
        if FileReferenceBackup::from_original(app.location, &app.name, original)? != *app {
            return Err("Font/help target evidence does not match.".into());
        }
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.file_reference_in(app, Some(&tx))?.as_ref() != expected {
            return Err("The font/help mapping changed. No existing value was overwritten.".into());
        }
        let key = self.file_reference_root(app.location, Some(&tx), true)?;
        match replacement {
            Some(value) => key.set_raw_value(
                &app.name,
                &RegValue {
                    vtype: REG_SZ,
                    bytes: Cow::Borrowed(&value.bytes),
                },
            ),
            None => key.delete_value(&app.name),
        }
        .map_err(|e| format!("Font/help registry update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Font/help transaction did not commit: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{ChangeManager, RegistryStore},
        PathProbe, ProbeResult, RegistryEntry, TargetKind,
    };
    struct Missing;
    impl PathProbe for Missing {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            ProbeResult::Missing
        }
    }
    struct Fixture {
        base: String,
    }
    impl Fixture {
        fn new() -> Self {
            Self {
                base: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
            }
        }
        fn key(&self, location: FileReferenceLocation) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\{:?}", self.base, location))
                .unwrap()
                .0
        }
        fn machine(&self) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\MachineFonts", self.base))
                .unwrap()
                .0
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                file_reference_test_root: Some(self.base.clone()),
                ..Default::default()
            }
        }
        fn put(&self, location: FileReferenceLocation, name: &str, value: &StoredValue) {
            self.key(location)
                .set_raw_value(
                    name,
                    &RegValue {
                        vtype: REG_SZ,
                        bytes: Cow::Borrowed(&value.bytes),
                    },
                )
                .unwrap();
        }
        fn registration(
            &self,
            location: FileReferenceLocation,
            index: usize,
        ) -> (FileReferenceBackup, StoredValue) {
            let name = if location.font() {
                format!("Owned Custom Font {index} (TrueType)")
            } else {
                format!("owned{index}{}", location.extension())
            };
            let text = if location.font() {
                format!(r"C:\RustRegistryMissing\font{index}.ttf")
            } else {
                format!(r"C:\RustRegistryMissing\{:?}\dir{index}\", location)
            };
            let original = StoredValue {
                kind: 1,
                bytes: text
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            };
            self.put(location, &name, &original);
            let app = FileReferenceBackup::from_original(location, &name, &original).unwrap();
            (app, original)
        }
        fn entry(&self, app: FileReferenceBackup, original: StoredValue) -> RegistryEntry {
            let mut e:RegistryEntry=serde_json::from_value(serde_json::json!({"id":format!("{:?}|{}",app.location,app.name),"name":app.name,"category":if app.location.font(){"fonts"}else{"help_files"},"hive":app.location.hive(),"keyPath":app.location.path(),"view":app.location.view(),"valueName":app.name,"valueType":"REG_SZ","rawValue":original.text().unwrap(),"publisher":null,"version":null,"assessment":{"status":"review","code":if app.location.font(){"font_file_missing"}else{"help_file_missing"},"explanation":"Owned missing file","target":app.target},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"fileReferenceRepairable":true})).unwrap();
            e.snapshot = Some(original);
            e.file_reference = Some(app);
            e
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.base);
        }
    }
    const LOCATIONS: [FileReferenceLocation; 5] = [
        FileReferenceLocation::UserFont,
        FileReferenceLocation::HtmlHelp64,
        FileReferenceLocation::HtmlHelp32,
        FileReferenceLocation::WinHelp64,
        FileReferenceLocation::WinHelp32,
    ];
    #[test]
    fn restores_frozen_schema20_history_backup_without_migration_or_stored_command_execution() {
        struct NoProbe;
        impl PathProbe for NoProbe {
            fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
                panic!("History must not probe or execute stored commands")
            }
        }
        let f = Fixture::new();
        let prefix = format!(r"{}\LegacyMaintenance", f.base);
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"{prefix}\run_history"))
            .unwrap()
            .0;
        key.set_raw_value(
            "",
            &RegValue {
                vtype: REG_SZ,
                bytes: Cow::Owned(vec![0, 0, 0, 0]),
            },
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let bytes = include_bytes!("../tests/fixtures/history-backup-v20.json");
        let record: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let id = record["id"].as_str().unwrap();
        let app: crate::maintenance::MaintenanceBackup =
            serde_json::from_value(record["maintenance"].clone()).unwrap();
        let file = dir.path().join(format!("{id}.json"));
        std::fs::write(&file, bytes).unwrap();
        let store = WindowsRegistryStore {
            maintenance_test_root: Some(prefix),
            ..Default::default()
        };
        let mut m = ChangeManager::new(store, dir.path().to_path_buf(), NoProbe);
        let p = m.prepare_restore(id).unwrap();
        assert_eq!(p.scope, "run_history");
        m.apply(&p.token).unwrap();
        let actual = super::super::read_maintenance_snapshot(&key, app.kind, &app.item).unwrap();
        assert_eq!(actual, app.snapshot);
        assert_eq!(std::fs::read(file).unwrap(), bytes);
    }
    #[test]
    fn font_and_both_help_views_support_individual_quick_selected_backups_and_exact_restart_restore(
    ) {
        for location in LOCATIONS {
            for mode in ["single", "quick", "selected"] {
                let f = Fixture::new();
                let (one, original) = f.registration(location, 0);
                let (two, other) = f.registration(location, 1);
                let root = f.key(location);
                root.set_value("Unrelated metadata", &17u32).unwrap();
                root.create_subkey("PackagedOrOtherRegistration").unwrap();
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("backups");
                let mut m = ChangeManager::new(f.store(), path.clone(), Missing);
                let entries = [
                    f.entry(one.clone(), original.clone()),
                    f.entry(two.clone(), other.clone()),
                ];
                let p = m.prepare_quarantine(&entries[0]).unwrap();
                assert_eq!(p.resolved_file.as_deref(), Some(one.target.as_str()));
                m.cancel();
                assert!(m.apply(&p.token).is_err());
                assert!(!path.exists());
                let ids = if mode == "single" {
                    let p = m.prepare_quarantine(&entries[0]).unwrap();
                    vec![m.apply(&p.token).unwrap().backup_id]
                } else {
                    let p = m.prepare_clean(&entries, mode).unwrap();
                    assert_eq!(p.items.len(), 2);
                    let r = m.apply_clean(&p.token).unwrap();
                    assert!(r.failed.is_none());
                    assert_eq!(r.completed.len(), 2);
                    r.completed.into_iter().map(|r| r.backup_id).collect()
                };
                drop(m);
                let mut m = ChangeManager::new(f.store(), path.clone(), Missing);
                for ((id, app), expected) in ids.iter().zip([&one, &two]).zip([&original, &other]) {
                    assert!(f.store().read_file_reference(app).unwrap().is_none());
                    let file = path.join(format!("{id}.json"));
                    let before = std::fs::read(&file).unwrap();
                    let record: serde_json::Value = serde_json::from_slice(&before).unwrap();
                    assert_eq!(record["schemaVersion"], 21);
                    assert!(record["fileReference"].is_object());
                    let p = m.prepare_restore(id).unwrap();
                    assert_eq!(p.registry_view, location.view());
                    assert_eq!(p.scope, location.scope());
                    m.apply(&p.token).unwrap();
                    assert_eq!(
                        f.store().read_file_reference(app).unwrap().as_ref(),
                        Some(expected)
                    );
                    assert_eq!(std::fs::read(file).unwrap(), before);
                }
                assert_eq!(root.get_value::<u32, _>("Unrelated metadata").unwrap(), 17);
                assert!(root.open_subkey("PackagedOrOtherRegistration").is_ok());
            }
        }
    }
    #[test]
    fn new_file_or_new_value_blocks_apply_and_restore_without_overwriting_data_or_backup() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        struct Switching(Arc<AtomicBool>);
        impl PathProbe for Switching {
            fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
                if self.0.load(Ordering::Relaxed) {
                    ProbeResult::Found
                } else {
                    ProbeResult::Missing
                }
            }
        }
        for location in LOCATIONS {
            let f = Fixture::new();
            let (app, original) = f.registration(location, 0);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("backups");
            let found = Arc::new(AtomicBool::new(false));
            let mut m = ChangeManager::new(f.store(), path.clone(), Switching(found.clone()));
            let e = f.entry(app.clone(), original.clone());
            let p = m.prepare_quarantine(&e).unwrap();
            found.store(true, Ordering::Relaxed);
            assert!(m
                .apply(&p.token)
                .unwrap_err()
                .contains("not confirmed missing"));
            assert!(!path.exists());
            assert_eq!(
                read_value(&f.key(location), &app.name).unwrap(),
                Some(original.clone())
            );
            found.store(false, Ordering::Relaxed);
            let p = m.prepare_quarantine(&e).unwrap();
            let id = m.apply(&p.token).unwrap().backup_id;
            let file = path.join(format!("{id}.json"));
            let before = std::fs::read(&file).unwrap();
            let p = m.prepare_restore(&id).unwrap();
            found.store(true, Ordering::Relaxed);
            assert!(m.apply(&p.token).is_err());
            assert!(read_value(&f.key(location), &app.name).unwrap().is_none());
            assert_eq!(std::fs::read(&file).unwrap(), before);
            found.store(false, Ordering::Relaxed);
            let p = m.prepare_restore(&id).unwrap();
            let replacement = StoredValue {
                kind: 1,
                bytes: r"C:\NewData\preserve"
                    .encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            };
            f.put(location, &app.name, &replacement);
            assert!(m.apply(&p.token).is_err());
            assert_eq!(
                read_value(&f.key(location), &app.name).unwrap(),
                Some(replacement)
            );
            assert_eq!(std::fs::read(file).unwrap(), before);
        }
    }
    #[test]
    fn machine_font_name_counterparts_block_review_apply_and_restore_with_original_bytes_preserved()
    {
        for stage in ["review", "apply", "restore", "restore_review"] {
            let f = Fixture::new();
            let (app, original) = f.registration(FileReferenceLocation::UserFont, 0);
            let e = f.entry(app.clone(), original.clone());
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("backups");
            let mut m = ChangeManager::new(f.store(), path.clone(), Missing);
            if stage == "review" {
                f.machine()
                    .set_value("OWNED CUSTOM FONT 0 (OpenType)", &"machine.ttf")
                    .unwrap();
                assert!(m
                    .prepare_quarantine(&e)
                    .unwrap_err()
                    .contains("matching machine"));
                assert!(!path.exists());
                continue;
            }
            let p = m.prepare_quarantine(&e).unwrap();
            if stage == "apply" {
                f.machine()
                    .set_value("Owned Custom Font 0", &"machine.ttf")
                    .unwrap();
                assert!(m.apply(&p.token).is_err());
                assert!(!path.exists());
                continue;
            }
            let id = m.apply(&p.token).unwrap().backup_id;
            let file = path.join(format!("{id}.json"));
            let bytes = std::fs::read(&file).unwrap();
            let p = if stage == "restore_review" {
                Some(m.prepare_restore(&id).unwrap())
            } else {
                None
            };
            f.machine()
                .set_value("Other & Owned Custom Font 0 (TrueType)", &"collection.ttc")
                .unwrap();
            if let Some(p) = p {
                assert!(m.apply(&p.token).is_err());
            } else {
                assert!(m.prepare_restore(&id).is_err());
            }
            assert!(read_value(&f.key(app.location), &app.name)
                .unwrap()
                .is_none());
            assert_eq!(std::fs::read(file).unwrap(), bytes);
        }
    }
    #[test]
    fn changed_scan_evidence_backup_failure_corruption_and_missing_keys_never_mutate_or_recreate() {
        let f = Fixture::new();
        let (app, original) = f.registration(FileReferenceLocation::HtmlHelp32, 0);
        let e = f.entry(app.clone(), original.clone());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backups");
        std::fs::write(&path, b"block directory creation").unwrap();
        let mut m = ChangeManager::new(f.store(), path.clone(), Missing);
        let p = m.prepare_quarantine(&e).unwrap();
        assert!(m.apply(&p.token).is_err());
        assert_eq!(
            read_value(&f.key(app.location), &app.name).unwrap(),
            Some(original.clone())
        );
        std::fs::remove_file(&path).unwrap();
        let p = m.prepare_quarantine(&e).unwrap();
        let id = m.apply(&p.token).unwrap().backup_id;
        let file = path.join(format!("{id}.json"));
        let bytes = std::fs::read(&file).unwrap();
        let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        record["name"] = serde_json::json!("corrupt label");
        std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(m.prepare_restore(&id).unwrap_err().contains("checksum"));
        let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        record["schemaVersion"] = serde_json::json!(20);
        std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(m.prepare_restore(&id).unwrap_err().contains("namespace"));
        std::fs::write(&file, &bytes).unwrap();
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey(format!(r"{}\{:?}", f.base, app.location))
            .unwrap();
        assert!(m.prepare_restore(&id).unwrap_err().contains("missing"));
        assert_eq!(std::fs::read(file).unwrap(), bytes);
    }
}
