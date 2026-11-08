use super::*;
use crate::{analysis::LocalPathProbe, changes::ChangeManager, RegistryEntry};

struct Fixture {
    base: String,
    files: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let f = Self {
            base: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
            files: tempfile::tempdir().unwrap(),
        };
        f.key("").set_value("", &".Default").unwrap();
        f.key("Apps\\CustomApp")
            .set_value("", &"Preserved app")
            .unwrap();
        for event in ["NotifyOne", "NotifyTwo"] {
            f.key(&format!(r"Apps\CustomApp\{event}"))
                .set_value("Label", &"Preserved event")
                .unwrap();
            let current = f.current(event);
            current.set_value("Keep", &17u32).unwrap();
            let original = f.original(event);
            current
                .set_raw_value(
                    "",
                    &RegValue {
                        vtype: REG_SZ,
                        bytes: Cow::Owned(original.bytes),
                    },
                )
                .unwrap();
            f.key(&format!(r"Apps\CustomApp\{event}\.Default"))
                .set_value("", &r"C:\Windows\Media\preserve.wav")
                .unwrap();
            f.key(&format!(r"Apps\CustomApp\{event}\.None"))
                .set_value("", &"")
                .unwrap();
        }
        f
    }
    fn key(&self, suffix: &str) -> RegKey {
        RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(if suffix.is_empty() {
                self.base.clone()
            } else {
                format!(r"{}\{suffix}", self.base)
            })
            .unwrap()
            .0
    }
    fn current(&self, event: &str) -> RegKey {
        self.key(&format!(r"Apps\CustomApp\{event}\.Current"))
    }
    fn target(&self, event: &str) -> String {
        self.files
            .path()
            .join(format!("{event}.wav"))
            .to_str()
            .unwrap()
            .into()
    }
    fn original(&self, event: &str) -> StoredValue {
        StoredValue {
            kind: 1,
            bytes: self
                .target(event)
                .encode_utf16()
                .chain([0, 0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    fn store(&self) -> WindowsRegistryStore {
        WindowsRegistryStore {
            sound_test_root: Some(self.base.clone()),
            sound_test_machine: Some(format!(r"{}\MachineApps", self.base)),
            ..Default::default()
        }
    }
    fn backup(&self, event: &str) -> SoundBackup {
        SoundBackup {
            application: "CustomApp".into(),
            event: event.into(),
            target: self.target(event),
            guard: self
                .store()
                .sound_snapshot("CustomApp", event, None)
                .unwrap()
                .guard,
        }
    }
    fn entry(&self, event: &str) -> RegistryEntry {
        let app = self.backup(event);
        let original = self.original(event);
        let mut e:RegistryEntry=serde_json::from_value(serde_json::json!({"id":event,"name":format!("CustomApp / {event} / .Current"),"category":"sound_events","hive":"HKCU","keyPath":app.key_path(),"view":"shared","valueName":"","valueType":"REG_SZ","rawValue":original.text().unwrap(),"publisher":null,"version":null,"assessment":{"status":"review","code":"sound_file_missing","explanation":"Owned missing sound","target":app.target},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"soundRepairable":true})).unwrap();
        e.snapshot = Some(original);
        e.sound_state = Some(app);
        e
    }
    fn preserved(&self, event: &str) {
        assert_eq!(self.current(event).get_value::<u32, _>("Keep").unwrap(), 17);
        assert_eq!(
            self.key(&format!(r"Apps\CustomApp\{event}\.Default"))
                .get_value::<String, _>("")
                .unwrap(),
            r"C:\Windows\Media\preserve.wav"
        );
        assert_eq!(
            self.key(&format!(r"Apps\CustomApp\{event}\.None"))
                .get_value::<String, _>("")
                .unwrap(),
            ""
        );
        assert_eq!(self.key("").get_value::<String, _>("").unwrap(), ".Default");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(&self.base)
            .unwrap();
    }
}

#[test]
fn sound_individual_selected_and_quick_clean_back_up_exact_bytes_and_restore_after_restart() {
    for mode in ["single", "selected", "quick"] {
        let f = Fixture::new();
        let entries = [f.entry("NotifyOne"), f.entry("NotifyTwo")];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backups");
        let mut m = ChangeManager::new(f.store(), path.clone(), LocalPathProbe);
        let ids = if mode == "single" {
            let p = m.prepare_quarantine(&entries[0]).unwrap();
            assert_eq!(p.scope, "sound_event");
            assert_eq!(p.resolved_file, Some(f.target("NotifyOne")));
            vec![m.apply(&p.token).unwrap().backup_id]
        } else {
            let p = m.prepare_clean(&entries, mode).unwrap();
            assert_eq!(p.items.len(), 2);
            let result = m.apply_clean(&p.token).unwrap();
            assert!(result.failed.is_none());
            result
                .completed
                .iter()
                .map(|r| r.backup_id.clone())
                .collect()
        };
        for (index, id) in ids.iter().enumerate() {
            let event = ["NotifyOne", "NotifyTwo"][index];
            assert_eq!(
                read_value(&f.current(event), "").unwrap(),
                Some(empty_assignment())
            );
            f.preserved(event);
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path.join(format!("{id}.json"))).unwrap())
                    .unwrap();
            assert_eq!(record["schemaVersion"], 22);
            assert!(record["fileReference"].is_null());
            assert_eq!(
                record["original"]["bytes"],
                serde_json::to_value(f.original(event).bytes).unwrap()
            );
        }
        drop(m);
        let mut restarted = ChangeManager::new(f.store(), path, LocalPathProbe);
        for (index, id) in ids.iter().enumerate() {
            let p = restarted.prepare_restore(id).unwrap();
            restarted.apply(&p.token).unwrap();
            let event = ["NotifyOne", "NotifyTwo"][index];
            assert_eq!(
                read_value(&f.current(event), "").unwrap(),
                Some(f.original(event))
            );
            f.preserved(event);
        }
    }
}

#[test]
fn sound_file_appearing_after_review_blocks_apply_and_restore_without_changing_backup() {
    for restore in [false, true] {
        let f = Fixture::new();
        let e = f.entry("NotifyOne");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backups");
        let mut m = ChangeManager::new(f.store(), path.clone(), LocalPathProbe);
        let p = m.prepare_quarantine(&e).unwrap();
        let (p, backup) = if restore {
            let id = m.apply(&p.token).unwrap().backup_id;
            let file = path.join(format!("{id}.json"));
            let bytes = std::fs::read(&file).unwrap();
            (m.prepare_restore(&id).unwrap(), Some((file, bytes)))
        } else {
            (p, None)
        };
        std::fs::write(f.target("NotifyOne"), []).unwrap();
        assert!(m
            .apply(&p.token)
            .unwrap_err()
            .contains("not confirmed missing"));
        assert_eq!(
            read_value(&f.current("NotifyOne"), "").unwrap(),
            Some(if restore {
                empty_assignment()
            } else {
                f.original("NotifyOne")
            })
        );
        if let Some((file, bytes)) = backup {
            assert_eq!(std::fs::read(file).unwrap(), bytes)
        } else {
            assert!(!path.exists())
        }
        f.preserved("NotifyOne");
    }
}

#[test]
fn sound_selection_saved_schemes_metadata_values_and_machine_counterparts_are_fresh_guards() {
    for mutation in ["selection", "saved", "metadata", "value", "machine"] {
        for restore in [false, true] {
            let f = Fixture::new();
            let e = f.entry("NotifyOne");
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("backups");
            let mut m = ChangeManager::new(f.store(), path.clone(), LocalPathProbe);
            let p = m.prepare_quarantine(&e).unwrap();
            let (p, backup) = if restore {
                let id = m.apply(&p.token).unwrap().backup_id;
                let file = path.join(format!("{id}.json"));
                let bytes = std::fs::read(&file).unwrap();
                (m.prepare_restore(&id).unwrap(), Some((file, bytes)))
            } else {
                (p, None)
            };
            match mutation {
                "selection" => f.key("").set_value("", &"CustomScheme").unwrap(),
                "saved" => f
                    .key(r"Apps\CustomApp\NotifyOne\.Default")
                    .set_value("NewMetadata", &"keep")
                    .unwrap(),
                "metadata" => f.current("NotifyOne").set_value("Keep", &18u32).unwrap(),
                "value" => f
                    .current("NotifyOne")
                    .set_value("", &"C:\\New\\preserve.wav")
                    .unwrap(),
                "machine" => {
                    f.key(r"MachineApps\CustomApp\NotifyOne\.Current");
                }
                _ => unreachable!(),
            };
            let actual = read_value(&f.current("NotifyOne"), "").unwrap();
            assert!(m.apply(&p.token).is_err());
            assert_eq!(read_value(&f.current("NotifyOne"), "").unwrap(), actual);
            if let Some((file, bytes)) = backup {
                assert_eq!(std::fs::read(file).unwrap(), bytes)
            } else {
                assert!(!path.exists())
            }
        }
    }
}

#[test]
fn sound_scan_evidence_backup_failure_corruption_namespace_and_deleted_keys_fail_closed() {
    let f = Fixture::new();
    let e = f.entry("NotifyOne");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backups");
    let mut m = ChangeManager::new(f.store(), path.clone(), LocalPathProbe);
    f.current("NotifyOne")
        .set_value("", &"C:\\New\\preserve.wav")
        .unwrap();
    assert!(m.prepare_quarantine(&e).is_err());
    assert!(!path.exists());
    f.current("NotifyOne")
        .set_raw_value(
            "",
            &RegValue {
                vtype: REG_SZ,
                bytes: Cow::Owned(f.original("NotifyOne").bytes),
            },
        )
        .unwrap();
    std::fs::write(&path, b"block directory creation").unwrap();
    let p = m.prepare_quarantine(&e).unwrap();
    assert!(m.apply(&p.token).is_err());
    assert_eq!(
        read_value(&f.current("NotifyOne"), "").unwrap(),
        Some(f.original("NotifyOne"))
    );
    std::fs::remove_file(&path).unwrap();
    let p = m.prepare_quarantine(&e).unwrap();
    let id = m.apply(&p.token).unwrap().backup_id;
    let file = path.join(format!("{id}.json"));
    let bytes = std::fs::read(&file).unwrap();
    let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    record["name"] = serde_json::json!("changed label");
    std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(m.prepare_restore(&id).unwrap_err().contains("checksum"));
    let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    record["schemaVersion"] = serde_json::json!(21);
    std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(m.prepare_restore(&id).unwrap_err().contains("namespace"));
    std::fs::write(&file, &bytes).unwrap();
    let p = m.prepare_restore(&id).unwrap();
    f.key(r"Apps\CustomApp\NotifyOne")
        .delete_subkey(CURRENT)
        .unwrap();
    assert!(m.apply(&p.token).is_err());
    assert!(f
        .key(r"Apps\CustomApp\NotifyOne")
        .open_subkey(CURRENT)
        .is_err());
    assert_eq!(std::fs::read(file).unwrap(), bytes);
}
