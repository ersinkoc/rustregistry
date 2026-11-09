use super::*;
use crate::{
    changes::ChangeManager, LocalPathProbe, PathProbe, ProbeResult, RegistryEntry, TargetKind,
};
struct Fixture {
    base: String,
    files: tempfile::TempDir,
}
fn text(value: &str) -> StoredValue {
    StoredValue {
        kind: 1,
        bytes: value
            .encode_utf16()
            .chain([0, 0])
            .flat_map(u16::to_le_bytes)
            .collect(),
    }
}
impl Fixture {
    fn new() -> Self {
        let f = Self {
            base: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
            files: tempfile::tempdir().unwrap(),
        };
        for i in 0..2 {
            f.put(
                &format!(r"User\AppPaths\old{i}.exe"),
                "pAth",
                &text(&format!("{}\\", f.directory(i))),
            );
            f.key(&format!(r"User\AppPaths\old{i}.exe"))
                .set_value("Keep", &17u32)
                .unwrap();
            let path = format!(r"User\Uninstall\Owned{i}");
            for (name, value) in [
                ("DisplayName", format!("Owned application {i}")),
                ("InstallLocation", f.directory(i)),
                (
                    "UninstallString",
                    format!("\"{}\\uninstall.exe\" /remove", f.directory(i)),
                ),
                (
                    "QuietUninstallString",
                    format!("\"{}\\uninstall.exe\" /quiet", f.directory(i)),
                ),
                ("Publisher", "Preserved publisher".into()),
                ("DisplayVersion", "1.2".into()),
            ] {
                f.put(&path, name, &text(&value));
            }
            f.key(&path)
                .set_raw_value(
                    "CustomBinary",
                    &RegValue {
                        vtype: REG_BINARY,
                        bytes: Cow::Borrowed(&[1, 0, 255]),
                    },
                )
                .unwrap();
        }
        f
    }
    fn directory(&self, i: usize) -> String {
        self.files
            .path()
            .join(format!("Missing{i}"))
            .to_str()
            .unwrap()
            .into()
    }
    fn key(&self, path: &str) -> RegKey {
        RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"{}\{path}", self.base))
            .unwrap()
            .0
    }
    fn put(&self, path: &str, name: &str, value: &StoredValue) {
        self.key(path)
            .set_raw_value(
                name,
                &RegValue {
                    vtype: if value.kind == 2 {
                        REG_EXPAND_SZ
                    } else {
                        REG_SZ
                    },
                    bytes: Cow::Borrowed(&value.bytes),
                },
            )
            .unwrap();
    }
    fn store(&self) -> WindowsRegistryStore {
        WindowsRegistryStore {
            leftover_test_root: Some(self.base.clone()),
            ..Default::default()
        }
    }
    fn backup(&self, i: usize) -> LeftoverBackup {
        let name = format!("old{i}.exe");
        let state = self.store().leftover_application(&name, None).unwrap();
        let anchor =
            read_uninstall_snapshot(&self.key(&format!(r"User\Uninstall\Owned{i}"))).unwrap();
        LeftoverBackup {
            executable_name: name,
            value_name: state.name,
            directory: self.directory(i),
            uninstall_key: format!("Owned{i}"),
            anchor: normalized_anchor(&anchor).unwrap(),
            application_values: state.other,
        }
    }
    fn entry(&self, i: usize) -> RegistryEntry {
        let app = self.backup(i);
        let original = self
            .store()
            .leftover_application(&app.executable_name, None)
            .unwrap()
            .value
            .unwrap();
        let evidence = app.verify_original(&original, &LocalPathProbe).unwrap();
        let mut e:RegistryEntry=serde_json::from_value(serde_json::json!({"id":format!("leftover{i}"),"name":evidence.application_name,"category":"application_leftovers","hive":"HKCU","keyPath":app.key_path(),"view":"shared","valueName":app.value_name,"valueType":"REG_SZ","rawValue":original.text().unwrap(),"publisher":null,"version":null,"assessment":{"status":"review","code":"application_leftover_candidate","explanation":"Owned evidence","target":app.directory},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"leftoverRepairable":true})).unwrap();
        e.snapshot = Some(original);
        e.leftover_state = Some(app);
        e.leftover_evidence = Some(evidence);
        e
    }
    fn preserved(&self, i: usize) {
        assert_eq!(
            self.key(&format!(r"User\AppPaths\old{i}.exe"))
                .get_value::<u32, _>("Keep")
                .unwrap(),
            17
        );
        assert_eq!(
            self.key(&format!(r"User\Uninstall\Owned{i}"))
                .get_raw_value("CustomBinary")
                .unwrap()
                .bytes
                .as_ref(),
            [1, 0, 255]
        );
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
fn leftover_individual_selected_quick_clean_and_exact_restart_restore_preserve_other_metadata() {
    for mode in ["single", "selected", "quick"] {
        let f = Fixture::new();
        let entries = [f.entry(0), f.entry(1)];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backups");
        let mut m = ChangeManager::new(f.store(), path.clone(), LocalPathProbe);
        let ids = if mode == "single" {
            let p = m.prepare_quarantine(&entries[0]).unwrap();
            assert_eq!(p.scope, "application_leftover");
            assert_eq!(p.supporting_evidence.len(), 4);
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
        for (i, id) in ids.iter().enumerate() {
            assert!(
                read_value(&f.key(&format!(r"User\AppPaths\old{i}.exe")), "Path")
                    .unwrap()
                    .is_none()
            );
            f.preserved(i);
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path.join(format!("{id}.json"))).unwrap())
                    .unwrap();
            assert_eq!(record["schemaVersion"], 23);
            assert!(record["sound"].is_null());
            assert!(record["fileReference"].is_null());
            assert_eq!(
                record["original"]["bytes"],
                serde_json::to_value(entries[i].snapshot.as_ref().unwrap().bytes.clone()).unwrap()
            );
        }
        drop(m);
        let mut restarted = ChangeManager::new(f.store(), path, LocalPathProbe);
        for (i, id) in ids.iter().enumerate() {
            let p = restarted.prepare_restore(id).unwrap();
            restarted.apply(&p.token).unwrap();
            assert_eq!(
                read_value(&f.key(&format!(r"User\AppPaths\old{i}.exe")), "pAth").unwrap(),
                entries[i].snapshot
            );
            f.preserved(i);
        }
    }
}

#[test]
fn leftover_correlation_requires_exact_directories_direct_uninstallers_and_non_msi_ownership() {
    struct Probe;
    impl PathProbe for Probe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            ProbeResult::Missing
        }
    }
    let f = Fixture::new();
    let original = f.entry(0).snapshot.unwrap();
    let b = f.backup(0);
    correlate("old0.exe", &original, "Owned0", &b.anchor, &Probe).unwrap();
    for case in [
        "different_directory",
        "external_uninstaller",
        "msi",
        "guid",
        "expanded",
        "multi_path",
        "default_mapping",
    ] {
        let mut app = b.clone();
        let mut value = original.clone();
        match case {
            "different_directory" => {
                app.anchor
                    .values
                    .iter_mut()
                    .find(|v| v.name == "InstallLocation")
                    .unwrap()
                    .value = text(&format!("{}Other", f.directory(0)));
            }
            "external_uninstaller" => {
                app.anchor
                    .values
                    .iter_mut()
                    .find(|v| v.name == "UninstallString")
                    .unwrap()
                    .value = text(r#""C:\Elsewhere\uninstall.exe" /remove"#);
            }
            "msi" => app.anchor.values.push(NamedValue {
                name: "WindowsInstaller".into(),
                value: StoredValue {
                    kind: 4,
                    bytes: vec![1, 0, 0, 0],
                },
            }),
            "guid" => app.uninstall_key = uuid::Uuid::new_v4().to_string(),
            "expanded" => value.kind = 2,
            "multi_path" => value = text(&format!("{};C:\\Other", f.directory(0))),
            "default_mapping" => app.application_values.push(NamedValue {
                name: "".into(),
                value: text(&format!(r"{}\old0.exe", f.directory(0))),
            }),
            _ => unreachable!(),
        };
        assert!(app.verify_original(&value, &Probe).is_err(), "{case}");
    }
}

#[test]
fn leftover_new_files_installation_directories_and_uninstall_metadata_block_apply_and_restore() {
    for mutation in [
        "directory",
        "anchor",
        "duplicate",
        "default",
        "metadata",
        "value",
        "machine32",
        "machine64",
        "machine_uninstall",
        "user_application",
    ] {
        for restore in [false, true] {
            let f = Fixture::new();
            let e = f.entry(0);
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
                "directory" => std::fs::create_dir(f.directory(0)).unwrap(),
                "anchor" => {
                    f.key(r"User\Uninstall\Owned0")
                        .set_value("Publisher", &"new publisher")
                        .unwrap();
                }
                "duplicate" => {
                    f.put(
                        r"User\Uninstall\Other",
                        "InstallLocation",
                        &text(&f.directory(0)),
                    );
                }
                "default" => {
                    f.put(
                        r"User\AppPaths\old0.exe",
                        "",
                        &text(&format!(r"{}\old0.exe", f.directory(0))),
                    );
                }
                "metadata" => {
                    f.key(r"User\AppPaths\old0.exe")
                        .set_value("Keep", &18u32)
                        .unwrap();
                }
                "value" => f.put(r"User\AppPaths\old0.exe", "Path", &text(r"C:\New\Preserve")),
                "machine32" => {
                    f.key(r"Machine32\AppPaths\old0.exe");
                }
                "machine64" => {
                    f.key(r"Machine64\AppPaths\old0.exe");
                }
                "machine_uninstall" => {
                    f.key(r"Machine64\Uninstall\Owned0");
                }
                "user_application" => {
                    f.key(r"User\Applications\old0.exe");
                }
                _ => unreachable!(),
            };
            let before = read_value(&f.key(r"User\AppPaths\old0.exe"), "Path").unwrap();
            assert!(m.apply(&p.token).is_err(), "{mutation}/{restore}");
            assert_eq!(
                read_value(&f.key(r"User\AppPaths\old0.exe"), "Path").unwrap(),
                before
            );
            if let Some((file, bytes)) = backup {
                assert_eq!(std::fs::read(file).unwrap(), bytes)
            } else {
                assert!(!path.exists())
            }
        }
    }
}

#[test]
fn leftover_cleanup_coexists_with_supported_uninstall_visibility_and_protects_missing_keys_and_bad_backups(
) {
    let f = Fixture::new();
    let e = f.entry(0);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backups");
    let mut m = ChangeManager::new(f.store(), path.clone(), LocalPathProbe);
    let p = m.prepare_quarantine(&e).unwrap();
    f.key(r"User\Uninstall\Owned0")
        .set_value("SystemComponent", &1u32)
        .unwrap();
    let id = m.apply(&p.token).unwrap().backup_id;
    let file = path.join(format!("{id}.json"));
    let bytes = std::fs::read(&file).unwrap();
    let p = m.prepare_restore(&id).unwrap();
    f.key(r"User\Uninstall\Owned0")
        .delete_value("SystemComponent")
        .unwrap();
    m.apply(&p.token).unwrap();
    f.preserved(0);
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    std::fs::remove_file(&file).unwrap();
    let p = m.prepare_quarantine(&e).unwrap();
    let id = m.apply(&p.token).unwrap().backup_id;
    let file = path.join(format!("{id}.json"));
    let original = std::fs::read(&file).unwrap();
    let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
    record["schemaVersion"] = serde_json::json!(22);
    std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(m.prepare_restore(&id).unwrap_err().contains("namespace"));
    let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
    record["name"] = serde_json::json!("changed");
    std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(m.prepare_restore(&id).unwrap_err().contains("checksum"));
    std::fs::write(&file, &original).unwrap();
    let p = m.prepare_restore(&id).unwrap();
    RegKey::predef(HKEY_CURRENT_USER)
        .delete_subkey(format!(r"{}\User\AppPaths\old0.exe", f.base))
        .unwrap();
    assert!(m.apply(&p.token).is_err());
    assert!(RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(format!(r"{}\User\AppPaths\old0.exe", f.base))
        .is_err());
    assert_eq!(std::fs::read(file).unwrap(), original);
}

#[test]
fn leftover_backup_storage_failure_never_removes_the_original_search_path() {
    let f = Fixture::new();
    let e = f.entry(0);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-directory");
    std::fs::write(&path, b"owned blocker").unwrap();
    let mut m = ChangeManager::new(f.store(), path, LocalPathProbe);
    let p = m.prepare_quarantine(&e).unwrap();
    assert!(m.apply(&p.token).is_err());
    assert_eq!(
        read_value(&f.key(r"User\AppPaths\old0.exe"), "Path").unwrap(),
        e.snapshot
    );
    f.preserved(0);
}

#[test]
fn leftover_expanded_anchor_for_same_directory_does_not_hide_ownership_ambiguity() {
    for variable in [false, true] {
        let f = Fixture::new();
        let entry = f.entry(0);
        let raw = if variable {
            format!(
                r"%TEMP%\{}\Missing0",
                f.files.path().file_name().unwrap().to_str().unwrap()
            )
        } else {
            f.directory(0)
        };
        let mut value = text(&raw);
        value.kind = 2;
        f.put(r"User\Uninstall\ExpandedOther", "InstallLocation", &value);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backups");
        let mut m = ChangeManager::new(f.store(), path.clone(), LocalPathProbe);
        assert!(
            m.prepare_quarantine(&entry).is_err(),
            "Expanded duplicate ownership must block review"
        );
        assert!(!path.exists());
        assert_eq!(
            read_value(&f.key(r"User\AppPaths\old0.exe"), "Path").unwrap(),
            entry.snapshot
        );
    }
}

#[test]
fn leftover_application_owned_link_metadata_remains_protected() {
    let f = Fixture::new();
    let entry = f.entry(0);
    let key = f.key(r"User\AppPaths\old0.exe");
    let bytes: Vec<u8> = r"\Registry\Machine\Software\RustRegistryOwnedMissingTarget"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    key.set_raw_value(
        "SymbolicLinkValue",
        &RegValue {
            vtype: REG_LINK,
            bytes: Cow::Owned(bytes),
        },
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backups");
    let mut m = ChangeManager::new(f.store(), path.clone(), LocalPathProbe);
    assert!(m.prepare_quarantine(&entry).unwrap_err().contains("links"));
    assert!(!path.exists());
    assert_eq!(read_value(&key, "Path").unwrap(), entry.snapshot);
}
