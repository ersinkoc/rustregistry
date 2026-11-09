use super::*;
use crate::changes::RegistryStore;
use crate::leftover_urls::UrlMetadataBackup;

impl Fixture {
    fn url_entries(&self, i: usize) -> Vec<RegistryEntry> {
        let original_entry = self.entry(i);
        let values = vec![
            NamedValue {
                name: "SupportedProtocols".into(),
                value: text("https:ftp:rr-custom"),
            },
            NamedValue {
                name: "uSeUrL".into(),
                value: StoredValue {
                    kind: 4,
                    bytes: vec![1, 0, 0, 0],
                },
            },
        ];
        for value in &values {
            self.put(
                &format!(r"User\AppPaths\old{i}.exe"),
                &value.name,
                &value.value,
            );
        }
        values
            .iter()
            .map(|value| {
                let mut entry = original_entry.clone();
                let mut app = entry.leftover_state.take().unwrap();
                app.url_metadata = Some(Box::new(UrlMetadataBackup {
                    path_name: app.value_name.clone(),
                    search_path: entry.snapshot.clone().unwrap(),
                    values: values.clone(),
                }));
                app.value_name = value.name.clone();
                entry.id = format!("url{i}|{}", value.name);
                entry.value_name = value.name.clone();
                entry.value_type = if value.value.kind == 4 {
                    "REG_DWORD"
                } else {
                    "REG_SZ"
                }
                .into();
                entry.raw_value = if value.value.kind == 4 {
                    "1".into()
                } else {
                    value.value.text().unwrap()
                };
                entry.snapshot = Some(value.value.clone());
                entry.leftover_state = Some(app);
                entry
            })
            .collect()
    }
}

#[test]
fn leftover_url_metadata_individual_cleanup_restores_exact_original_after_restart() {
    for index in 0..2 {
        let f = Fixture::new();
        let entries = f.url_entries(0);
        let entry = &entries[index];
        let storage = tempfile::tempdir().unwrap();
        let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
        let plan = manager
            .prepare_quarantine(entry)
            .expect("Correlated URL metadata should support reviewed cleanup");
        let id = manager.apply(&plan.token).unwrap().backup_id;
        let key = f.key(r"User\AppPaths\old0.exe");
        assert!(read_value(&key, &entry.value_name).unwrap().is_none());
        assert_eq!(
            read_value(&key, &entries[1 - index].value_name).unwrap(),
            entries[1 - index].snapshot
        );
        drop(manager);
        let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
        let restore = manager.prepare_restore(&id).unwrap();
        manager.apply(&restore.token).unwrap();
        assert_eq!(read_value(&key, &entry.value_name).unwrap(), entry.snapshot);
        f.preserved(0);
    }
}

#[test]
fn leftover_url_metadata_siblings_restore_in_either_order_and_newer_path_backup_restores_first() {
    for reverse in [false, true] {
        let f = Fixture::new();
        let entries = f.url_entries(0);
        let storage = tempfile::tempdir().unwrap();
        let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
        let plan = manager.prepare_clean(&entries, "selected").unwrap();
        assert_eq!(plan.items.len(), 2);
        let cleaned = manager.apply_clean(&plan.token).unwrap();
        assert_eq!(cleaned.completed.len(), 2);
        assert!(cleaned.failed.is_none());
        let path = f.entry(0);
        let reviewed = manager.prepare_quarantine(&path).unwrap();
        let path_id = manager.apply(&reviewed.token).unwrap().backup_id;
        for value in &cleaned.completed {
            assert!(manager
                .prepare_restore(&value.backup_id)
                .unwrap_err()
                .contains("search path"));
        }
        let reviewed = manager.prepare_restore(&path_id).unwrap();
        manager.apply(&reviewed.token).unwrap();
        drop(manager);
        let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
        let mut completed = cleaned.completed;
        if reverse {
            completed.reverse();
        }
        for value in completed {
            let file = storage.path().join(format!("{}.json", value.backup_id));
            let bytes = std::fs::read(&file).unwrap();
            let reviewed = manager.prepare_restore(&value.backup_id).unwrap();
            manager.apply(&reviewed.token).unwrap();
            assert_eq!(std::fs::read(file).unwrap(), bytes);
        }
        let key = f.key(r"User\AppPaths\old0.exe");
        for entry in &entries {
            assert_eq!(read_value(&key, &entry.value_name).unwrap(), entry.snapshot);
        }
        f.preserved(0);
    }
}

#[test]
fn leftover_url_metadata_apply_and_restore_conflicts_never_overwrite_values_or_backups() {
    for mutation in [
        "directory",
        "anchor",
        "duplicate",
        "default",
        "path",
        "path_case",
        "missing_path",
        "metadata",
        "user_application",
        "machine32",
        "machine64",
        "machine_anchor",
        "activation",
        "target",
        "target_case",
        "sibling",
        "nested",
        "missing_key",
    ] {
        for restore in [false, true] {
            let f = Fixture::new();
            let entry = f.url_entries(0).remove(0);
            let storage = tempfile::tempdir().unwrap();
            let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
            let plan = manager.prepare_quarantine(&entry).unwrap();
            let (plan, saved) = if restore {
                let id = manager.apply(&plan.token).unwrap().backup_id;
                let file = storage.path().join(format!("{id}.json"));
                let bytes = std::fs::read(&file).unwrap();
                (manager.prepare_restore(&id).unwrap(), Some((file, bytes)))
            } else {
                (plan, None)
            };
            let path = r"User\AppPaths\old0.exe";
            match mutation {
                "directory" => std::fs::create_dir(f.directory(0)).unwrap(),
                "anchor" => f.put(r"User\Uninstall\Owned0", "Publisher", &text("changed")),
                "duplicate" => {
                    f.key(r"User\Uninstall\Other")
                        .set_value("InstallLocation", &f.directory(0))
                        .unwrap();
                }
                "default" => f.put(path, "", &text(&format!(r"{}\old0.exe", f.directory(0)))),
                "path" => f.put(path, "pAth", &text(r"C:\Other")),
                "path_case" => {
                    let k = f.key(path);
                    k.delete_value("pAth").unwrap();
                    f.put(
                        path,
                        "Path",
                        &entry
                            .leftover_state
                            .as_ref()
                            .unwrap()
                            .url_metadata
                            .as_ref()
                            .unwrap()
                            .search_path,
                    );
                }
                "missing_path" => f.key(path).delete_value("pAth").unwrap(),
                "metadata" => {
                    f.key(path).set_value("Keep", &18u32).unwrap();
                }
                "user_application" => {
                    f.key(r"User\Applications\old0.exe");
                }
                "machine32" => {
                    f.key(r"Machine32\AppPaths\old0.exe");
                }
                "machine64" => {
                    f.key(r"Machine64\Applications\old0.exe");
                }
                "machine_anchor" => {
                    f.key(r"Machine64\Uninstall\Owned0");
                }
                "activation" => f.put(
                    path,
                    "DropTarget",
                    &text("{11111111-1111-4111-8111-111111111111}"),
                ),
                "target" => f.put(path, &entry.value_name, &text("https:changed")),
                "target_case" => {
                    f.key(path).delete_value(&entry.value_name).ok();
                    f.put(
                        path,
                        &entry.value_name.to_lowercase(),
                        entry.snapshot.as_ref().unwrap(),
                    );
                }
                "sibling" => {
                    f.key(path).set_value("uSeUrL", &0u32).unwrap();
                }
                "nested" => {
                    f.key(r"User\AppPaths\old0.exe\Nested");
                }
                "missing_key" => {
                    f.key(r"User\AppPaths")
                        .delete_subkey_all("old0.exe")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let read = || {
                RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(format!(r"{}\{path}", f.base))
                    .ok()
                    .and_then(|k| read_value(&k, &entry.value_name).unwrap())
            };
            let before = read();
            let error = manager.apply(&plan.token).unwrap_err();
            assert!(
                !error.contains("token") && !error.contains("expired"),
                "{mutation}/{restore}: {error}"
            );
            assert_eq!(read(), before, "{mutation}/{restore}");
            if let Some((file, bytes)) = saved {
                assert_eq!(std::fs::read(file).unwrap(), bytes);
            } else {
                assert_eq!(std::fs::read_dir(storage.path()).unwrap().count(), 0);
            }
        }
    }
}

#[test]
fn leftover_url_metadata_full_clean_handles_128_values_and_restores_all_after_restart() {
    let f = Fixture::new();
    let mut entries = vec![];
    for i in 0..64 {
        if i >= 2 {
            let path = format!(r"User\AppPaths\old{i}.exe");
            f.put(&path, "pAth", &text(&format!("{}\\", f.directory(i))));
            f.key(&path).set_value("Keep", &17u32).unwrap();
            let owner = format!(r"User\Uninstall\Owned{i}");
            for (name, value) in [
                ("DisplayName", format!("Owned application {i}")),
                ("InstallLocation", f.directory(i)),
                (
                    "UninstallString",
                    format!("\"{}\\uninstall.exe\" /remove", f.directory(i)),
                ),
            ] {
                f.put(&owner, name, &text(&value));
            }
        }
        entries.extend(f.url_entries(i));
    }
    let selected = crate::changes::select_clean_entries(&entries, "full", &[], None).unwrap();
    assert_eq!(selected.len(), 128);
    let storage = tempfile::tempdir().unwrap();
    let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
    let plan = manager.prepare_clean(&selected, "full").unwrap();
    assert_eq!(plan.items.len(), 128);
    let result = manager.apply_clean(&plan.token).unwrap();
    assert!(result.failed.is_none());
    assert_eq!(result.completed.len(), 128);
    let inventory = manager.inventory().unwrap();
    assert_eq!(inventory.backups.len(), 128);
    assert!(inventory.warnings.is_empty());
    drop(manager);
    let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
    for result in result.completed.iter().rev() {
        let reviewed = manager.prepare_restore(&result.backup_id).unwrap();
        manager.apply(&reviewed.token).unwrap();
    }
    for entry in entries {
        let app = entry.leftover_state.as_ref().unwrap();
        assert_eq!(f.store().read_leftover(app).unwrap(), entry.snapshot);
    }
}

#[test]
fn leftover_url_metadata_protects_unsupported_types_schemes_and_backup_namespaces() {
    let mut bad = vec![
        (0, text("")),
        (0, text("https:")),
        (0, text(":https")),
        (0, text("https:HTTPS")),
        (0, text("https://example.com")),
        (0, text("https:with space")),
        (0, text("https:ğ")),
        (0, text(&"a".repeat(33))),
        (0, text(&vec!["http"; 17].join(":"))),
        (0, text("%URL_SCHEMES%")),
        (1, text("1")),
        (
            1,
            StoredValue {
                kind: 4,
                bytes: vec![2, 0, 0, 0],
            },
        ),
        (
            1,
            StoredValue {
                kind: 4,
                bytes: vec![1, 0],
            },
        ),
    ];
    let mut expanded = text("https:ftp");
    expanded.kind = 2;
    bad.push((0, expanded));
    for (index, value) in bad {
        let f = Fixture::new();
        let mut entry = f.url_entries(0).remove(index);
        entry.snapshot = Some(value.clone());
        let app = entry.leftover_state.as_mut().unwrap();
        let name = app.value_name.clone();
        app.url_metadata
            .as_mut()
            .unwrap()
            .values
            .iter_mut()
            .find(|v| v.name == name)
            .unwrap()
            .value = value;
        let storage = tempfile::tempdir().unwrap();
        let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
        assert!(
            manager.prepare_quarantine(&entry).is_err(),
            "{}",
            entry.value_name
        );
        assert_eq!(std::fs::read_dir(storage.path()).unwrap().count(), 0);
    }
    let f = Fixture::new();
    let mut entry = f.url_entries(0).remove(0);
    entry.leftover_state.as_mut().unwrap().path_list = entry
        .leftover_state
        .as_ref()
        .unwrap()
        .url_metadata
        .as_ref()
        .map(|u| u.search_path.clone());
    let storage = tempfile::tempdir().unwrap();
    let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
    assert!(manager
        .prepare_quarantine(&entry)
        .unwrap_err()
        .contains("namespaces"));
}

#[test]
fn leftover_url_metadata_backup_failure_and_corruption_preserve_current_values() {
    let f = Fixture::new();
    let entries = f.url_entries(0);
    let storage = tempfile::tempdir().unwrap();
    let blocked = storage.path().join("blocked");
    std::fs::write(&blocked, b"preserve").unwrap();
    let mut manager = ChangeManager::new(f.store(), blocked.clone(), LocalPathProbe);
    let reviewed = manager.prepare_quarantine(&entries[1]).unwrap();
    assert!(manager.apply(&reviewed.token).is_err());
    assert_eq!(std::fs::read(blocked).unwrap(), b"preserve");
    assert_eq!(
        f.store()
            .read_leftover(entries[1].leftover_state.as_ref().unwrap())
            .unwrap(),
        entries[1].snapshot
    );
    let backups = storage.path().join("backups");
    let mut manager = ChangeManager::new(f.store(), backups.clone(), LocalPathProbe);
    let reviewed = manager.prepare_quarantine(&entries[1]).unwrap();
    let id = manager.apply(&reviewed.token).unwrap().backup_id;
    let file = backups.join(format!("{id}.json"));
    let original = std::fs::read(&file).unwrap();
    for mutation in ["schema", "checksum", "original", "namespace"] {
        let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
        assert_eq!(record["schemaVersion"], 26);
        match mutation {
            "schema" => record["schemaVersion"] = 25.into(),
            "checksum" => record["integritySha256"] = "0".repeat(64).into(),
            "original" => record["original"]["bytes"][0] = 0.into(),
            "namespace" => record["valueName"] = "DropTarget".into(),
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec_pretty(&record).unwrap();
        std::fs::write(&file, &bytes).unwrap();
        assert!(manager.prepare_restore(&id).is_err(), "{mutation}");
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        assert!(
            read_value(&f.key(r"User\AppPaths\old0.exe"), &entries[1].value_name)
                .unwrap()
                .is_none()
        );
    }
    std::fs::write(&file, original).unwrap();
    let reviewed = manager.prepare_restore(&id).unwrap();
    manager.apply(&reviewed.token).unwrap();
    f.preserved(0);
}
