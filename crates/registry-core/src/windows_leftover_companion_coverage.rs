use super::*;

#[test]
fn leftover_companion_mapping_can_be_cleaned_between_hints_without_recreating_it_during_recovery() {
    for reverse in [false, true] {
        let f = Fixture::new();
        let entries = f.companion_entries();
        let storage = tempfile::tempdir().unwrap();
        let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
        let plan = manager.prepare_clean(&entries, "full").unwrap();
        let result = manager
            .apply_clean_with_progress(
                &plan.token,
                || false,
                |progress| {
                    if progress.completed == 1 {
                        f.key(r"User\AppPaths\old0.exe").delete_value("").unwrap();
                    }
                },
            )
            .unwrap();
        assert!(result.failed.is_none());
        assert_eq!(result.completed.len(), 2);
        drop(manager);
        let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
        let mut completed = result.completed;
        if reverse {
            completed.reverse();
        }
        for record in completed {
            let file = storage.path().join(format!("{}.json", record.backup_id));
            let before = std::fs::read(&file).unwrap();
            let plan = manager.prepare_restore(&record.backup_id).unwrap();
            manager.apply(&plan.token).unwrap();
            assert_eq!(std::fs::read(file).unwrap(), before);
        }
        assert!(read_value(&f.key(r"User\AppPaths\old0.exe"), "")
            .unwrap()
            .is_none());
        for entry in &entries {
            assert_eq!(
                f.store()
                    .read_leftover(entry.leftover_state.as_ref().unwrap())
                    .unwrap(),
                entry.snapshot
            );
        }
    }
}

#[test]
fn leftover_companion_apply_restore_conflicts_preserve_hints_and_immutable_backups() {
    for mutation in [
        "directory",
        "command",
        "metadata",
        "anchor",
        "duplicate",
        "machine32",
        "machine64",
        "machine_owner",
        "companion_mapping",
        "new_mapping",
        "companion_path",
        "path_case",
        "companion_metadata",
        "activation",
        "nested",
        "missing_companion",
        "hint",
        "hint_case",
        "missing_application",
    ] {
        for restore in [false, true] {
            let f = Fixture::new();
            let mut entry = f.companion_entries().remove(0);
            if mutation == "new_mapping" {
                f.key(r"User\AppPaths\old0.exe").delete_value("").unwrap();
                entry
                    .leftover_state
                    .as_mut()
                    .unwrap()
                    .supported_type
                    .as_mut()
                    .unwrap()
                    .app_paths = f
                    .store()
                    .leftover_type_companion("old0.exe", None)
                    .unwrap()
                    .map(Box::new);
            }
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
            match mutation {
                "directory" => std::fs::create_dir(f.directory(0)).unwrap(),
                "command" => f.put(
                    r"User\Applications\old0.exe\shell\open\command",
                    "",
                    &text(r#""C:\Other\old0.exe" "%1""#),
                ),
                "metadata" => f.put(
                    r"User\Applications\old0.exe",
                    "LicenseMarker",
                    &text("changed"),
                ),
                "anchor" => f.put(r"User\Uninstall\Owned0", "Publisher", &text("changed")),
                "duplicate" => f.put(
                    r"User\Uninstall\Other",
                    "InstallLocation",
                    &text(&f.directory(0)),
                ),
                "machine32" => {
                    f.key(r"Machine32\AppPaths\old0.exe");
                }
                "machine64" => {
                    f.key(r"Machine64\Applications\old0.exe");
                }
                "machine_owner" => {
                    f.key(r"Machine64\Uninstall\Owned0");
                }
                "companion_mapping" => {
                    f.put(r"User\AppPaths\old0.exe", "", &text(r"C:\Other\old0.exe"))
                }
                "new_mapping" => f.put(
                    r"User\AppPaths\old0.exe",
                    "",
                    &text(&format!(r"{}\old0.exe", f.directory(0))),
                ),
                "companion_path" => f.put(r"User\AppPaths\old0.exe", "pAth", &text(r"C:\Other")),
                "path_case" => {
                    let key = f.key(r"User\AppPaths\old0.exe");
                    key.delete_value("pAth").unwrap();
                    let original = entry
                        .leftover_state
                        .as_ref()
                        .unwrap()
                        .supported_type
                        .as_ref()
                        .unwrap()
                        .app_paths
                        .as_ref()
                        .unwrap()
                        .get("Path")
                        .unwrap();
                    f.put(r"User\AppPaths\old0.exe", "Path", original);
                }
                "companion_metadata" => {
                    f.put(r"User\AppPaths\old0.exe", "LicenseMarker", &text("changed"))
                }
                "activation" => f.put(
                    r"User\AppPaths\old0.exe",
                    "DropTarget",
                    &text("{11111111-1111-4111-8111-111111111111}"),
                ),
                "nested" => {
                    f.key(r"User\AppPaths\old0.exe\Nested");
                }
                "missing_companion" => f
                    .key(r"User\AppPaths")
                    .delete_subkey_all("old0.exe")
                    .unwrap(),
                "hint" => f.put(
                    r"User\Applications\old0.exe\SupportedTypes",
                    &entry.value_name,
                    &text("new"),
                ),
                "hint_case" => {
                    f.key(r"User\Applications\old0.exe\SupportedTypes")
                        .delete_value(&entry.value_name)
                        .ok();
                    f.put(
                        r"User\Applications\old0.exe\SupportedTypes",
                        &entry.value_name.to_lowercase(),
                        entry.snapshot.as_ref().unwrap(),
                    );
                }
                "missing_application" => f
                    .key(r"User\Applications")
                    .delete_subkey_all("old0.exe")
                    .unwrap(),
                _ => unreachable!(),
            }
            let read = || {
                RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(format!(
                        r"{}\User\Applications\old0.exe\SupportedTypes",
                        f.base
                    ))
                    .ok()
                    .and_then(|key| read_value(&key, &entry.value_name).unwrap())
            };
            let before = read();
            let error = manager.apply(&plan.token).unwrap_err();
            assert!(
                !error.contains("expired") && !error.contains("token"),
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
fn leftover_companion_protects_unsupported_evidence_and_does_not_weaken_legacy_backups() {
    for mutation in [
        "mapping",
        "expanded_mapping",
        "expanded_path",
        "path_list",
        "path",
        "activation",
        "empty_evidence",
        "oversized",
        "duplicate",
    ] {
        let f = Fixture::new();
        let mut entry = f.companion_entries().remove(0);
        let companion = entry
            .leftover_state
            .as_mut()
            .unwrap()
            .supported_type
            .as_mut()
            .unwrap()
            .app_paths
            .as_mut()
            .unwrap();
        match mutation {
            "mapping" => {
                companion
                    .values
                    .iter_mut()
                    .find(|v| v.name.is_empty())
                    .unwrap()
                    .value = text(r"C:\Other\old0.exe")
            }
            "expanded_mapping" => {
                companion
                    .values
                    .iter_mut()
                    .find(|v| v.name.is_empty())
                    .unwrap()
                    .value
                    .kind = 2
            }
            "expanded_path" => {
                companion
                    .values
                    .iter_mut()
                    .find(|v| v.name.eq_ignore_ascii_case("Path"))
                    .unwrap()
                    .value
                    .kind = 2
            }
            "path_list" => {
                companion
                    .values
                    .iter_mut()
                    .find(|v| v.name.eq_ignore_ascii_case("Path"))
                    .unwrap()
                    .value = text(&format!("{};C:\\Other", f.directory(0)))
            }
            "path" => {
                companion
                    .values
                    .iter_mut()
                    .find(|v| v.name.eq_ignore_ascii_case("Path"))
                    .unwrap()
                    .value = text(r"C:\Other")
            }
            "activation" => companion.values.push(NamedValue {
                name: "UseUrl".into(),
                value: StoredValue {
                    kind: 4,
                    bytes: vec![1, 0, 0, 0],
                },
            }),
            "empty_evidence" => companion
                .values
                .retain(|v| !v.name.is_empty() && !v.name.eq_ignore_ascii_case("Path")),
            "oversized" => companion.values.push(NamedValue {
                name: "TooLarge".into(),
                value: text(&"a".repeat(9000)),
            }),
            "duplicate" => companion.values.push(companion.values[0].clone()),
            _ => unreachable!(),
        }
        let storage = tempfile::tempdir().unwrap();
        let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
        assert!(manager.prepare_quarantine(&entry).is_err(), "{mutation}");
        assert_eq!(std::fs::read_dir(storage.path()).unwrap().count(), 0);
    }
    let f = Fixture::new();
    let entries = f.type_entries();
    f.put(
        r"User\AppPaths\old0.exe",
        "",
        &text(&format!(r"{}\old0.exe", f.directory(0))),
    );
    let storage = tempfile::tempdir().unwrap();
    let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
    assert_eq!(entries[0].leftover_state.as_ref().unwrap().schema(), 25);
    assert!(manager
        .prepare_quarantine(&entries[0])
        .unwrap_err()
        .contains("counterpart"));
}

impl Fixture {
    fn companion_entries_at(&self, i: usize) -> Vec<RegistryEntry> {
        if i == 0 {
            return self.companion_entries();
        }
        let path = format!(r"User\AppPaths\old{i}.exe");
        if i >= 2 {
            self.put(&path, "pAth", &text(&format!("{}\\", self.directory(i))));
            self.key(&path).set_value("Keep", &17u32).unwrap();
            let owner = format!(r"User\Uninstall\Owned{i}");
            for (name, value) in [
                ("DisplayName", format!("Owned companion {i}")),
                ("InstallLocation", self.directory(i)),
                (
                    "UninstallString",
                    format!("\"{}\\uninstall.exe\" /remove", self.directory(i)),
                ),
            ] {
                self.put(&owner, name, &text(&value));
            }
        }
        let base = self.entry(i);
        self.put(
            &path,
            "",
            &text(&format!(r"{}\old{i}.exe", self.directory(i))),
        );
        self.put(&path, "LicenseMarker", &text("COMPANION-PRESERVE"));
        let application = format!(r"User\Applications\old{i}.exe");
        self.put(
            &application,
            "FriendlyAppName",
            &text(&format!("Owned companion {i}")),
        );
        self.put(&application, "LicenseMarker", &text("APPLICATION-PRESERVE"));
        self.put(
            &format!(r"{application}\shell\open\command"),
            "",
            &text(&format!(r#""{}\old{i}.exe" "%1" %*"#, self.directory(i))),
        );
        for (name, bytes) in [
            (".ONE", vec![0, 0]),
            (".two", vec![0, 0, 0, 0]),
            (".keep", text("PRESERVE").bytes),
        ] {
            self.put(
                &format!(r"{application}\SupportedTypes"),
                name,
                &StoredValue { kind: 1, bytes },
            );
        }
        let mut state = self
            .store()
            .leftover_type_state(&format!("old{i}.exe"), None)
            .unwrap();
        state.guard.app_paths = self
            .store()
            .leftover_type_companion(&format!("old{i}.exe"), None)
            .unwrap()
            .map(Box::new);
        state
            .hints
            .iter()
            .filter(|h| h.name != ".keep")
            .map(|hint| {
                let mut entry = base.clone();
                let app = entry.leftover_state.as_mut().unwrap();
                app.value_name = hint.name.clone();
                app.application_values = state.application_values.clone();
                app.supported_type = Some(Box::new(state.guard.clone()));
                entry.id = format!("companion{i}|{}", hint.name);
                entry.value_name = hint.name.clone();
                entry.raw_value = String::new();
                entry.key_path = app.key_path();
                entry.snapshot = Some(hint.value.clone());
                entry.leftover_evidence =
                    Some(app.verify_original(&hint.value, &LocalPathProbe).unwrap());
                entry
            })
            .collect()
    }
}

#[test]
fn leftover_companion_full_clean_handles_128_hints_and_exact_restart_recovery() {
    let f = Fixture::new();
    let entries: Vec<_> = (0..64).flat_map(|i| f.companion_entries_at(i)).collect();
    let originals: Vec<_> = (0..64)
        .map(|i| {
            f.store()
                .leftover_type_companion(&format!("old{i}.exe"), None)
                .unwrap()
        })
        .collect();
    let selected = crate::changes::select_clean_entries(&entries, "full", &[], None).unwrap();
    assert_eq!(selected.len(), 128);
    let storage = tempfile::tempdir().unwrap();
    let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
    let plan = manager.prepare_clean(&selected, "full").unwrap();
    assert_eq!(plan.items.len(), 128);
    let result = manager.apply_clean(&plan.token).unwrap();
    assert!(result.failed.is_none());
    assert_eq!(result.completed.len(), 128);
    assert_eq!(manager.inventory().unwrap().backups.len(), 128);
    drop(manager);
    let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
    for record in result.completed.iter().rev() {
        let plan = manager.prepare_restore(&record.backup_id).unwrap();
        manager.apply(&plan.token).unwrap();
    }
    for entry in entries {
        assert_eq!(
            f.store()
                .read_leftover(entry.leftover_state.as_ref().unwrap())
                .unwrap(),
            entry.snapshot
        );
    }
    for (i, original) in originals.iter().enumerate() {
        assert_eq!(
            &f.store()
                .leftover_type_companion(&format!("old{i}.exe"), None)
                .unwrap(),
            original
        );
    }
}

#[test]
fn leftover_companion_backup_failures_and_corruption_do_not_mutate_registrations() {
    let f = Fixture::new();
    let entry = f.companion_entries().remove(0);
    let storage = tempfile::tempdir().unwrap();
    let blocked = storage.path().join("blocked");
    std::fs::write(&blocked, b"PRESERVE").unwrap();
    let mut manager = ChangeManager::new(f.store(), blocked.clone(), LocalPathProbe);
    let plan = manager.prepare_quarantine(&entry).unwrap();
    assert!(manager.apply(&plan.token).is_err());
    assert_eq!(
        f.store()
            .read_leftover(entry.leftover_state.as_ref().unwrap())
            .unwrap(),
        entry.snapshot
    );
    let directory = storage.path().join("backups");
    let mut manager = ChangeManager::new(f.store(), directory.clone(), LocalPathProbe);
    let plan = manager.prepare_quarantine(&entry).unwrap();
    let id = manager.apply(&plan.token).unwrap().backup_id;
    let file = directory.join(format!("{id}.json"));
    let original = std::fs::read(&file).unwrap();
    for mutation in ["schema", "checksum", "original", "companion"] {
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        assert_eq!(value["schemaVersion"], 27);
        match mutation {
            "schema" => value["schemaVersion"] = 25.into(),
            "checksum" => value["integritySha256"] = "0".repeat(64).into(),
            "original" => value["original"]["bytes"] = serde_json::json!([0, 0, 0, 0]),
            "companion" => {
                value["leftover"]["supportedType"]["appPaths"]["values"][0]["name"] =
                    "DropTarget".into()
            }
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        std::fs::write(&file, &bytes).unwrap();
        assert!(manager.prepare_restore(&id).is_err(), "{mutation}");
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        assert!(read_value(
            &f.key(r"User\Applications\old0.exe\SupportedTypes"),
            &entry.value_name
        )
        .unwrap()
        .is_none());
    }
    std::fs::write(&file, original).unwrap();
    let plan = manager.prepare_restore(&id).unwrap();
    manager.apply(&plan.token).unwrap();
}
