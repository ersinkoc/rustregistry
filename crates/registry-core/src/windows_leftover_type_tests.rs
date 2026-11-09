use super::*;
#[test]
fn leftover_supported_types_changes_after_review_never_overwrite_values_or_backups() {
    for mutation in [
        "directory",
        "command",
        "metadata",
        "anchor",
        "duplicate",
        "user_path",
        "machine32",
        "machine64",
        "machine_anchor",
        "value",
        "case",
        "activation",
        "icon",
        "nested",
        "missing_key",
        "missing_app",
    ] {
        for restore in [false, true] {
            let f = Fixture::new();
            let entries = f.type_entries();
            let e = &entries[0];
            let dir = tempfile::tempdir().unwrap();
            let mut m = ChangeManager::new(f.store(), dir.path().into(), LocalPathProbe);
            let p = m.prepare_quarantine(e).unwrap();
            let (p, backup) = if restore {
                let id = m.apply(&p.token).unwrap().backup_id;
                let file = dir.path().join(format!("{id}.json"));
                let bytes = std::fs::read(&file).unwrap();
                (m.prepare_restore(&id).unwrap(), Some((file, bytes)))
            } else {
                (p, None)
            };
            match mutation {
                "directory" => std::fs::create_dir(f.directory(0)).unwrap(),
                "command" => f.put(
                    r"User\Applications\old0.exe\shell\open\command",
                    "",
                    &text(r#""C:\Changed\old0.exe" "%1""#),
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
                "user_path" => {
                    f.key(r"User\AppPaths\old0.exe");
                }
                "machine32" => {
                    f.key(r"Machine32\Applications\old0.exe");
                }
                "machine64" => {
                    f.key(r"Machine64\AppPaths\old0.exe");
                }
                "machine_anchor" => {
                    f.key(r"Machine64\Uninstall\Owned0");
                }
                "value" => f.put(
                    r"User\Applications\old0.exe\SupportedTypes",
                    &e.value_name,
                    &text("new value"),
                ),
                "case" => {
                    f.key(r"User\Applications\old0.exe\SupportedTypes")
                        .delete_value(&e.value_name)
                        .ok();
                    f.put(
                        r"User\Applications\old0.exe\SupportedTypes",
                        &e.value_name.to_lowercase(),
                        &StoredValue {
                            kind: 1,
                            bytes: vec![0, 0],
                        },
                    );
                }
                "activation" => {
                    f.key(r"User\Applications\old0.exe\DropTarget");
                }
                "icon" => f.put(
                    r"User\Applications\old0.exe\DefaultIcon",
                    "",
                    &text("new icon"),
                ),
                "nested" => {
                    f.key(r"User\Applications\old0.exe\SupportedTypes\Nested");
                }
                "missing_key" => f
                    .key(r"User\Applications\old0.exe")
                    .delete_subkey_all("SupportedTypes")
                    .unwrap(),
                "missing_app" => f
                    .key(r"User\Applications")
                    .delete_subkey_all("old0.exe")
                    .unwrap(),
                _ => unreachable!(),
            }
            let read = || {
                f.key(r"User\Applications")
                    .open_subkey(r"old0.exe\SupportedTypes")
                    .ok()
                    .and_then(|k| read_value(&k, &e.value_name).unwrap())
            };
            let before = read();
            assert!(m.apply(&p.token).is_err(), "{mutation}/{restore}");
            assert_eq!(read(), before);
            if let Some((file, bytes)) = backup {
                assert_eq!(std::fs::read(file).unwrap(), bytes);
            } else {
                assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
            }
        }
    }
}
#[test]
fn leftover_supported_types_reject_unsupported_hints_and_mixed_namespaces() {
    let f = Fixture::new();
    let entries = f.type_entries();
    let app = entries[0].leftover_state.as_ref().unwrap();
    for hint in [
        StoredValue {
            kind: 0,
            bytes: vec![],
        },
        StoredValue {
            kind: 2,
            bytes: vec![0, 0],
        },
        StoredValue {
            kind: 1,
            bytes: vec![],
        },
        StoredValue {
            kind: 1,
            bytes: vec![0],
        },
        text("nonempty"),
    ] {
        assert!(app.verify_original(&hint, &LocalPathProbe).is_err());
    }
    for name in ["Path", "", ".bad\\name", ".a.b", ".unicodeé", ".", " .one"] {
        let mut a = app.clone();
        a.value_name = name.into();
        assert!(a
            .verify_original(entries[0].snapshot.as_ref().unwrap(), &LocalPathProbe)
            .is_err());
    }
    let mut mixed = app.clone();
    mixed.path_list = Some(text(&format!("{};C:\\Other", f.directory(0))));
    assert!(mixed.validate().is_err());
    let mut protected = app.clone();
    protected.application_values.push(NamedValue {
        name: "IsHostApp".into(),
        value: StoredValue {
            kind: 4,
            bytes: vec![1, 0, 0, 0],
        },
    });
    assert!(protected.validate().is_err());
}
#[test]
fn leftover_supported_types_backup_failures_and_tampering_are_non_destructive() {
    let f = Fixture::new();
    let entries = f.type_entries();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-directory");
    std::fs::write(&file, b"preserve").unwrap();
    let mut blocked = ChangeManager::new(f.store(), file.clone(), LocalPathProbe);
    let p = blocked.prepare_quarantine(&entries[0]).unwrap();
    assert!(blocked.apply(&p.token).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"preserve");
    let mut m = ChangeManager::new(f.store(), dir.path().join("backups"), LocalPathProbe);
    let p = m.prepare_quarantine(&entries[0]).unwrap();
    let id = m.apply(&p.token).unwrap().backup_id;
    let file = dir.path().join("backups").join(format!("{id}.json"));
    let bytes = std::fs::read(&file).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for field in ["schemaVersion", "valueName", "original", "integritySha256"] {
        let mut corrupt = original.clone();
        corrupt[field] = match field {
            "schemaVersion" => serde_json::json!(24),
            "valueName" => serde_json::json!(".other"),
            "original" => serde_json::json!({"kind":1,"bytes":[65,0,0,0]}),
            _ => serde_json::json!("invalid"),
        };
        std::fs::write(&file, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(m.prepare_restore(&id).is_err());
    }
    std::fs::write(&file, bytes).unwrap();
    let p = m.prepare_restore(&id).unwrap();
    m.apply(&p.token).unwrap();
    assert_eq!(
        f.store()
            .leftover_type_state("old0.exe", None)
            .unwrap()
            .hints
            .len(),
        3
    );
}
