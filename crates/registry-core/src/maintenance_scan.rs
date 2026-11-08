use super::*;
use crate::{
    changes::{NamedValue, StoredValue},
    maintenance::*,
    windows_changes::read_maintenance_snapshot,
};

pub(super) fn scan_maintenance(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let kind = if source.category == Category::MuiCache {
        MaintenanceKind::MuiCache
    } else if source.path == RUN_HISTORY_KEY {
        MaintenanceKind::RunHistory
    } else {
        MaintenanceKind::TypedPaths
    };
    let mut items = std::collections::BTreeMap::new();
    let mut unknown_cache_fields = Vec::new();
    if kind.history() {
        let item = if kind == MaintenanceKind::RunHistory {
            "RunMRU"
        } else {
            "TypedPaths"
        };
        items.insert(
            item.to_string(),
            (
                item.to_string(),
                true,
                read_maintenance_snapshot(root, kind, item),
            ),
        );
    } else {
        let nested = root.enum_keys().next().is_some();
        for (index, item) in root.enum_values().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                scope.status = "cancelled".into();
                break;
            }
            if index >= MAX_ENTRIES_PER_SCOPE {
                scope.status = "limited".into();
                scope
                    .notes
                    .push("MUI cache inventory reached its 10,000-value limit.".into());
                break;
            }
            match item {
                Ok((name, value)) => {
                    let target = cache_target(&name).unwrap_or(&name).to_string();
                    let known = cache_target(&name).is_some();
                    if !known {
                        unknown_cache_fields.push(name.to_ascii_lowercase());
                    }
                    let (_, _, snapshot) =
                        items.entry(target.to_ascii_lowercase()).or_insert_with(|| {
                            (
                                target,
                                known,
                                if nested {
                                    Err("Nested or unreadable cache keys remain read-only.".into())
                                } else {
                                    Ok(MaintenanceSnapshot {
                                        values: vec![],
                                        preserved: vec![],
                                    })
                                },
                            )
                        });
                    if value.bytes.len() > MAX_VALUE_BYTES {
                        *snapshot = Err("Oversized cache values remain read-only.".into());
                    } else if let Ok(snapshot) = snapshot {
                        snapshot.values.push(NamedValue {
                            name,
                            value: StoredValue {
                                kind: value.vtype as u32,
                                bytes: value.bytes.into_owned(),
                            },
                        });
                    }
                }
                Err(e) => scope.notes.push(read_error(&e)),
            }
        }
    }
    for (_, (item, known, mut snapshot)) in items {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if known
            && !kind.history()
            && unknown_cache_fields
                .iter()
                .any(|name| name.starts_with(&format!("{}.", item.to_ascii_lowercase())))
        {
            snapshot = Err("Unknown cache fields for this executable remain read-only.".into());
        }
        let mut entry = make_entry(
            source,
            "",
            if kind.history() {
                if kind == MaintenanceKind::RunHistory {
                    "Run dialog registry history".into()
                } else {
                    "Explorer typed-path registry history".into()
                }
            } else {
                item.rsplit('\\').next().unwrap_or(&item).into()
            },
            &item,
            Err("Maintenance snapshot not yet assessed.".into()),
            environment,
            probe,
        );
        entry.value_type = "REG_SZ snapshot".into();
        match snapshot {
            Ok(mut snapshot) => {
                snapshot.values.sort_by_key(|v| v.name.to_ascii_lowercase());
                let app = MaintenanceBackup {
                    kind,
                    item: item.clone(),
                    snapshot,
                };
                entry.raw_value = app.summary().unwrap_or_else(|_| {
                    "Unsupported registry data; raw values are preserved.".into()
                });
                if kind.history() {
                    let validation = app.validate();
                    entry.assessment = if app.snapshot.values.is_empty()
                        || (kind == MaintenanceKind::RunHistory
                            && app.snapshot.values.iter().all(|v| {
                                v.name == "MRUList"
                                    && maintenance_text(&v.value).is_ok_and(|s| s.is_empty())
                            })) {
                        Assessment{status:EntryStatus::Found,code:"history_empty".into(),explanation:"This registry history has no stored items. No cleaning is needed; other Windows history stores are not inspected.".into(),target:None}
                    } else if let Err(reason) = validation {
                        Assessment {
                            status: EntryStatus::Unknown,
                            code: "history_unverified".into(),
                            explanation: reason,
                            target: None,
                        }
                    } else {
                        Assessment{status:EntryStatus::Found,code:"optional_history".into(),explanation:"Optional personal history, not a registry error. An explicit individual or selected review can back up and clear this registry snapshot. Quick Clean excludes it. Explorer may retain cached suggestions, and other history stores and files remain untouched.".into(),target:None}
                    };
                } else if known && app.snapshot.validate_text().is_ok() {
                    entry.assessment = analyze_target(&item, TargetKind::File, environment, probe);
                    if entry.assessment.status == EntryStatus::Review {
                        entry.assessment.code = "cache_target_missing".into();
                        entry.assessment.explanation="The cached application's literal local executable was not found. This is cached display metadata, not an installed-application record; clearing it does not uninstall software or change default handlers.".into();
                    }
                } else {
                    entry.assessment=Assessment{status:EntryStatus::Unknown,code:"cache_metadata_unverified".into(),explanation:"Only recognized per-executable FriendlyAppName and ApplicationCompany cache fields support cleaning. This metadata is preserved.".into(),target:None};
                }
                if (kind.history() && entry.assessment.code == "optional_history")
                    || (!kind.history() && entry.assessment.code == "cache_target_missing")
                {
                    let eligibility = app.validate();
                    match eligibility {
                        Ok(()) => {
                            entry.maintenance_repairable = true;
                            entry.maintenance_state = Some(app);
                        }
                        Err(reason) => entry
                            .assessment
                            .explanation
                            .push_str(&format!(" Cleaning unavailable: {reason}")),
                    }
                }
            }
            Err(reason) => {
                entry.assessment = Assessment {
                    status: EntryStatus::Unknown,
                    code: "maintenance_unverified".into(),
                    explanation: reason,
                    target: None,
                };
            }
        }
        entries.push(entry);
    }
    scope.notes.push(if kind.history(){"History is optional maintenance and never contributes a missing-target finding or enters Quick Clean. Only this registry store is covered; Explorer's cached UI and other history sources are not cleared."}else{"Recognized cache values are grouped by executable. Missing, disconnected or inaccessible evidence is rechecked before cleaning; application settings and files are preserved. Windows can recreate cache values later."}.into());
}

#[cfg(test)]
mod tests {
    use super::*;
    struct NoProbe;
    impl PathProbe for NoProbe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            panic!("History scanning must not resolve commands or paths")
        }
    }
    struct CacheProbe;
    impl PathProbe for CacheProbe {
        fn probe(&self, path: &str, _: TargetKind) -> ProbeResult {
            if path.to_ascii_lowercase().ends_with("found.exe") {
                ProbeResult::Found
            } else {
                ProbeResult::Missing
            }
        }
    }
    fn inspect(
        root: &RegKey,
        path: &'static str,
        category: Category,
        probe: &impl PathProbe,
    ) -> Vec<RegistryEntry> {
        let source = Source {
            category,
            hive: "HKCU",
            path,
            view: "shared",
            flag: KEY_WOW64_64KEY,
        };
        let mut entries = vec![];
        let mut scope = ScopeResult {
            id: "owned".into(),
            category,
            hive: "HKCU".into(),
            key_path: path.into(),
            view: "shared".into(),
            status: "complete".into(),
            entries: 0,
            notes: vec![],
        };
        scan_maintenance(
            &source,
            root,
            &AtomicBool::new(false),
            &Environment::current(),
            &mut entries,
            &mut scope,
            probe,
        );
        entries
    }
    #[test]
    fn history_inventory_is_optional_bounded_and_read_only_without_file_probes() {
        let base = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
        let root = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&base)
            .unwrap()
            .0;
        root.set_value("", &"").unwrap();
        root.set_value("a", &"never execute\\1").unwrap();
        root.set_value("MRUList", &"a").unwrap();
        let before: Vec<_> = root
            .enum_values()
            .map(|v| {
                let (n, v) = v.unwrap();
                (n, v.vtype, v.bytes.into_owned())
            })
            .collect();
        let entries = inspect(&root, RUN_HISTORY_KEY, Category::UsageHistory, &NoProbe);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].assessment.status, EntryStatus::Found);
        assert_eq!(entries[0].assessment.code, "optional_history");
        assert!(entries[0].maintenance_repairable);
        let after: Vec<_> = root
            .enum_values()
            .map(|v| {
                let (n, v) = v.unwrap();
                (n, v.vtype, v.bytes.into_owned())
            })
            .collect();
        assert_eq!(before, after);
        root.set_value("MRUList", &"aa").unwrap();
        assert!(
            !inspect(&root, RUN_HISTORY_KEY, Category::UsageHistory, &NoProbe)[0]
                .maintenance_repairable
        );
        root.delete_value("a").unwrap();
        root.set_value("MRUList", &"").unwrap();
        let empty = inspect(&root, RUN_HISTORY_KEY, Category::UsageHistory, &NoProbe);
        assert_eq!(empty[0].assessment.code, "history_empty");
        assert!(!empty[0].maintenance_repairable);
        drop(root);
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(base)
            .unwrap();
    }
    #[test]
    fn cache_inventory_groups_known_fields_and_preserves_existing_unknown_and_unsupported_records()
    {
        let base = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
        let root = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&base)
            .unwrap()
            .0;
        for name in [
            r"C:\Owned\missing.exe.FriendlyAppName",
            r"C:\Owned\missing.exe.ApplicationCompany",
            r"C:\Owned\found.exe.FriendlyAppName",
            r"C:\Owned\complex.exe.FriendlyAppName",
            r"C:\Owned\complex.exe.NewMetadata",
        ] {
            root.set_value(name, &"Display label").unwrap();
        }
        root.set_value("LangID", &1033u32).unwrap();
        let entries = inspect(&root, MUI_CACHE_KEY, Category::MuiCache, &CacheProbe);
        let missing = entries
            .iter()
            .find(|e| e.value_name == r"C:\Owned\missing.exe")
            .unwrap();
        assert!(missing.maintenance_repairable);
        assert_eq!(
            missing
                .maintenance_state
                .as_ref()
                .unwrap()
                .snapshot
                .values
                .len(),
            2
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.value_name == r"C:\Owned\found.exe")
                .unwrap()
                .assessment
                .status,
            EntryStatus::Found
        );
        assert!(
            !entries
                .iter()
                .find(|e| e.value_name == r"C:\Owned\complex.exe")
                .unwrap()
                .maintenance_repairable
        );
        assert_eq!(root.get_value::<u32, _>("LangID").unwrap(), 1033);
        assert_eq!(root.enum_values().count(), 6);
        drop(root);
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(base)
            .unwrap();
        let sources = super::super::sources();
        assert_eq!(sources.len(), 66);
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::UsageHistory)
                .count(),
            2
        );
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::MuiCache)
                .count(),
            1
        );
    }
}
