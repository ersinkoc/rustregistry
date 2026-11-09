use super::{open_registration_path, WindowsRegistryStore};
use crate::{
    changes::{NamedValue, StoredValue},
    maintenance::*,
};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

pub(crate) fn open_maintenance_source(
    kind: MaintenanceKind,
    tx: Option<&Transaction>,
    write: bool,
) -> Result<Option<RegKey>, String> {
    if kind != MaintenanceKind::MuiCache {
        return open_registration_path(HKEY_CURRENT_USER, kind.path(), KEY_WOW64_64KEY, tx, write);
    }
    // Follow only the fixed Windows-managed Classes hive alias. Every subsequent
    // component is opened with OPEN_LINK; arbitrary cache links are rejected.
    let mut key =
        super::applications::root(&RegKey::predef(HKEY_CURRENT_USER), r"Software\Classes", tx)?;
    let parts = [
        "Local Settings",
        "Software",
        "Microsoft",
        "Windows",
        "Shell",
        "MuiCache",
    ];
    for (index, part) in parts.iter().enumerate() {
        let Some(next) =
            super::applications::open(&key, part, tx, write && index + 1 == parts.len())?
        else {
            return Ok(None);
        };
        key = next;
    }
    Ok(Some(key))
}

pub(crate) fn read_maintenance_snapshot(
    key: &RegKey,
    kind: MaintenanceKind,
    item: &str,
) -> Result<MaintenanceSnapshot, String> {
    if key.enum_keys().next().is_some() {
        return Err("Nested or unreadable maintenance keys remain read-only.".into());
    }
    let mut snapshot = MaintenanceSnapshot {
        values: vec![],
        preserved: vec![],
    };
    let mut size = 0;
    for (index, value) in key.enum_values().enumerate() {
        if index >= if kind.history() { 28 } else { 10000 } {
            return Err("Maintenance inventory exceeds its read limit.".into());
        }
        let (name, value) =
            value.map_err(|_| "Maintenance values could not be read completely.")?;
        if kind == MaintenanceKind::MuiCache {
            if !name
                .to_ascii_lowercase()
                .starts_with(&format!("{}.", item.to_ascii_lowercase()))
            {
                continue;
            }
            if !cache_target(&name).is_some_and(|p| p.eq_ignore_ascii_case(item)) {
                return Err("Unknown fields for this cached application remain read-only.".into());
            }
        }
        size += name.len() + value.bytes.len();
        if size > 16384 {
            return Err("Maintenance values exceed the backup size limit.".into());
        }
        let named = NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        };
        if kind.history() && named.name.is_empty() {
            snapshot.preserved.push(named);
        } else {
            snapshot.values.push(named);
        }
    }
    snapshot.values.sort_by_key(|v| v.name.to_ascii_lowercase());
    Ok(snapshot)
}

fn read_cache_batch(
    key: &RegKey,
    apps: &[MaintenanceBackup],
    limit: usize,
) -> Result<Vec<Result<MaintenanceSnapshot, String>>, String> {
    if apps.len() > limit || key.enum_keys().next().is_some() {
        return Err("Nested, unreadable or oversized cache batches remain read-only.".into());
    }
    let mut indices = std::collections::HashMap::<String, Vec<usize>>::new();
    for (index, app) in apps.iter().enumerate() {
        app.validate()?;
        indices
            .entry(app.item.to_ascii_lowercase())
            .or_default()
            .push(index);
    }
    let mut states: Vec<Result<MaintenanceSnapshot, String>> = apps
        .iter()
        .map(|_| {
            Ok(MaintenanceSnapshot {
                values: vec![],
                preserved: vec![],
            })
        })
        .collect();
    let mut sizes = vec![0usize; apps.len()];
    for (index, value) in key.enum_values().enumerate() {
        if index >= 10000 {
            return Err("Maintenance inventory exceeds its read limit.".into());
        }
        let (name, value) =
            value.map_err(|_| "Maintenance values could not be read completely.")?;
        if let Some(target) = cache_target(&name) {
            if let Some(matches) = indices.get(&target.to_ascii_lowercase()) {
                for &i in matches {
                    sizes[i] += name.len() + value.bytes.len();
                    if sizes[i] > 16384 {
                        states[i] = Err("Maintenance values exceed the backup size limit.".into());
                    } else if let Ok(state) = &mut states[i] {
                        state.values.push(NamedValue {
                            name: name.clone(),
                            value: StoredValue {
                                kind: value.vtype.clone() as u32,
                                bytes: value.bytes.to_vec(),
                            },
                        });
                    }
                }
            }
        } else {
            let lower = name.to_ascii_lowercase();
            for (item, matches) in &indices {
                if lower.starts_with(&format!("{item}.")) {
                    for &i in matches {
                        states[i] = Err(
                            "Unknown fields for this cached application remain read-only.".into(),
                        );
                    }
                }
            }
        }
    }
    for state in states.iter_mut().flatten() {
        state.values.sort_by_key(|v| v.name.to_ascii_lowercase());
    }
    Ok(states)
}
impl WindowsRegistryStore {
    pub(crate) fn maintenance_batch(
        &self,
        apps: &[MaintenanceBackup],
    ) -> Vec<Result<MaintenanceSnapshot, String>> {
        if apps.is_empty() {
            return vec![];
        }
        if apps.iter().any(|app| app.kind != MaintenanceKind::MuiCache) {
            return apps.iter().map(|app| self.maintenance_state(app)).collect();
        }
        match self
            .maintenance_root(MaintenanceKind::MuiCache, None, false)
            .and_then(|root| read_cache_batch(&root, apps, crate::changes::MAX_CLEAN_ENTRIES))
        {
            Ok(states) => states,
            Err(reason) => apps.iter().map(|_| Err(reason.clone())).collect(),
        }
    }
    pub(crate) fn maintenance_inventory(
        &self,
        apps: &[MaintenanceBackup],
    ) -> Vec<Result<MaintenanceSnapshot, String>> {
        if apps.is_empty() {
            return vec![];
        }
        if apps.iter().any(|app| app.kind != MaintenanceKind::MuiCache) {
            return apps
                .iter()
                .map(|_| {
                    Err("Only display-cache records support the shared inventory snapshot.".into())
                })
                .collect();
        }
        match self
            .maintenance_root(MaintenanceKind::MuiCache, None, false)
            .and_then(|root| read_cache_batch(&root, apps, crate::changes::MAX_BACKUP_ENTRIES))
        {
            Ok(states) => states,
            Err(reason) => apps.iter().map(|_| Err(reason.clone())).collect(),
        }
    }
    fn maintenance_root(
        &self,
        kind: MaintenanceKind,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<RegKey, String> {
        #[cfg(test)]
        let path = self
            .maintenance_test_root
            .as_ref()
            .map(|p| format!(r"{p}\{}", kind.scope()));
        #[cfg(test)]
        let path = path.as_deref().unwrap_or(kind.path());
        #[cfg(not(test))]
        let path = kind.path();
        let root = if path == kind.path() {
            open_maintenance_source(kind, tx, write)?
        } else {
            open_registration_path(HKEY_CURRENT_USER, path, KEY_WOW64_64KEY, tx, write)?
        };
        root.ok_or("The existing maintenance key is missing; no key will be recreated.".into())
    }
    pub(crate) fn maintenance_state(
        &self,
        app: &MaintenanceBackup,
    ) -> Result<MaintenanceSnapshot, String> {
        read_maintenance_snapshot(
            &self.maintenance_root(app.kind, None, false)?,
            app.kind,
            &app.item,
        )
    }
    pub(crate) fn maintenance_access(&self, app: &MaintenanceBackup) -> Result<(), String> {
        self.maintenance_root(app.kind, None, true).map(|_| ())
    }
    pub(crate) fn exchange_maintenance(
        &self,
        app: &MaintenanceBackup,
        expected: &MaintenanceSnapshot,
        replacement: &MaintenanceSnapshot,
    ) -> Result<(), String> {
        app.validate()?;
        if !((expected == &app.snapshot && replacement == &app.cleared())
            || (expected == &app.cleared() && replacement == &app.snapshot))
        {
            return Err("Only exact maintenance clearing or restoration is supported.".into());
        }
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        let key = self.maintenance_root(app.kind, Some(&tx), true)?;
        if read_maintenance_snapshot(&key, app.kind, &app.item)? != *expected {
            return Err("Maintenance data changed. No existing value was overwritten.".into());
        }
        if replacement.values.is_empty() {
            for v in &expected.values {
                key.delete_value(&v.name)
                    .map_err(|e| format!("Maintenance clearing failed: {e}"))?;
            }
        } else {
            for v in &replacement.values {
                key.set_raw_value(
                    &v.name,
                    &RegValue {
                        vtype: REG_SZ,
                        bytes: Cow::Borrowed(&v.value.bytes),
                    },
                )
                .map_err(|e| format!("Maintenance restore failed: {e}"))?;
            }
        }
        tx.commit()
            .map_err(|e| format!("Maintenance transaction did not commit: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        changes::{is_quick_clean_candidate, ChangeManager, RegistryStore},
        Category, PathProbe, ProbeResult, RegistryEntry, TargetKind,
    };
    struct Missing;
    impl PathProbe for Missing {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            ProbeResult::Missing
        }
    }
    struct NoProbe;
    impl PathProbe for NoProbe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            panic!("History must never probe or run its stored commands")
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
        fn key(&self, kind: MaintenanceKind) -> RegKey {
            RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\{}", self.base, kind.scope()))
                .unwrap()
                .0
        }
        fn store(&self) -> WindowsRegistryStore {
            WindowsRegistryStore {
                maintenance_test_root: Some(self.base.clone()),
                ..Default::default()
            }
        }
        fn put(&self, kind: MaintenanceKind, name: &str, text: &str) {
            self.key(kind)
                .set_raw_value(
                    name,
                    &RegValue {
                        vtype: REG_SZ,
                        bytes: Cow::Owned(
                            text.encode_utf16()
                                .chain([0, 0])
                                .flat_map(u16::to_le_bytes)
                                .collect(),
                        ),
                    },
                )
                .unwrap();
        }
        fn app(&self, kind: MaintenanceKind, item: &str) -> MaintenanceBackup {
            let snapshot = read_maintenance_snapshot(&self.key(kind), kind, item).unwrap();
            MaintenanceBackup {
                kind,
                item: item.into(),
                snapshot,
            }
        }
        fn entry(&self, app: MaintenanceBackup) -> RegistryEntry {
            let history = app.kind.history();
            let mut e:RegistryEntry=serde_json::from_value(serde_json::json!({"id":format!("{}|{}",app.kind.scope(),app.item),"name":app.item,"category":if history{"usage_history"}else{"mui_cache"},"hive":"HKCU","view":"shared","keyPath":app.kind.path(),"valueName":app.item,"valueType":"REG_SZ snapshot","rawValue":app.summary().unwrap(),"publisher":null,"version":null,"assessment":{"status":if history{"found"}else{"review"},"code":if history{"optional_history"}else{"cache_target_missing"},"explanation":"Owned fixture","target":null},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"maintenanceRepairable":true})).unwrap();
            e.maintenance_state = Some(app);
            e
        }
        fn cache(&self, item: &str) -> MaintenanceBackup {
            self.put(
                MaintenanceKind::MuiCache,
                &format!("{item}.FriendlyAppName"),
                "Owned application",
            );
            self.put(
                MaintenanceKind::MuiCache,
                &format!("{item}.ApplicationCompany"),
                "Owned publisher",
            );
            self.app(MaintenanceKind::MuiCache, item)
        }
        fn history(&self, kind: MaintenanceKind) -> MaintenanceBackup {
            self.put(kind, "", "");
            if kind == MaintenanceKind::RunHistory {
                self.put(kind, "a", "do not execute this command\\1");
                self.put(kind, "b", "私人 history\\1");
                self.put(kind, "MRUList", "ba");
            } else {
                self.put(kind, "url1", r"C:\Owned path");
                self.put(kind, "url3", r"\\offline\never-probe");
            }
            self.app(
                kind,
                if kind == MaintenanceKind::RunHistory {
                    "RunMRU"
                } else {
                    "TypedPaths"
                },
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.base);
        }
    }
    #[test]
    fn batch_review_reads_cache_once_and_apply_still_rechecks_changed_live_values() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        struct CountingStore {
            native: WindowsRegistryStore,
            bulk: Arc<AtomicUsize>,
            individual: Arc<AtomicUsize>,
        }
        impl RegistryStore for CountingStore {
            fn read(&self, name: &str) -> Result<Option<StoredValue>, String> {
                self.native.read(name)
            }
            fn compare_exchange(
                &self,
                name: &str,
                expected: Option<&StoredValue>,
                replacement: Option<&StoredValue>,
            ) -> Result<(), String> {
                self.native.compare_exchange(name, expected, replacement)
            }
            fn read_maintenance_batch(
                &self,
                apps: &[MaintenanceBackup],
            ) -> Vec<Result<MaintenanceSnapshot, String>> {
                self.bulk.fetch_add(1, Ordering::Relaxed);
                self.native.read_maintenance_batch(apps)
            }
            fn read_maintenance(
                &self,
                app: &MaintenanceBackup,
            ) -> Result<MaintenanceSnapshot, String> {
                self.individual.fetch_add(1, Ordering::Relaxed);
                self.native.read_maintenance(app)
            }
            fn check_maintenance_write_access(
                &self,
                app: &MaintenanceBackup,
            ) -> Result<(), String> {
                self.native.check_maintenance_write_access(app)
            }
            fn compare_exchange_maintenance(
                &self,
                app: &MaintenanceBackup,
                expected: &MaintenanceSnapshot,
                replacement: &MaintenanceSnapshot,
            ) -> Result<(), String> {
                self.native
                    .compare_exchange_maintenance(app, expected, replacement)
            }
        }
        let f = Fixture::new();
        let mut entries = Vec::new();
        for i in 0..100 {
            let app = f.cache(&format!(r"C:\RustRegistryMissing\app{i}.exe"));
            entries.push(f.entry(app));
        }
        let one = entries[0].maintenance_state.clone().unwrap();
        let root = f.key(MaintenanceKind::MuiCache);
        for i in 0..8300 {
            root.set_value(format!("Unrelated {i}"), &17u32).unwrap();
        }
        assert_eq!(root.enum_values().count(), 8500);
        let bulk = Arc::new(AtomicUsize::new(0));
        let individual = Arc::new(AtomicUsize::new(0));
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        let mut m = ChangeManager::new(
            CountingStore {
                native: f.store(),
                bulk: bulk.clone(),
                individual: individual.clone(),
            },
            backups.clone(),
            Missing,
        );
        let plan = m.prepare_clean(&entries, "selected").unwrap();
        assert_eq!(plan.items.len(), 100);
        assert_eq!(
            bulk.load(Ordering::Relaxed),
            1,
            "One cache read per batch preparation is the registry I/O budget"
        );
        assert_eq!(individual.load(Ordering::Relaxed), 0);
        assert!(!backups.exists());
        f.put(
            one.kind,
            &format!("{}.FriendlyAppName", one.item),
            "new display label",
        );
        let result = m.apply_clean(&plan.token).unwrap();
        assert!(result.completed.is_empty());
        assert!(result.failed.is_some());
        assert!(
            individual.load(Ordering::Relaxed) > 0,
            "Apply must read live evidence again rather than trusting the prepared batch snapshot"
        );
        assert!(!backups.exists());
    }

    #[test]
    fn large_cache_reviews_and_backup_inventory_keep_separate_upper_bounds() {
        let f = Fixture::new();
        let one = f.cache(r"C:\RustRegistryMissing\inventory.exe");
        let apps = vec![one.clone(); 615];
        let states = f.store().read_maintenance_inventory(&apps);
        assert_eq!(states.len(), 615);
        for state in states {
            assert_eq!(state.unwrap(), one.snapshot);
        }
        assert!(
            f.store()
                .read_maintenance_batch(&apps)
                .into_iter()
                .all(|state| state.is_ok()),
            "Cleaning review must accept more than 100 entries"
        );
        assert!(f
            .store()
            .read_maintenance_batch(&vec![one.clone(); crate::changes::MAX_CLEAN_ENTRIES + 1])
            .into_iter()
            .all(|state| state.is_err()));
        assert!(
            f.store()
                .read_maintenance_inventory(&vec![
                    one.clone();
                    crate::changes::MAX_BACKUP_ENTRIES + 1
                ])
                .into_iter()
                .all(|state| state.is_err()),
            "Backup inventory remains bounded to its documented storage capacity"
        );
    }
    #[test]
    fn cache_single_quick_and_selected_use_individual_verified_backups_and_restore_exact_bytes_after_restart(
    ) {
        for mode in ["single", "quick", "selected"] {
            let f = Fixture::new();
            let app = f.cache(r"C:\RustRegistryMissing\one.exe");
            let other = f.cache(r"C:\RustRegistryMissing\two.exe");
            f.key(MaintenanceKind::MuiCache)
                .set_value("Unrelated DWORD", &123u32)
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut m = ChangeManager::new(f.store(), backups.clone(), Missing);
            let p = m.prepare_quarantine(&f.entry(app.clone())).unwrap();
            m.cancel();
            assert!(m.apply(&p.token).is_err());
            assert!(!backups.exists());
            assert_eq!(f.store().read_maintenance(&app).unwrap(), app.snapshot);
            let ids = if mode == "single" {
                let p = m.prepare_quarantine(&f.entry(app.clone())).unwrap();
                vec![m.apply(&p.token).unwrap().backup_id]
            } else {
                let p = m
                    .prepare_clean(&[f.entry(app.clone()), f.entry(other.clone())], mode)
                    .unwrap();
                assert_eq!(p.items.len(), 2);
                let r = m.apply_clean(&p.token).unwrap();
                assert!(r.failed.is_none());
                assert_eq!(r.completed.len(), 2);
                r.completed.into_iter().map(|r| r.backup_id).collect()
            };
            drop(m);
            let mut m = ChangeManager::new(f.store(), backups.clone(), Missing);
            for (id, app) in ids.iter().zip([&app, &other]) {
                assert_eq!(f.store().read_maintenance(app).unwrap(), app.cleared());
                let record: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(backups.join(format!("{id}.json"))).unwrap(),
                )
                .unwrap();
                assert_eq!(record["schemaVersion"], 20);
                assert_eq!(record["maintenance"]["kind"], "mui_cache");
                let p = m.prepare_restore(id).unwrap();
                assert_eq!(p.scope, "mui_cache");
                m.apply(&p.token).unwrap();
                assert_eq!(f.store().read_maintenance(app).unwrap(), app.snapshot);
            }
            assert_eq!(
                f.key(MaintenanceKind::MuiCache)
                    .get_value::<u32, _>("Unrelated DWORD")
                    .unwrap(),
                123
            );
        }
    }
    #[test]
    fn optional_history_never_enters_quick_clean_and_restores_exact_order_commands_types_and_default(
    ) {
        for kind in [MaintenanceKind::RunHistory, MaintenanceKind::TypedPaths] {
            for mode in ["single", "selected"] {
                let f = Fixture::new();
                let app = f.history(kind);
                let e = f.entry(app.clone());
                assert_eq!(e.category, Category::UsageHistory);
                assert!(!is_quick_clean_candidate(&e));
                let dir = tempfile::tempdir().unwrap();
                let backups = dir.path().join("backups");
                let mut m = ChangeManager::new(f.store(), backups.clone(), NoProbe);
                let quick = m.prepare_clean(std::slice::from_ref(&e), "quick").unwrap();
                assert!(quick.items.is_empty());
                assert_eq!(quick.skipped.len(), 1);
                assert!(!backups.exists());
                let id = if mode == "single" {
                    let p = m.prepare_quarantine(&e).unwrap();
                    m.apply(&p.token).unwrap().backup_id
                } else {
                    let p = m.prepare_clean(&[e], "selected").unwrap();
                    m.apply_clean(&p.token).unwrap().completed[0]
                        .backup_id
                        .clone()
                };
                assert_eq!(f.store().read_maintenance(&app).unwrap(), app.cleared());
                drop(m);
                let mut m = ChangeManager::new(f.store(), backups, NoProbe);
                let p = m.prepare_restore(&id).unwrap();
                m.apply(&p.token).unwrap();
                assert_eq!(f.store().read_maintenance(&app).unwrap(), app.snapshot);
            }
        }
    }
    #[test]
    fn new_or_changed_history_blocks_prepare_apply_and_restore_without_overwriting_new_data() {
        for stage in ["scan", "review", "restore", "restore_review"] {
            let f = Fixture::new();
            let app = f.history(MaintenanceKind::RunHistory);
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let mut m = ChangeManager::new(f.store(), backups.clone(), NoProbe);
            let e = f.entry(app.clone());
            if stage == "scan" {
                f.put(app.kind, "a", "new data");
                assert!(m.prepare_quarantine(&e).unwrap_err().contains("changed"));
                assert!(!backups.exists());
                continue;
            }
            let p = m.prepare_quarantine(&e).unwrap();
            if stage == "review" {
                f.put(app.kind, "a", "new data");
                assert!(m.apply(&p.token).is_err());
                assert!(!backups.exists());
                continue;
            }
            let id = m.apply(&p.token).unwrap().backup_id;
            let path = backups.join(format!("{id}.json"));
            let before = std::fs::read(&path).unwrap();
            let p = if stage == "restore_review" {
                Some(m.prepare_restore(&id).unwrap())
            } else {
                None
            };
            f.put(app.kind, "a", "new data");
            f.put(app.kind, "MRUList", "a");
            if let Some(p) = p {
                assert!(m.apply(&p.token).is_err());
            } else {
                assert!(m.prepare_restore(&id).is_err());
            }
            assert_eq!(
                super::super::read_value(&f.key(app.kind), "a")
                    .unwrap()
                    .unwrap()
                    .bytes,
                "new data"
                    .encode_utf16()
                    .chain([0, 0])
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            );
            assert_eq!(std::fs::read(path).unwrap(), before);
            assert_eq!(m.inventory().unwrap().backups[0].state, "unverified");
        }
    }
    #[test]
    fn unsupported_cache_fields_types_history_order_nested_keys_and_missing_keys_are_read_only() {
        let f = Fixture::new();
        let app = f.cache(r"C:\RustRegistryMissing\app.exe");
        let dir = tempfile::tempdir().unwrap();
        let mut m = ChangeManager::new(f.store(), dir.path().join("backups"), Missing);
        f.put(app.kind, &format!("{}.Unknown", app.item), "preserve");
        assert!(m.prepare_quarantine(&f.entry(app.clone())).is_err());
        f.key(app.kind)
            .delete_value(format!("{}.Unknown", app.item))
            .unwrap();
        f.key(app.kind).create_subkey("Nested").unwrap();
        assert!(m.prepare_quarantine(&f.entry(app)).is_err());
        let mut history = f.history(MaintenanceKind::RunHistory);
        history
            .snapshot
            .values
            .iter_mut()
            .find(|v| v.name == "MRUList")
            .unwrap()
            .value
            .bytes = "aa\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(history.validate().is_err());
        let mut history = f.history(MaintenanceKind::TypedPaths);
        history.snapshot.values[0].value.kind = 2;
        assert!(history.validate().is_err());
    }

    #[test]
    fn cache_target_reappearing_blocks_apply_and_restore_and_keeps_verified_backup_immutable() {
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
        let f = Fixture::new();
        let app = f.cache(r"C:\RustRegistryMissing\appears.exe");
        let found = Arc::new(AtomicBool::new(false));
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        let mut m = ChangeManager::new(f.store(), backups.clone(), Switching(found.clone()));
        let p = m.prepare_quarantine(&f.entry(app.clone())).unwrap();
        found.store(true, Ordering::Relaxed);
        assert!(m
            .apply(&p.token)
            .unwrap_err()
            .contains("not confirmed missing"));
        assert!(!backups.exists());
        assert_eq!(f.store().read_maintenance(&app).unwrap(), app.snapshot);
        found.store(false, Ordering::Relaxed);
        let p = m.prepare_quarantine(&f.entry(app.clone())).unwrap();
        let id = m.apply(&p.token).unwrap().backup_id;
        let file = backups.join(format!("{id}.json"));
        let before = std::fs::read(&file).unwrap();
        let p = m.prepare_restore(&id).unwrap();
        found.store(true, Ordering::Relaxed);
        assert!(m.apply(&p.token).is_err());
        assert_eq!(f.store().read_maintenance(&app).unwrap(), app.cleared());
        assert_eq!(std::fs::read(&file).unwrap(), before);
        found.store(false, Ordering::Relaxed);
        let p = m.prepare_restore(&id).unwrap();
        m.apply(&p.token).unwrap();
        assert_eq!(f.store().read_maintenance(&app).unwrap(), app.snapshot);
    }
    #[test]
    fn corrupt_or_mixed_scope_backups_and_missing_keys_never_recreate_or_overwrite_data() {
        let f = Fixture::new();
        let app = f.history(MaintenanceKind::TypedPaths);
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        let mut m = ChangeManager::new(f.store(), backups.clone(), NoProbe);
        let p = m.prepare_quarantine(&f.entry(app.clone())).unwrap();
        let id = m.apply(&p.token).unwrap().backup_id;
        let file = backups.join(format!("{id}.json"));
        let original = std::fs::read(&file).unwrap();
        let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
        record["maintenance"]["snapshot"]["values"][1]["value"]["bytes"][0] = serde_json::json!(90);
        std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(m.prepare_restore(&id).unwrap_err().contains("checksum"));
        let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
        record["maintenance"]["kind"] = serde_json::json!("run_history");
        std::fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(m.prepare_restore(&id).unwrap_err().contains("namespace"));
        std::fs::write(&file, &original).unwrap();
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey(format!(r"{}\{}", f.base, app.kind.scope()))
            .unwrap();
        assert!(m.prepare_restore(&id).unwrap_err().contains("missing"));
        assert!(RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(format!(r"{}\{}", f.base, app.kind.scope()))
            .is_err());
        assert_eq!(std::fs::read(file).unwrap(), original);
    }
}
