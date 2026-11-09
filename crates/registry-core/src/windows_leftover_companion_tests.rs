use super::*;
use crate::{changes::RegistryStore, leftover_companions::AppPathsCompanion};
#[path = "windows_leftover_companion_coverage.rs"]
mod coverage;

impl Fixture {
    fn companion_entries(&self) -> Vec<RegistryEntry> {
        let mut entries = self.type_entries();
        let path = r"User\AppPaths\old0.exe";
        self.put(path, "", &text(&format!(r"{}\old0.exe", self.directory(0))));
        self.put(path, "pAth", &text(&format!("{}\\", self.directory(0))));
        self.put(path, "LicenseMarker", &text("COMPANION-PRESERVE"));
        let companion = AppPathsCompanion {
            values: crate::windows_changes::applications::values(&self.key(path)).unwrap(),
        };
        for entry in &mut entries {
            entry
                .leftover_state
                .as_mut()
                .unwrap()
                .supported_type
                .as_mut()
                .unwrap()
                .app_paths = Some(Box::new(companion.clone()));
            entry.leftover_evidence = Some(
                entry
                    .leftover_state
                    .as_ref()
                    .unwrap()
                    .verify_original(entry.snapshot.as_ref().unwrap(), &LocalPathProbe)
                    .unwrap(),
            );
        }
        entries
    }
}

#[test]
fn leftover_companion_hint_cleanup_restores_exact_original_after_restart() {
    for layout in ["both", "mapping_only", "path_only"] {
        for index in 0..2 {
            let f = Fixture::new();
            let mut entries = f.companion_entries();
            if layout != "both" {
                f.key(r"User\AppPaths\old0.exe")
                    .delete_value(if layout == "mapping_only" { "pAth" } else { "" })
                    .unwrap();
                let current = f
                    .store()
                    .leftover_type_companion("old0.exe", None)
                    .unwrap()
                    .unwrap();
                for e in &mut entries {
                    e.leftover_state
                        .as_mut()
                        .unwrap()
                        .supported_type
                        .as_mut()
                        .unwrap()
                        .app_paths = Some(Box::new(current.clone()));
                }
            }
            let entry = &entries[index];
            let storage = tempfile::tempdir().unwrap();
            let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
            let path_before =
                crate::windows_changes::applications::values(&f.key(r"User\AppPaths\old0.exe"))
                    .unwrap();
            let plan = manager.prepare_quarantine(entry).expect(
                "A corroborated missing App Paths counterpart should permit reviewed hint cleanup",
            );
            let id = manager.apply(&plan.token).unwrap().backup_id;
            assert!(f
                .store()
                .read_leftover(entry.leftover_state.as_ref().unwrap())
                .unwrap()
                .is_none());
            drop(manager);
            let mut manager = ChangeManager::new(f.store(), storage.path().into(), LocalPathProbe);
            let plan = manager.prepare_restore(&id).unwrap();
            manager.apply(&plan.token).unwrap();
            assert_eq!(
                f.store()
                    .read_leftover(entry.leftover_state.as_ref().unwrap())
                    .unwrap(),
                entry.snapshot
            );
            assert_eq!(
                crate::windows_changes::applications::values(&f.key(r"User\AppPaths\old0.exe"))
                    .unwrap(),
                path_before
            );
            let record: serde_json::Value = serde_json::from_slice(
                &std::fs::read(storage.path().join(format!("{id}.json"))).unwrap(),
            )
            .unwrap();
            assert_eq!(record["schemaVersion"], 27);
        }
    }
}
