use crate::{
    analyze_target, Category, EntryStatus, Environment, PathProbe, RegistryEntry, TargetKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const STARTUP_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const MAX_BYTES: usize = 32_768;
const MAX_BACKUP_BYTES: u64 = 262_144;
const PLAN_LIFETIME: u64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredValue {
    pub kind: u32,
    pub bytes: Vec<u8>,
}

impl StoredValue {
    pub fn text(&self) -> Result<String, String> {
        if ![1, 2].contains(&self.kind)
            || self.bytes.len() > MAX_BYTES
            || !self.bytes.len().is_multiple_of(2)
        {
            return Err(
                "Only bounded REG_SZ and REG_EXPAND_SZ startup values can be changed.".into(),
            );
        }
        let mut units: Vec<u16> = self
            .bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        let text = String::from_utf16(&units)
            .map_err(|_| "The original value contains invalid UTF-16.".to_string())?;
        if text.trim().is_empty() || text.contains('\0') {
            return Err("An empty or ambiguous startup command cannot be changed.".into());
        }
        Ok(text)
    }
}

pub fn validate_value_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.contains('\0') || name.encode_utf16().count() > 16_383 {
        Err("A nonempty, valid startup value name is required.".into())
    } else {
        Ok(())
    }
}

pub trait RegistryStore {
    fn read(&self, name: &str) -> Result<Option<StoredValue>, String>;
    /// Atomically enforce the expected value, mutate it, and commit, or change nothing.
    fn compare_exchange(
        &self,
        name: &str,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String>;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePlan {
    pub token: String,
    pub action: String,
    pub name: String,
    pub value_name: String,
    pub registry_path: String,
    pub original_value: String,
    pub value_type: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupRecord {
    schema_version: u32,
    id: Uuid,
    name: String,
    value_name: String,
    created_at: u64,
    original: StoredValue,
    integrity_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub id: String,
    pub name: String,
    pub value_name: String,
    pub created_at: u64,
    pub state: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInventory {
    pub storage_path: String,
    pub backups: Vec<BackupSummary>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeResult {
    pub backup_id: String,
    pub action: String,
    pub message: String,
}

enum PendingAction {
    Quarantine(BackupRecord),
    Restore(BackupRecord),
}
struct Pending {
    plan: ChangePlan,
    action: PendingAction,
}

pub struct ChangeManager<S: RegistryStore, P: PathProbe> {
    store: S,
    directory: PathBuf,
    probe: P,
    pending: Option<Pending>,
}

fn now() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64)
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

impl<S: RegistryStore, P: PathProbe> ChangeManager<S, P> {
    pub fn new(store: S, directory: PathBuf, probe: P) -> Self {
        Self {
            store,
            directory,
            probe,
            pending: None,
        }
    }

    fn ensure_directory(&self, create: bool) -> Result<(), String> {
        if create {
            fs::create_dir_all(&self.directory)
                .map_err(|e| format!("Cannot create the backup directory: {e}"))?;
        }
        match fs::symlink_metadata(&self.directory) {
            Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => Ok(()),
            Ok(_) => Err("The backup location must be a regular local directory.".into()),
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("Cannot access the backup directory: {error}")),
        }
    }

    fn validate_record(record: &BackupRecord) -> Result<(), String> {
        if record.schema_version != 1 || record.name.len() > 65_536 {
            return Err("Unsupported backup format.".into());
        }
        validate_value_name(&record.value_name)?;
        record.original.text()?;
        if record.integrity_sha256 != Self::checksum(record)? {
            return Err("The backup integrity checksum does not match. Restore is blocked.".into());
        }
        Ok(())
    }

    fn checksum(record: &BackupRecord) -> Result<String, String> {
        let bytes = serde_json::to_vec(&(
            record.schema_version,
            record.id,
            &record.name,
            &record.value_name,
            record.created_at,
            &record.original,
        ))
        .map_err(|e| e.to_string())?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn load(&self, id: &str) -> Result<BackupRecord, String> {
        let id = Uuid::parse_str(id).map_err(|_| "Invalid backup identifier.".to_string())?;
        self.ensure_directory(false)?;
        let path = self.directory.join(format!("{id}.json"));
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000);
        }
        let file = options
            .open(path)
            .map_err(|e| format!("Cannot open this backup: {e}"))?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_BACKUP_BYTES {
            return Err("The backup is not a supported regular file.".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BACKUP_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_BACKUP_BYTES {
            return Err("The backup exceeds the size limit.".into());
        }
        let record: BackupRecord = serde_json::from_slice(&bytes)
            .map_err(|_| "This backup is corrupted or has an unsupported format.".to_string())?;
        if record.id != id {
            return Err("The backup identifier does not match its file.".into());
        }
        Self::validate_record(&record)?;
        Ok(record)
    }

    fn save(&self, record: &BackupRecord) -> Result<(), String> {
        self.ensure_directory(true)?;
        Self::validate_record(record)?;
        let path = self.directory.join(format!("{}.json", record.id));
        let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_BACKUP_BYTES {
            return Err("The backup exceeds the size limit.".into());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                format!("Cannot create a new backup. No registry value was changed: {e}")
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| {
                format!("Cannot flush the backup to disk. No registry value was changed: {e}")
            })?;
        drop(file);
        let verified = self.load(&record.id.to_string())?;
        if verified.original != record.original || verified.value_name != record.value_name {
            return Err("Backup verification failed. No registry value was changed.".into());
        }
        Ok(())
    }

    fn verify_missing(&self, value: &StoredValue) -> Result<(), String> {
        let check = analyze_target(
            &value.text()?,
            TargetKind::Command,
            &Environment::current(),
            &self.probe,
        );
        if check.status != EntryStatus::Review || check.code != "target_missing" {
            return Err("The target is no longer confirmed missing. Scan again; this entry cannot be changed.".into());
        }
        Ok(())
    }

    pub fn prepare_quarantine(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        self.pending = None;
        if entry.category != Category::Startup
            || entry.hive != "HKCU"
            || entry.view != "shared"
            || !entry.key_path.eq_ignore_ascii_case(STARTUP_KEY)
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "target_missing"
        {
            return Err(
                "Only confirmed missing-target entries in the current user's Run key are eligible."
                    .into(),
            );
        }
        validate_value_name(&entry.value_name)?;
        let original = entry
            .snapshot
            .clone()
            .ok_or("Scan evidence is unavailable. Run a fresh scan.")?;
        if original.text()? != entry.raw_value
            || self.store.read(&entry.value_name)?.as_ref() != Some(&original)
        {
            return Err(
                "This entry changed after the scan. Run a fresh scan before reviewing a change."
                    .into(),
            );
        }
        self.verify_missing(&original)?;
        let mut record = BackupRecord {
            schema_version: 1,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: entry.value_name.clone(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    pub fn prepare_restore(&mut self, id: &str) -> Result<ChangePlan, String> {
        self.pending = None;
        let record = self.load(id)?;
        if self.store.read(&record.value_name)?.is_some() {
            return Err("A value with this name already exists. Restore never overwrites an existing value.".into());
        }
        self.prepare(record, true)
    }

    fn prepare(&mut self, record: BackupRecord, restore: bool) -> Result<ChangePlan, String> {
        let plan = ChangePlan {
            token: Uuid::new_v4().to_string(),
            action: if restore { "restore" } else { "quarantine" }.into(),
            name: record.name.clone(),
            value_name: record.value_name.clone(),
            registry_path: format!("HKCU\\{STARTUP_KEY}"),
            original_value: record.original.text()?,
            value_type: if record.original.kind == 1 {
                "REG_SZ"
            } else {
                "REG_EXPAND_SZ"
            }
            .into(),
            expires_at: now()? + PLAN_LIFETIME,
        };
        self.pending = Some(Pending {
            plan: plan.clone(),
            action: if restore {
                PendingAction::Restore(record)
            } else {
                PendingAction::Quarantine(record)
            },
        });
        Ok(plan)
    }

    pub fn cancel(&mut self) {
        self.pending = None;
    }

    pub fn apply(&mut self, token: &str) -> Result<ChangeResult, String> {
        let pending = self
            .pending
            .take()
            .ok_or("No pending change. Review the entry again.")?;
        if pending.plan.token != token || now()? > pending.plan.expires_at {
            return Err("This review expired or does not match. Review the change again.".into());
        }
        let (record, restore) = match pending.action {
            PendingAction::Quarantine(record) => (record, false),
            PendingAction::Restore(record) => (record, true),
        };
        if restore {
            // Re-read immutable backup evidence immediately before restoring.
            let disk = self.load(&record.id.to_string())?;
            if disk.original != record.original || disk.value_name != record.value_name {
                return Err("The backup changed after review. Nothing was restored.".into());
            }
            self.store
                .compare_exchange(&record.value_name, None, Some(&record.original))?;
        } else {
            self.verify_missing(&record.original)?;
            if self.store.read(&record.value_name)?.as_ref() != Some(&record.original) {
                return Err(
                    "The registry value changed after review. Nothing was disabled.".into(),
                );
            }
            self.save(&record)?;
            self.store
                .compare_exchange(&record.value_name, Some(&record.original), None)?;
        }
        let actual = self.store.read(&record.value_name)?;
        let expected = if restore {
            Some(record.original.clone())
        } else {
            None
        };
        if actual != expected {
            return Err(format!("The change committed, but the current value has changed again. Backup {} is preserved; refresh and inspect the result.", record.id));
        }
        Ok(ChangeResult {
            backup_id: record.id.to_string(),
            action: pending.plan.action,
            message: if restore {
                "Original startup value restored and verified."
            } else {
                "Startup value disabled. Its exact original bytes are saved in a verified backup."
            }
            .into(),
        })
    }

    pub fn inventory(&self) -> Result<BackupInventory, String> {
        self.ensure_directory(false)?;
        let mut inventory = BackupInventory {
            storage_path: self.directory.to_string_lossy().into(),
            backups: Vec::new(),
            warnings: Vec::new(),
        };
        let files = match fs::read_dir(&self.directory) {
            Ok(files) => files,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(inventory),
            Err(error) => return Err(format!("Cannot list backups: {error}")),
        };
        for (index, file) in files.enumerate() {
            if index >= 1000 {
                inventory
                    .warnings
                    .push("Only the first 1,000 backup directory entries were inspected.".into());
                break;
            }
            let file = match file {
                Ok(file) => file,
                Err(_) => {
                    inventory
                        .warnings
                        .push("A backup directory entry could not be read.".into());
                    continue;
                }
            };
            let path = file.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let record = match self.load(id) {
                Ok(record) => record,
                Err(error) => {
                    inventory.warnings.push(format!("{id}: {error}"));
                    continue;
                }
            };
            let (state, note) = match self.store.read(&record.value_name) {
                Ok(None) => (
                    "restore_available",
                    "The value is absent. Its original can be reviewed for restore.".into(),
                ),
                Ok(Some(value)) if value == record.original => (
                    "original_present",
                    "The live value matches this backup. No restore is needed.".into(),
                ),
                Ok(Some(_)) => (
                    "conflict",
                    "A different value with the same name exists. Restore is blocked.".into(),
                ),
                Err(error) => ("unverified", error),
            };
            inventory.backups.push(BackupSummary {
                id: record.id.to_string(),
                name: record.name,
                value_name: record.value_name,
                created_at: record.created_at,
                state: state.into(),
                note,
            });
        }
        inventory
            .backups
            .sort_by_key(|record| std::cmp::Reverse(record.created_at));
        Ok(inventory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Assessment, ProbeResult};
    use std::{
        cell::{Cell, RefCell},
        collections::HashMap,
        path::Path,
        rc::Rc,
    };
    #[derive(Clone, Default)]
    struct Memory(Rc<RefCell<HashMap<String, StoredValue>>>);
    impl RegistryStore for Memory {
        fn read(&self, name: &str) -> Result<Option<StoredValue>, String> {
            Ok(self.0.borrow().get(name).cloned())
        }
        fn compare_exchange(
            &self,
            name: &str,
            expected: Option<&StoredValue>,
            replacement: Option<&StoredValue>,
        ) -> Result<(), String> {
            let mut values = self.0.borrow_mut();
            if values.get(name) != expected {
                return Err("Conflict".into());
            }
            match replacement {
                Some(value) => {
                    values.insert(name.into(), value.clone());
                }
                None => {
                    values.remove(name);
                }
            }
            Ok(())
        }
    }
    struct Probe(Rc<Cell<ProbeResult>>);
    impl PathProbe for Probe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            self.0.get()
        }
    }
    fn original() -> StoredValue {
        StoredValue {
            kind: 2,
            bytes: "C:\\Missing\\app.exe\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    fn entry() -> RegistryEntry {
        RegistryEntry {
            id: "entry".into(),
            name: "Example".into(),
            category: Category::Startup,
            hive: "HKCU".into(),
            key_path: STARTUP_KEY.into(),
            view: "shared".into(),
            value_name: "Example".into(),
            value_type: "REG_EXPAND_SZ".into(),
            raw_value: r"C:\Missing\app.exe".into(),
            publisher: None,
            version: None,
            assessment: Assessment {
                status: EntryStatus::Review,
                code: "target_missing".into(),
                explanation: "Missing".into(),
                target: Some(r"C:\Missing\app.exe".into()),
            },
            snapshot: Some(original()),
        }
    }
    fn setup(path: &Path) -> (Memory, Rc<Cell<ProbeResult>>, ChangeManager<Memory, Probe>) {
        let store = Memory::default();
        store.0.borrow_mut().insert("Example".into(), original());
        let state = Rc::new(Cell::new(ProbeResult::Missing));
        (
            store.clone(),
            state.clone(),
            ChangeManager::new(store, path.into(), Probe(state)),
        )
    }

    #[test]
    fn review_is_read_only_and_verified_backup_survives_restart_for_exact_restore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backups");
        let (store, state, mut manager) = setup(&path);
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        assert!(!path.exists());
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        let result = manager.apply(&plan.token).unwrap();
        assert!(store.read("Example").unwrap().is_none());
        assert_eq!(
            manager.inventory().unwrap().backups[0].state,
            "restore_available"
        );
        let mut reopened = ChangeManager::new(store.clone(), path, Probe(state));
        let restore = reopened.prepare_restore(&result.backup_id).unwrap();
        reopened.apply(&restore.token).unwrap();
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        assert_eq!(
            reopened.inventory().unwrap().backups[0].state,
            "original_present"
        );
    }
    #[test]
    fn registry_and_filesystem_changes_after_review_block_disable() {
        for registry_changed in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let (store, state, mut manager) = setup(dir.path());
            let plan = manager.prepare_quarantine(&entry()).unwrap();
            if registry_changed {
                store.0.borrow_mut().insert(
                    "Example".into(),
                    StoredValue {
                        kind: 1,
                        bytes: original().bytes,
                    },
                );
            } else {
                state.set(ProbeResult::Found);
            }
            assert!(manager.apply(&plan.token).is_err());
            assert!(store.read("Example").unwrap().is_some());
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }
    #[test]
    fn never_disables_out_of_scope_or_uncertain_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        for change in 0..6 {
            let mut record = entry();
            match change {
                0 => record.hive = "HKLM".into(),
                1 => record.key_path.push_str("Once"),
                2 => record.category = Category::AppPaths,
                3 => record.assessment.status = EntryStatus::Unknown,
                4 => record.snapshot = None,
                _ => record.view = "32".into(),
            }
            assert!(manager.prepare_quarantine(&record).is_err());
        }
        assert_eq!(store.read("Example").unwrap(), Some(original()));
    }
    #[test]
    fn backup_failure_prevents_registry_change_and_plans_are_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-directory");
        fs::write(&path, "occupied").unwrap();
        let (store, _, mut manager) = setup(&path);
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        assert!(manager.apply(&plan.token).is_err());
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        assert!(manager.apply(&plan.token).is_err());
    }
    #[test]
    fn restore_conflict_and_backup_tampering_do_not_overwrite_live_values() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let restore = manager.prepare_restore(&result.backup_id).unwrap();
        let other = StoredValue {
            kind: 1,
            bytes: original().bytes,
        };
        store.0.borrow_mut().insert("Example".into(), other.clone());
        assert!(manager.apply(&restore.token).is_err());
        assert_eq!(store.read("Example").unwrap(), Some(other));
        assert_eq!(manager.inventory().unwrap().backups[0].state, "conflict");
        store.0.borrow_mut().clear();
        let restore = manager.prepare_restore(&result.backup_id).unwrap();
        fs::write(
            dir.path().join(format!("{}.json", result.backup_id)),
            "corrupted",
        )
        .unwrap();
        assert!(manager.apply(&restore.token).is_err());
        assert!(store.read("Example").unwrap().is_none());
        assert_eq!(manager.inventory().unwrap().warnings.len(), 1);
    }
    #[test]
    fn cancellation_expiry_wrong_tokens_and_path_traversal_cannot_apply_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        manager.prepare_quarantine(&entry()).unwrap();
        assert!(manager.apply("wrong-token").is_err());
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        manager.cancel();
        assert!(manager.apply(&plan.token).is_err());
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        manager.pending.as_mut().unwrap().plan.expires_at = 0;
        assert!(manager.apply(&plan.token).is_err());
        assert!(manager.prepare_restore("../outside").is_err());
        assert_eq!(store.read("Example").unwrap(), Some(original()));
    }

    #[test]
    fn valid_json_with_changed_backup_bytes_fails_integrity_verification() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let path = dir.path().join(format!("{}.json", result.backup_id));
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        json["original"]["bytes"][0] = serde_json::json!(68);
        fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(manager
            .prepare_restore(&result.backup_id)
            .unwrap_err()
            .contains("integrity"));
        assert!(store.read("Example").unwrap().is_none());
    }
}
