use crate::storage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const MAX_OPERATION_ENTRIES: usize = 10_000;
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILES: usize = 10_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Clean,
    Restore,
    Undo,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalEntry {
    pub backup_id: String,
    pub integrity_sha256: String,
    pub name: String,
    pub registry_path: String,
    pub registry_view: String,
    pub value_name: String,
    pub scope: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationHeader {
    pub version: u32,
    pub id: String,
    pub kind: OperationKind,
    pub mode: String,
    pub source_operation_id: Option<String>,
    pub created_at: u64,
    pub entries: Vec<JournalEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Begin { header: OperationHeader },
    Attempt { index: usize },
    Applied { index: usize },
    Original { index: usize },
    Failed { index: usize, reason: String },
    Blocked { index: usize, reason: String },
    Finish { outcome: String },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrameData {
    sequence: usize,
    previous_sha256: String,
    time: u64,
    event: Event,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Frame {
    data: FrameData,
    integrity_sha256: String,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationSummary {
    pub id: String,
    pub kind: OperationKind,
    pub mode: String,
    pub source_operation_id: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub state: String,
    pub total: usize,
    pub attempted: usize,
    pub applied: usize,
    pub already_original: usize,
    pub blocked: usize,
    pub failed: usize,
    pub not_attempted: usize,
    pub can_undo: bool,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationInventory {
    pub storage_path: String,
    pub operations: Vec<OperationSummary>,
    pub warnings: Vec<String>,
}
#[derive(Debug)]
pub struct RecordedOperation {
    pub header: OperationHeader,
    pub states: Vec<u8>,
    pub reasons: Vec<Option<String>>,
    pub summary: OperationSummary,
}
pub struct JournalStore {
    directory: PathBuf,
}
pub struct OperationRun {
    file: File,
    id: String,
    previous: String,
    sequence: usize,
    bytes: u64,
    poisoned: bool,
}

fn digest(data: &FrameData) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(data).map_err(|e| e.to_string())?)
    ))
}
fn validate_header(header: &OperationHeader) -> Result<(), String> {
    storage::canonical_id(&header.id)?;
    if let Some(id) = &header.source_operation_id {
        storage::canonical_id(id)?;
    }
    let mut ids = std::collections::HashSet::new();
    if header.version != 1
        || header.entries.is_empty()
        || header.entries.len() > MAX_OPERATION_ENTRIES
        || header.mode.len() > 64
    {
        return Err("Unsupported operation journal header.".into());
    }
    for entry in &header.entries {
        storage::canonical_id(&entry.backup_id)?;
        if !ids.insert(&entry.backup_id)
            || entry.integrity_sha256.len() != 64
            || !entry
                .integrity_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || entry.name.len() > 65536
            || entry.registry_path.len() > 32768
            || entry.value_name.len() > 32768
            || entry.scope.len() > 128
            || !["shared", "32", "64"].contains(&entry.registry_view.as_str())
        {
            return Err("Unsupported or duplicate operation backup reference.".into());
        }
    }
    Ok(())
}
impl JournalStore {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn start(
        &self,
        kind: OperationKind,
        mode: &str,
        source: Option<String>,
        entries: Vec<JournalEntry>,
    ) -> Result<OperationRun, String> {
        storage::directory(&self.directory, true)?;
        if fs::read_dir(&self.directory)
            .map_err(|e| e.to_string())?
            .take(MAX_FILES + 1)
            .count()
            >= MAX_FILES
        {
            return Err("Operation storage reached 10,000 directory entries. Archive older journals before changing records.".into());
        }
        let header = OperationHeader {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            mode: mode.into(),
            source_operation_id: source,
            created_at: storage::now()?,
            entries,
        };
        validate_header(&header)?;
        let file =
            storage::create_file(&self.directory.join(format!("{}.jsonl", header.id)), true)?;
        let mut run = OperationRun {
            file,
            id: header.id.clone(),
            previous: "0".repeat(64),
            sequence: 0,
            bytes: 0,
            poisoned: false,
        };
        run.append(Event::Begin { header })?;
        Ok(run)
    }
    pub fn read(&self, id: &str) -> Result<RecordedOperation, String> {
        storage::canonical_id(id)?;
        let path = self.directory.join(format!("{id}.jsonl"));
        let bytes = storage::read_file(&path, MAX_BYTES)?;
        let mut header = None;
        let mut states = vec![];
        let mut reasons = vec![];
        let mut previous = "0".repeat(64);
        let mut sequence = 0;
        let mut finished = None;
        let mut updated = 0;
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            if line.last() != Some(&b'\n') {
                break;
            }
            if sequence > MAX_OPERATION_ENTRIES * 2 + 2 {
                return Err("Operation journal exceeds its event limit.".into());
            }
            let frame: Frame = serde_json::from_slice(line)
                .map_err(|_| "An operation journal frame is corrupt.")?;
            if finished.is_some()
                || frame.data.sequence != sequence
                || frame.data.previous_sha256 != previous
                || frame.integrity_sha256 != digest(&frame.data)?
            {
                return Err("The operation journal integrity chain is invalid.".into());
            }
            updated = frame.data.time;
            previous = frame.integrity_sha256;
            sequence += 1;
            let mut change = |index: usize,
                              expected: u8,
                              replacement: u8,
                              reason: Option<String>|
             -> Result<(), String> {
                if index >= states.len()
                    || states[index] != expected
                    || reason.as_ref().is_some_and(|r| r.len() > 8192)
                {
                    return Err(
                        "The operation journal contains an invalid state transition.".into(),
                    );
                }
                states[index] = replacement;
                reasons[index] = reason;
                Ok(())
            };
            match frame.data.event {
                Event::Begin { header: h } => {
                    if header.is_some() || sequence != 1 || h.id != id {
                        return Err("The operation journal identity is invalid.".into());
                    }
                    validate_header(&h)?;
                    states = vec![0; h.entries.len()];
                    reasons = vec![None; h.entries.len()];
                    header = Some(h);
                }
                Event::Attempt { index } => change(index, 0, 1, None)?,
                Event::Applied { index } => change(index, 1, 2, None)?,
                Event::Original { index } => change(index, 0, 5, None)?,
                Event::Failed { index, reason } => change(index, 1, 3, Some(reason))?,
                Event::Blocked { index, reason } => change(index, 0, 4, Some(reason))?,
                Event::Finish { outcome } => {
                    if !["completed", "cancelled", "attention", "failed"]
                        .contains(&outcome.as_str())
                    {
                        return Err("Unknown operation completion state.".into());
                    }
                    finished = Some(outcome);
                }
            }
        }
        let header = header.ok_or(
            "The operation journal has no complete header. No recovery is authorized by this file.",
        )?;
        let state = if let Some(outcome) = finished {
            outcome
        } else if self.writer_active(&path)? {
            "running".into()
        } else {
            "interrupted".into()
        };
        let attempted = states.iter().filter(|s| [1, 2, 3].contains(s)).count();
        let summary = OperationSummary {
            id: id.into(),
            kind: header.kind,
            mode: header.mode.clone(),
            source_operation_id: header.source_operation_id.clone(),
            created_at: header.created_at,
            updated_at: updated,
            state: state.clone(),
            total: states.len(),
            attempted,
            applied: states.iter().filter(|s| **s == 2).count(),
            already_original: states.iter().filter(|s| **s == 5).count(),
            blocked: states.iter().filter(|s| **s == 4).count(),
            failed: states.iter().filter(|s| **s == 3).count(),
            not_attempted: states.iter().filter(|s| **s == 0).count(),
            can_undo: state != "running"
                && ((header.kind == OperationKind::Clean && attempted > 0)
                    || (header.kind == OperationKind::Undo
                        && ["interrupted", "cancelled", "attention", "failed"]
                            .contains(&state.as_str()))),
        };
        Ok(RecordedOperation {
            header,
            states,
            reasons,
            summary,
        })
    }
    fn writer_active(&self, path: &Path) -> Result<bool, String> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            match OpenOptions::new()
                .write(true)
                .share_mode(1)
                .custom_flags(0x00200000)
                .open(path)
            {
                Ok(_) => Ok(false),
                Err(e) if [Some(32), Some(33)].contains(&e.raw_os_error()) => Ok(true),
                Err(e) => Err(format!("Cannot verify the operation writer state: {e}")),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Ok(false)
        }
    }
    pub fn inventory(&self) -> Result<OperationInventory, String> {
        storage::directory(&self.directory, false)?;
        let mut result = OperationInventory {
            storage_path: self.directory.to_string_lossy().into(),
            operations: vec![],
            warnings: vec![],
        };
        let files = match fs::read_dir(&self.directory) {
            Ok(files) => files,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(result),
            Err(e) => return Err(e.to_string()),
        };
        for (index, file) in files.enumerate() {
            if index >= MAX_FILES {
                result.warnings.push(
                    "Only the first 10,000 operation directory entries were inspected.".into(),
                );
                break;
            }
            let file = file.map_err(|e| e.to_string())?;
            let name = file.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".jsonl") else {
                continue;
            };
            if storage::canonical_id(id).is_err() {
                continue;
            }
            match self.read(id) {
                Ok(operation) => result.operations.push(operation.summary),
                Err(error) => result.warnings.push(format!("{id}: {error}")),
            }
        }
        result
            .operations
            .sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        Ok(result)
    }
}
impl OperationRun {
    pub fn id(&self) -> &str {
        &self.id
    }
    fn append(&mut self, event: Event) -> Result<(), String> {
        if self.poisoned {
            return Err(
                "The operation journal is unavailable. Review Recovery before continuing.".into(),
            );
        }
        let data = FrameData {
            sequence: self.sequence,
            previous_sha256: self.previous.clone(),
            time: storage::now()?,
            event,
        };
        let hash = digest(&data)?;
        let mut bytes = serde_json::to_vec(&Frame {
            data,
            integrity_sha256: hash.clone(),
        })
        .map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if self.bytes + bytes.len() as u64 > MAX_BYTES {
            self.poisoned = true;
            return Err("The operation journal reached its size limit. Registry state must be reviewed in Recovery.".into());
        }
        if let Err(error) = self
            .file
            .write_all(&bytes)
            .and_then(|_| self.file.sync_all())
        {
            self.poisoned = true;
            return Err(format!("Cannot durably checkpoint operation {}: {error}. Registry state may already have changed; open Recovery.",self.id));
        }
        self.bytes += bytes.len() as u64;
        self.sequence += 1;
        self.previous = hash;
        Ok(())
    }
    pub fn attempt(&mut self, index: usize) -> Result<(), String> {
        self.append(Event::Attempt { index })
    }
    pub fn applied(&mut self, index: usize) -> Result<(), String> {
        self.append(Event::Applied { index })
    }
    pub fn original(&mut self, index: usize) -> Result<(), String> {
        self.append(Event::Original { index })
    }
    fn reason(reason: &str) -> String {
        reason.chars().take(2048).collect()
    }
    pub fn failed(&mut self, index: usize, reason: &str) -> Result<(), String> {
        self.append(Event::Failed {
            index,
            reason: Self::reason(reason),
        })
    }
    pub fn blocked(&mut self, index: usize, reason: &str) -> Result<(), String> {
        self.append(Event::Blocked {
            index,
            reason: Self::reason(reason),
        })
    }
    pub fn finish(&mut self, outcome: &str) -> Result<(), String> {
        self.append(Event::Finish {
            outcome: outcome.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry() -> JournalEntry {
        JournalEntry {
            backup_id: uuid::Uuid::new_v4().to_string(),
            integrity_sha256: "a".repeat(64),
            name: "Owned".into(),
            registry_path: r"HKCU\Software\Owned".into(),
            registry_view: "shared".into(),
            value_name: "Owned".into(),
            scope: "startup".into(),
        }
    }
    #[test]
    fn restart_accepts_only_complete_verified_frames_and_never_replays_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path().join("operations"));
        let mut run = store
            .start(OperationKind::Clean, "selected", None, vec![entry()])
            .unwrap();
        let id = run.id().to_string();
        run.attempt(0).unwrap();
        assert_eq!(store.read(&id).unwrap().summary.state, "running");
        drop(run);
        let path = store.directory.join(format!("{id}.jsonl"));
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{partial")
            .unwrap();
        let reopened = store.read(&id).unwrap();
        assert_eq!(reopened.summary.state, "interrupted");
        assert_eq!(reopened.states, vec![1]);
        assert_eq!(reopened.summary.applied, 0);
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(store.read(&id).is_err());
        assert_eq!(store.inventory().unwrap().warnings.len(), 1);
    }
    #[test]
    fn rejects_reordered_frames_unknown_versions_and_duplicate_backup_references() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path().join("operations"));
        let item = entry();
        assert!(store
            .start(
                OperationKind::Clean,
                "selected",
                None,
                vec![item.clone(), item]
            )
            .is_err());
        let mut run = store
            .start(OperationKind::Clean, "selected", None, vec![entry()])
            .unwrap();
        let id = run.id().to_string();
        run.attempt(0).unwrap();
        run.applied(0).unwrap();
        run.finish("completed").unwrap();
        drop(run);
        let path = store.directory.join(format!("{id}.jsonl"));
        let text = fs::read_to_string(&path).unwrap();
        let mut lines = text.lines().collect::<Vec<_>>();
        lines.swap(1, 2);
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(store.read(&id).is_err());
        assert!(store.read("../outside").is_err());
    }
    #[test]
    fn storage_failure_prevents_any_operation_authorization() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-directory");
        fs::write(&path, b"control").unwrap();
        assert!(JournalStore::new(path.clone())
            .start(OperationKind::Clean, "selected", None, vec![entry()])
            .is_err());
        assert_eq!(fs::read(path).unwrap(), b"control");
    }
}
