//! Local immutable scan archives. Archived reports never carry native repair snapshots.
use crate::{storage, ScanReport};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

const MAX_COMPRESSED: u64 = 64 * 1024 * 1024;
const MAX_EXPANDED: u64 = 512 * 1024 * 1024;
pub const RETAINED_SCANS: usize = 20;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavedScan {
    pub version: u32,
    pub id: String,
    pub scan_id: String,
    pub started_at: u64,
    pub duration_ms: u64,
    pub cancelled: bool,
    pub entries: usize,
    pub sections: usize,
    pub sha256: String,
    pub compressed_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report(index: u64) -> ScanReport {
        ScanReport {
            history_warning: None,
            id: uuid::Uuid::new_v4().to_string(),
            started_at: index,
            duration_ms: 42,
            cancelled: false,
            read_only: true,
            architecture: "x64".into(),
            entries: vec![],
            scopes: vec![],
        }
    }
    #[test]
    fn archives_persist_across_restart_and_retention_preserves_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history");
        let store = HistoryStore::new(path.clone());
        for index in 0..23 {
            store.save(&report(index)).unwrap();
        }
        fs::write(path.join("control.txt"), b"preserve").unwrap();
        let reopened = HistoryStore::new(path.clone());
        let inventory = reopened.inventory().unwrap();
        assert_eq!(inventory.scans.len(), 20);
        assert_eq!(inventory.scans[0].started_at, 22);
        assert_eq!(inventory.scans.last().unwrap().started_at, 3);
        for summary in inventory.scans {
            assert_eq!(reopened.load(&summary.id).unwrap().id, summary.scan_id);
        }
        assert_eq!(fs::read(path.join("control.txt")).unwrap(), b"preserve");
    }
    #[test]
    fn corrupt_payload_metadata_and_uncommitted_archive_never_become_loaded_reports() {
        let dir = tempfile::tempdir().unwrap();
        let store = HistoryStore::new(dir.path().join("history"));
        let saved = store.save(&report(1)).unwrap();
        fs::write(
            store.directory.join(format!("{}.scan.gz", saved.id)),
            b"corrupt",
        )
        .unwrap();
        assert!(store.load(&saved.id).is_err());
        fs::write(
            store
                .directory
                .join(format!("{}.scan.gz", uuid::Uuid::new_v4())),
            b"orphan after crash",
        )
        .unwrap();
        assert_eq!(store.inventory().unwrap().scans.len(), 1);
        fs::write(
            store.directory.join(format!("{}.json", saved.id)),
            b"{partial",
        )
        .unwrap();
        assert!(store.inventory().unwrap().scans.is_empty());
        assert_eq!(store.inventory().unwrap().warnings.len(), 1);
        assert!(store.load("../control").is_err());
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryInventory {
    pub scans: Vec<SavedScan>,
    pub warnings: Vec<String>,
    pub storage_path: String,
    pub retained_scans: usize,
}
pub struct HistoryStore {
    directory: PathBuf,
}
impl HistoryStore {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }
    fn summary(&self, id: &str) -> Result<SavedScan, String> {
        storage::canonical_id(id)?;
        let summary: SavedScan = serde_json::from_slice(&storage::read_file(
            &self.directory.join(format!("{id}.json")),
            16384,
        )?)
        .map_err(|e| e.to_string())?;
        if summary.version != 1
            || summary.id != id
            || summary.sha256.len() != 64
            || summary.compressed_bytes > MAX_COMPRESSED
        {
            return Err("Unsupported saved scan metadata.".into());
        }
        Ok(summary)
    }
    pub fn inventory(&self) -> Result<HistoryInventory, String> {
        storage::directory(&self.directory, false)?;
        let mut inventory = HistoryInventory {
            scans: vec![],
            warnings: vec![],
            storage_path: self.directory.to_string_lossy().into(),
            retained_scans: RETAINED_SCANS,
        };
        let files = match fs::read_dir(&self.directory) {
            Ok(files) => files,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(inventory),
            Err(e) => return Err(e.to_string()),
        };
        for (index, file) in files.enumerate() {
            if index >= 10000 {
                inventory
                    .warnings
                    .push("History directory inspection stopped at 10,000 entries.".into());
                break;
            }
            let file = file.map_err(|e| e.to_string())?;
            let name = file.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if storage::canonical_id(id).is_err() {
                continue;
            }
            match self.summary(id) {
                Ok(summary) => inventory.scans.push(summary),
                Err(error) => inventory.warnings.push(format!("{id}: {error}")),
            }
        }
        inventory
            .scans
            .sort_by(|a, b| b.started_at.cmp(&a.started_at).then(b.id.cmp(&a.id)));
        Ok(inventory)
    }
    pub fn load(&self, id: &str) -> Result<ScanReport, String> {
        let summary = self.summary(id)?;
        let bytes = storage::read_file(
            &self.directory.join(format!("{id}.scan.gz")),
            MAX_COMPRESSED,
        )?;
        if bytes.len() as u64 != summary.compressed_bytes
            || format!("{:x}", Sha256::digest(&bytes)) != summary.sha256
        {
            return Err("The saved scan checksum does not match.".into());
        }
        let mut json = Vec::new();
        GzDecoder::new(bytes.as_slice())
            .take(MAX_EXPANDED + 1)
            .read_to_end(&mut json)
            .map_err(|e| e.to_string())?;
        if json.len() as u64 > MAX_EXPANDED {
            return Err("The saved scan exceeds its expanded size limit.".into());
        }
        let report: ScanReport = serde_json::from_slice(&json).map_err(|e| e.to_string())?;
        if report.id != summary.scan_id
            || report.started_at != summary.started_at
            || report.entries.len() != summary.entries
            || report.scopes.len() != summary.sections
            || report.cancelled != summary.cancelled
            || report.duration_ms != summary.duration_ms
        {
            return Err("The saved scan does not match its metadata.".into());
        }
        Ok(report)
    }
    pub fn save(&self, report: &ScanReport) -> Result<SavedScan, String> {
        storage::directory(&self.directory, true)?;
        if fs::read_dir(&self.directory)
            .map_err(|e| e.to_string())?
            .take(10001)
            .count()
            >= 10000
        {
            return Err(
                "Local scan storage is full. Archive older history before saving more scans."
                    .into(),
            );
        }
        let id = uuid::Uuid::new_v4().to_string();
        let path = self.directory.join(format!("{id}.scan.gz"));
        let file = storage::create_file(&path, true)?;
        let mut encoder = GzEncoder::new(file, Compression::fast());
        serde_json::to_writer(&mut encoder, report).map_err(|e| e.to_string())?;
        encoder
            .finish()
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())?;
        let bytes = storage::read_file(&path, MAX_COMPRESSED)?;
        let summary = SavedScan {
            version: 1,
            id: id.clone(),
            scan_id: report.id.clone(),
            started_at: report.started_at,
            duration_ms: report.duration_ms,
            cancelled: report.cancelled,
            entries: report.entries.len(),
            sections: report.scopes.len(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            compressed_bytes: bytes.len() as u64,
        };
        let mut marker = storage::create_file(&self.directory.join(format!("{id}.json")), true)?;
        marker
            .write_all(&serde_json::to_vec(&summary).map_err(|e| e.to_string())?)
            .and_then(|_| marker.sync_all())
            .map_err(|e| e.to_string())?;
        drop(marker);
        // Invalid and unrelated files are preserved. A complete validated pair alone is eligible for retention cleanup.
        for old in self.inventory()?.scans.into_iter().skip(RETAINED_SCANS) {
            self.load(&old.id)?;
            fs::remove_file(self.directory.join(format!("{}.json", old.id)))
                .map_err(|e| e.to_string())?;
            fs::remove_file(self.directory.join(format!("{}.scan.gz", old.id)))
                .map_err(|e| e.to_string())?;
        }
        Ok(summary)
    }
}
