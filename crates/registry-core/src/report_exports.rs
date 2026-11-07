use crate::{Category, EntryStatus, RegistryEntry, ScanReport};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportRequest {
    pub scan_id: String,
    pub entry_ids: Vec<String>,
    pub query: String,
    pub category: Option<Category>,
    pub status: Option<EntryStatus>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    pub path: String,
    pub entries: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Filters<'a> {
    query: &'a str,
    category: Option<Category>,
    status: Option<EntryStatus>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanInfo<'a> {
    id: &'a str,
    started_at: u64,
    duration_ms: u64,
    cancelled: bool,
    read_only: bool,
    architecture: &'a str,
    scope_count: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Findings<'a> {
    format: &'static str,
    schema_version: u32,
    application_version: &'static str,
    exported_at: u64,
    scan: ScanInfo<'a>,
    filters: Filters<'a>,
    total_entries: usize,
    exported_entries: usize,
    entries: Vec<&'a RegistryEntry>,
}
fn reparse(metadata: &fs::Metadata) -> bool {
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
pub fn export_findings(
    report: &ScanReport,
    request: &ExportRequest,
    directory: &Path,
) -> Result<ExportResult, String> {
    if request.scan_id != report.id {
        return Err(
            "Only the latest scan can be exported. Scan again before exporting historical results."
                .into(),
        );
    }
    if request.query.len() > 16384
        || request.entry_ids.is_empty()
        || request.entry_ids.len() > report.entries.len()
    {
        return Err("Choose a nonempty, bounded selection of scan findings to export.".into());
    }
    let ids: HashSet<_> = request.entry_ids.iter().collect();
    if ids.len() != request.entry_ids.len() {
        return Err("Duplicate export entries are not allowed.".into());
    }
    let entries: Vec<_> = report
        .entries
        .iter()
        .filter(|e| ids.contains(&e.id))
        .collect();
    if entries.len() != ids.len()
        || entries.iter().any(|e| {
            request.category.is_some_and(|c| e.category != c)
                || request.status.is_some_and(|s| e.assessment.status != s)
        })
    {
        return Err("The export selection does not match this scan and its filters.".into());
    }
    let count = entries.len();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    let payload = Findings {
        format: "rustregistry.findings",
        schema_version: 1,
        application_version: env!("CARGO_PKG_VERSION"),
        exported_at: now,
        scan: ScanInfo {
            id: &report.id,
            started_at: report.started_at,
            duration_ms: report.duration_ms,
            cancelled: report.cancelled,
            read_only: report.read_only,
            architecture: &report.architecture,
            scope_count: report.scopes.len(),
        },
        filters: Filters {
            query: &request.query,
            category: request.category,
            status: request.status,
        },
        total_entries: report.entries.len(),
        exported_entries: count,
        entries,
    };
    let bytes = serde_json::to_vec_pretty(&payload).map_err(|e| e.to_string())?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("This report exceeds 64 MiB. Narrow the filters and export again.".into());
    }
    fs::create_dir_all(directory)
        .map_err(|e| format!("Cannot create the report directory: {e}"))?;
    let metadata = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || reparse(&metadata) {
        return Err("The report location must be a regular local directory.".into());
    }
    let path = directory.join(format!(
        "RustRegistry-findings-{now}-{}.json",
        uuid::Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| format!("Cannot create the report: {e}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("Report writing failed: {e}"))?;
    Ok(ExportResult {
        path: path.to_string_lossy().into_owned(),
        entries: count,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn report() -> ScanReport {
        let entries=(0..60).map(|i|serde_json::from_value(serde_json::json!({"id":format!("id-{i}"),"name":format!("Entry {i}"),"category":"application_icons","hive":"HKCU","view":"shared","keyPath":format!(r"Software\Classes\Applications\App{i}.exe\DefaultIcon"),"valueName":"","valueType":"REG_SZ","rawValue":r"C:\Missing\icon.ico","publisher":null,"version":null,"assessment":{"status":"review","code":"target_missing","explanation":"Missing icon only","target":r"C:\Missing\icon.ico"},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false,"iconRepairable":true})).unwrap()).collect();
        ScanReport {
            id: "current-scan".into(),
            started_at: 1,
            duration_ms: 2,
            cancelled: true,
            read_only: true,
            architecture: "x64".into(),
            entries,
            scopes: vec![],
        }
    }
    fn request() -> ExportRequest {
        ExportRequest {
            scan_id: "current-scan".into(),
            entry_ids: (10..50).map(|i| format!("id-{i}")).collect(),
            query: "icon".into(),
            category: Some(Category::ApplicationIcons),
            status: Some(EntryStatus::Review),
        }
    }
    #[test]
    fn exports_all_selected_findings_beyond_one_page_marks_partial_scans_and_never_overwrites_reports(
    ) {
        let report = report();
        let directory = tempfile::tempdir().unwrap();
        let first = export_findings(&report, &request(), directory.path()).unwrap();
        let second = export_findings(&report, &request(), directory.path()).unwrap();
        assert_ne!(first.path, second.path);
        assert_eq!(first.entries, 40);
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&first.path).unwrap()).unwrap();
        assert_eq!(document["format"], "rustregistry.findings");
        assert_eq!(document["exportedEntries"], 40);
        assert_eq!(document["totalEntries"], 60);
        assert_eq!(document["scan"]["cancelled"], true);
        assert_eq!(document["entries"][0]["id"], "id-10");
        assert_eq!(document["entries"][39]["id"], "id-49");
        assert_eq!(document["entries"][0]["rawValue"], r"C:\Missing\icon.ico");
        assert!(document["entries"][0].get("iconState").is_none());
        assert!(document.get("integritySha256").is_none());
        assert_eq!(report.entries.len(), 60);
    }
    #[test]
    fn refuses_stale_duplicate_unknown_empty_or_mismatched_selections_before_creating_files() {
        let report = report();
        let directory = tempfile::tempdir().unwrap();
        for scenario in 0..6 {
            let mut request = request();
            match scenario {
                0 => request.scan_id = "old-scan".into(),
                1 => request.entry_ids.push(request.entry_ids[0].clone()),
                2 => request.entry_ids[0] = "unknown".into(),
                3 => request.entry_ids.clear(),
                4 => request.status = Some(EntryStatus::Found),
                5 => request.query = "x".repeat(16385),
                _ => unreachable!(),
            };
            assert!(export_findings(&report, &request, directory.path()).is_err());
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }
    #[test]
    fn reports_storage_failure_without_touching_scan_data() {
        let report = report();
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("blocked");
        fs::write(&file, b"preserve").unwrap();
        assert!(export_findings(&report, &request(), &file)
            .unwrap_err()
            .contains("report directory"));
        assert_eq!(fs::read(file).unwrap(), b"preserve");
        assert_eq!(report.entries.len(), 60);
    }
}
