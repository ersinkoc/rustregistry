#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use registry_core::{
    changes::{
        BackupInventory, ChangeManager, ChangePlan, ChangeResult, CleanPlan, CleanProgress,
        CleanResult, UndoPlan, UndoResult,
    },
    windows_changes::WindowsRegistryStore,
    Category, LocalPathProbe, ScanProgress, ScanReport,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::{ipc::Channel, Manager, State};

#[derive(Default)]
struct ScanControl {
    running: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    clean_cancelled: Arc<AtomicBool>,
    last_report: Arc<Mutex<Option<ScanReport>>>,
}

struct Changes(Arc<Mutex<ChangeManager<WindowsRegistryStore, LocalPathProbe>>>);
struct History(std::path::PathBuf);

struct RunningGuard(Arc<AtomicBool>);
impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn acquire(control: &ScanControl) -> Result<RunningGuard, String> {
    control
        .running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "A scan or registry change is already running.".to_string())?;
    Ok(RunningGuard(control.running.clone()))
}

#[tauri::command]
async fn scan_registry(
    control: State<'_, ScanControl>,
    history: State<'_, History>,
    on_progress: Channel<ScanProgress>,
) -> Result<ScanReport, String> {
    let guard = acquire(&control)?;
    control.cancelled.store(false, Ordering::Release);
    let cancelled = control.cancelled.clone();
    let last_report = control.last_report.clone();
    let history_path = history.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let mut result = registry_core::scan(&cancelled, |progress| {
            let _ = on_progress.send(progress);
        })?;
        if let Err(error) = registry_core::history::HistoryStore::new(history_path).save(&result) {
            result.history_warning = Some(format!(
                "This scan could not be saved to local history: {error}"
            ));
        }
        *last_report
            .lock()
            .map_err(|_| "Scan state is unavailable.".to_string())? = Some(result.clone());
        Ok(result)
    })
    .await
    .map_err(|error| format!("The scan could not be completed: {error}"))?
}

#[tauri::command]
fn cancel_scan(control: State<'_, ScanControl>) {
    control.cancelled.store(true, Ordering::Release);
}

#[tauri::command]
async fn export_findings(
    app: tauri::AppHandle,
    control: State<'_, ScanControl>,
    request: registry_core::report_exports::ExportRequest,
) -> Result<registry_core::report_exports::ExportResult, String> {
    let guard = acquire(&control)?;
    let reports = app
        .path()
        .app_local_data_dir()
        .map_err(|e| e.to_string())?
        .join("reports-v1");
    let cache = control.last_report.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let cache = cache.lock().map_err(|_| "Scan state is unavailable.")?;
        let report = cache
            .as_ref()
            .ok_or("Run a scan before exporting findings.")?;
        registry_core::report_exports::export_findings(report, &request, &reports)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn prepare_quarantine(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    entry_id: String,
    scan_id: Option<String>,
) -> Result<ChangePlan, String> {
    let guard = acquire(&control)?;
    let entry = {
        let cache = control
            .last_report
            .lock()
            .map_err(|_| "Scan state is unavailable.")?;
        let report = cache
            .as_ref()
            .filter(|report| !report.cancelled)
            .ok_or("Complete a fresh scan before reviewing a change.")?;
        if scan_id.as_ref().is_some_and(|id| id != &report.id) {
            return Err("Historical reports cannot authorize changes. Run a fresh scan.".into());
        }
        report
            .entries
            .iter()
            .find(|entry| entry.id == entry_id)
            .cloned()
            .ok_or("This entry is not in the latest scan.")?
    };
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        manager
            .lock()
            .map_err(|_| "Change state is unavailable.".to_string())?
            .prepare_quarantine(&entry)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn prepare_restore(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    backup_id: String,
) -> Result<ChangePlan, String> {
    let guard = acquire(&control)?;
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        manager
            .lock()
            .map_err(|_| "Change state is unavailable.".to_string())?
            .prepare_restore(&backup_id)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn apply_change(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    token: String,
    confirmed: bool,
) -> Result<ChangeResult, String> {
    if !confirmed {
        return Err("Explicit confirmation is required.".into());
    }
    let guard = acquire(&control)?;
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        manager
            .lock()
            .map_err(|_| "Change state is unavailable.".to_string())?
            .apply(&token)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn prepare_clean(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    mode: String,
    entry_ids: Vec<String>,
    category: Option<Category>,
    scan_id: Option<String>,
) -> Result<CleanPlan, String> {
    let guard = acquire(&control)?;
    control.clean_cancelled.store(false, Ordering::Release);
    let entries = {
        let cache = control
            .last_report
            .lock()
            .map_err(|_| "Scan state is unavailable.")?;
        let report = cache
            .as_ref()
            .filter(|r| !r.cancelled)
            .ok_or("Complete a fresh scan before cleaning.")?;
        if scan_id.as_ref().is_some_and(|id| id != &report.id) {
            return Err("Historical reports cannot authorize cleaning. Run a fresh scan.".into());
        }
        registry_core::changes::select_clean_entries(&report.entries, &mode, &entry_ids, category)?
    };
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        manager
            .lock()
            .map_err(|_| "Change state is unavailable.".to_string())?
            .prepare_clean(&entries, &mode)
    })
    .await
    .map_err(|e| e.to_string())?
}
async fn run_clean(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    token: String,
    confirmed: bool,
    on_progress: Option<Channel<CleanProgress>>,
) -> Result<CleanResult, String> {
    if !confirmed {
        return Err("Explicit confirmation is required.".into());
    }
    let guard = acquire(&control)?;
    let cancellation = control.clean_cancelled.clone();
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        manager
            .lock()
            .map_err(|_| "Change state is unavailable.".to_string())?
            .apply_clean_with_progress(
                &token,
                || cancellation.load(Ordering::Acquire),
                |progress| {
                    if let Some(channel) = &on_progress {
                        let _ = channel.send(progress);
                    }
                },
            )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn apply_clean(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    token: String,
    confirmed: bool,
) -> Result<CleanResult, String> {
    run_clean(control, changes, token, confirmed, None).await
}
#[tauri::command]
async fn apply_clean_progress(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    token: String,
    confirmed: bool,
    on_progress: Channel<CleanProgress>,
) -> Result<CleanResult, String> {
    run_clean(control, changes, token, confirmed, Some(on_progress)).await
}

#[tauri::command]
fn cancel_clean(control: State<'_, ScanControl>) {
    control.clean_cancelled.store(true, Ordering::Release);
}

#[tauri::command]
fn cancel_change(changes: State<'_, Changes>) -> Result<(), String> {
    changes
        .0
        .lock()
        .map_err(|_| "Change state is unavailable.")?
        .cancel();
    Ok(())
}

#[tauri::command]
async fn list_backups(changes: State<'_, Changes>) -> Result<BackupInventory, String> {
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager
            .lock()
            .map_err(|_| "Change state is unavailable.".to_string())?
            .inventory()
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn set_display_scale(window: tauri::WebviewWindow, percent: u32) -> Result<(), String> {
    if ![100, 125, 150, 175, 200].contains(&percent) {
        return Err("Unsupported interface size.".into());
    }
    window
        .set_zoom(f64::from(percent) / 100.0)
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn list_operations(
    changes: State<'_, Changes>,
) -> Result<registry_core::journal::OperationInventory, String> {
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager
            .lock()
            .map_err(|_| "Change state is unavailable.")?
            .operation_inventory()
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn list_scan_history(
    history: State<'_, History>,
) -> Result<registry_core::history::HistoryInventory, String> {
    let path = history.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        registry_core::history::HistoryStore::new(path).inventory()
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn get_saved_scan(history: State<'_, History>, id: String) -> Result<ScanReport, String> {
    let path = history.0.clone();
    // Loading an archive deliberately never changes ScanControl.last_report.
    tauri::async_runtime::spawn_blocking(move || {
        registry_core::history::HistoryStore::new(path).load(&id)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn prepare_undo(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    operation_id: Option<String>,
    backup_ids: Vec<String>,
) -> Result<UndoPlan, String> {
    let guard = acquire(&control)?;
    control.clean_cancelled.store(false, Ordering::Release);
    if operation_id.is_some() && !backup_ids.is_empty() {
        return Err("Choose an operation or selected backups.".into());
    }
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let mut manager = manager.lock().map_err(|_| "Change state is unavailable.")?;
        match operation_id {
            Some(id) => manager.prepare_undo_operation(&id),
            None => manager.prepare_undo_backups(&backup_ids),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn apply_undo(
    control: State<'_, ScanControl>,
    changes: State<'_, Changes>,
    token: String,
    confirmed: bool,
    on_progress: Channel<CleanProgress>,
) -> Result<UndoResult, String> {
    if !confirmed {
        return Err("Explicit confirmation is required.".into());
    }
    let guard = acquire(&control)?;
    let cancellation = control.clean_cancelled.clone();
    let manager = changes.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        manager
            .lock()
            .map_err(|_| "Change state is unavailable.")?
            .apply_undo_with_progress(
                &token,
                || cancellation.load(Ordering::Acquire),
                |progress| {
                    let _ = on_progress.send(progress);
                },
            )
    })
    .await
    .map_err(|e| e.to_string())?
}

fn recovery_directory(normal: std::path::PathBuf) -> std::path::PathBuf {
    // An owned, uniquely named E2E alias gets isolated journal/history storage across restarts.
    // This cannot redirect registry access or backup storage.
    if let (Ok(token), Ok(exe)) = (
        std::env::var("RUSTREGISTRY_ELEVATED_WEBVIEW_TOKEN"),
        std::env::current_exe(),
    ) {
        if uuid::Uuid::parse_str(&token).is_ok_and(|id| id.to_string() == token)
            && exe.file_name().and_then(|name| name.to_str())
                == Some(format!("RustRegistry-E2E-WebView-{token}.exe").as_str())
        {
            if let Some(parent) = exe.parent() {
                return parent.join("state-v0200");
            }
        }
    }
    normal
}

fn main() {
    tauri::Builder::default()
        .manage(ScanControl::default())
        .setup(|app| {
            let local = app.path().app_local_data_dir()?;
            let directory = local.join("backups-v1");
            let recovery = recovery_directory(local);
            app.manage(History(recovery.join("history-v1")));
            app.manage(Changes(Arc::new(Mutex::new(
                ChangeManager::new(WindowsRegistryStore::default(), directory, LocalPathProbe)
                    .with_journal(recovery.join("operations-v1")),
            ))));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            set_display_scale,
            export_findings,
            scan_registry,
            cancel_scan,
            cancel_clean,
            prepare_quarantine,
            prepare_restore,
            apply_change,
            prepare_clean,
            apply_clean,
            apply_clean_progress,
            cancel_change,
            list_backups,
            list_operations,
            list_scan_history,
            get_saved_scan,
            prepare_undo,
            apply_undo
        ])
        .run(tauri::generate_context!())
        .expect("RustRegistry could not be started");
}
