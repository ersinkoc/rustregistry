#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use registry_core::{
    changes::{
        BackupInventory, ChangeManager, ChangePlan, ChangeResult, CleanPlan, CleanProgress,
        CleanResult,
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
    on_progress: Channel<ScanProgress>,
) -> Result<ScanReport, String> {
    let guard = acquire(&control)?;
    control.cancelled.store(false, Ordering::Release);
    let cancelled = control.cancelled.clone();
    let last_report = control.last_report.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let result = registry_core::scan(&cancelled, |progress| {
            let _ = on_progress.send(progress);
        })?;
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

fn main() {
    tauri::Builder::default()
        .manage(ScanControl::default())
        .setup(|app| {
            let directory = app.path().app_local_data_dir()?.join("backups-v1");
            app.manage(Changes(Arc::new(Mutex::new(ChangeManager::new(
                WindowsRegistryStore::default(),
                directory,
                LocalPathProbe,
            )))));
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
            list_backups
        ])
        .run(tauri::generate_context!())
        .expect("RustRegistry could not be started");
}
