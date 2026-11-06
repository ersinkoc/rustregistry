#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use registry_core::{ScanProgress, ScanReport};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tauri::{ipc::Channel, State};

#[derive(Default)]
struct ScanControl {
    running: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
}

struct RunningGuard(Arc<AtomicBool>);
impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[tauri::command]
async fn scan_registry(
    control: State<'_, ScanControl>,
    on_progress: Channel<ScanProgress>,
) -> Result<ScanReport, String> {
    control
        .running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "A scan is already running.".to_string())?;
    control.cancelled.store(false, Ordering::Release);
    let guard = RunningGuard(control.running.clone());
    let cancelled = control.cancelled.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        registry_core::scan(&cancelled, |progress| {
            let _ = on_progress.send(progress);
        })
    })
    .await
    .map_err(|error| format!("The scan could not be completed: {error}"))?
}

#[tauri::command]
fn cancel_scan(control: State<'_, ScanControl>) {
    control.cancelled.store(true, Ordering::Release);
}

fn main() {
    tauri::Builder::default()
        .manage(ScanControl::default())
        .invoke_handler(tauri::generate_handler![scan_registry, cancel_scan])
        .run(tauri::generate_context!())
        .expect("RustRegistry could not be started");
}
