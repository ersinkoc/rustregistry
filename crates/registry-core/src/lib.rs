mod analysis;
pub mod app_leftovers;
pub mod applications;
pub mod associations;
pub mod changes;
pub mod com;
pub mod com_conversions;
pub mod com_redirects;
pub mod file_references;
pub mod leftover_types;
pub mod leftover_urls;
pub mod maintenance;
mod model;
pub mod prog_ids;
pub mod registered_apps;
#[cfg(windows)]
mod scan_probe;
#[cfg(windows)]
mod scanner;
pub mod services;
pub mod shared_dlls;
pub mod sound_events;
pub mod type_libraries;
pub mod uninstall;
#[cfg(windows)]
pub mod windows_changes;

pub use analysis::{
    analyze_target, Environment, LocalPathProbe, PathProbe, ProbeResult, TargetKind,
};
pub use model::*;
#[cfg(windows)]
pub use scanner::scan;

#[cfg(not(windows))]
pub fn scan(
    _cancel: &std::sync::atomic::AtomicBool,
    _progress: impl Fn(ScanProgress),
) -> Result<ScanReport, String> {
    Err("Live registry scanning is only available on Windows.".into())
}

pub mod interfaces;

pub mod com_proxies;

pub mod application_icons;
pub mod report_exports;

pub mod shell_menus;
