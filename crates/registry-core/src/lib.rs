mod analysis;
pub mod changes;
mod model;
#[cfg(windows)]
mod scanner;
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
