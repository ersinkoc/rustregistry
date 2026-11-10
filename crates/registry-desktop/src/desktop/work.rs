use registry_core::{
    changes::{BackupInventory, ChangeManager, ChangePlan, CleanPlan, CleanProgress, UndoPlan},
    history::{HistoryInventory, HistoryStore},
    journal::OperationInventory,
    windows_changes::WindowsRegistryStore,
    LocalPathProbe, ScanProgress, ScanReport,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

type Manager = ChangeManager<WindowsRegistryStore, LocalPathProbe>;

#[derive(Clone)]
pub struct Store {
    pub directory: PathBuf,
    pub manager: Arc<Mutex<Manager>>,
}

impl Store {
    pub fn new(directory: PathBuf) -> Self {
        let manager = ChangeManager::new(
            WindowsRegistryStore::default(),
            directory.join("backups-v1"),
            LocalPathProbe,
        )
        .with_journal(directory.join("operations-v1"));
        Self {
            directory,
            manager: Arc::new(Mutex::new(manager)),
        }
    }

    pub fn history(&self) -> HistoryStore {
        HistoryStore::new(self.directory.join("history-v1"))
    }

    pub fn change<T>(
        &self,
        task: impl FnOnce(&mut Manager) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut manager = self
            .manager
            .lock()
            .map_err(|_| "Registry change state is unavailable.")?;
        task(&mut manager)
    }
}

#[derive(Clone, Debug)]
pub struct Progress {
    pub completed: usize,
    pub total: usize,
    pub current: String,
    pub entries: Option<usize>,
}

#[derive(Clone, Default)]
pub struct Control {
    stopped: Arc<AtomicBool>,
    progress: Arc<Mutex<Option<Progress>>>,
}

impl Control {
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    pub fn take_progress(&self) -> Option<Progress> {
        self.progress.lock().ok()?.take()
    }

    fn publish(&self, progress: Progress) {
        if let Ok(mut current) = self.progress.lock() {
            *current = Some(progress);
        }
    }

    fn scan_progress(&self, progress: ScanProgress) {
        self.publish(Progress {
            completed: progress.completed,
            total: progress.total,
            current: progress.current,
            entries: Some(progress.entries),
        });
    }

    pub fn change_progress(&self, progress: CleanProgress) {
        self.publish(Progress {
            completed: progress.completed,
            total: progress.total,
            current: progress.current,
            entries: None,
        });
    }

    pub fn scan(&self, store: &Store) -> Result<ScanReport, String> {
        let mut report = registry_core::scan(&self.stopped, |update| self.scan_progress(update))?;
        if let Err(error) = store.history().save(&report) {
            report.history_warning = Some(format!("Could not save the scan locally: {error}"));
        }
        Ok(report)
    }
}

pub enum Review {
    Change(Box<ChangePlan>),
    Clean(CleanPlan),
    Undo(UndoPlan),
}

pub enum Completed {
    Report(ScanReport, bool),
    Backups(BackupInventory),
    Operations(OperationInventory),
    History(HistoryInventory),
    Review(Review),
    Receipt {
        title: String,
        details: Vec<String>,
        registry_changed: bool,
    },
    Discarded,
}
