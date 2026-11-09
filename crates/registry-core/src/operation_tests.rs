use super::*;
use crate::{
    changes::{ChangeManager, RegistryStore, StoredValue, STARTUP_KEY},
    journal::JournalStore,
    LocalPathProbe, RegistryEntry,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::{Cell, RefCell},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[derive(Serialize, Deserialize)]
struct Config {
    root: String,
    directory: PathBuf,
    action: String,
    operation_id: Option<String>,
}
struct ObservedStore {
    native: WindowsRegistryStore,
    count: Cell<usize>,
    crash_at: Option<usize>,
    directory: PathBuf,
    operation: RefCell<Option<String>>,
}
impl RegistryStore for ObservedStore {
    fn read(&self, name: &str) -> Result<Option<StoredValue>, String> {
        self.native.read(name)
    }
    fn compare_exchange(
        &self,
        name: &str,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        if self.operation.borrow().is_none() {
            let inventory = JournalStore::new(self.directory.join("operations")).inventory()?;
            let id = inventory
                .operations
                .into_iter()
                .find(|op| op.state == "running")
                .ok_or("No durable intent before registry write")?
                .id;
            *self.operation.borrow_mut() = Some(id);
        }
        let path = self.directory.join("operations").join(format!(
            "{}.jsonl",
            self.operation.borrow().as_ref().unwrap()
        ));
        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let line = bytes[..bytes.len() - 1]
            .rsplit(|b| *b == b'\n')
            .next()
            .unwrap();
        let frame: serde_json::Value = serde_json::from_slice(line).unwrap();
        assert_eq!(
            frame["data"]["event"]["type"], "attempt",
            "Durable intent must precede each registry transaction"
        );
        assert!(frame["data"]["event"]["index"]
            .as_u64()
            .is_some_and(|index| index < 1000));
        self.native.compare_exchange(name, expected, replacement)?;
        let count = self.count.get() + 1;
        self.count.set(count);
        if self.crash_at == Some(count) {
            let mut file = fs::File::create(self.directory.join("committed.marker")).unwrap();
            write!(file, "{count}").unwrap();
            file.sync_all().unwrap();
            // Parent kills this process while the native transaction has committed,
            // before post-read verification and the Applied checkpoint. No unwinding.
            loop {
                std::thread::park();
            }
        }
        Ok(())
    }
}
fn stored(path: &Path) -> StoredValue {
    StoredValue {
        kind: 2,
        bytes: format!("{}\0", path.join("missing.exe").display())
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
    }
}
fn entries(path: &Path) -> Vec<RegistryEntry> {
    (0..1000).map(|index|{
        let name=format!("Owned{index:04}");let value=stored(path);
        let mut entry:RegistryEntry=serde_json::from_value(serde_json::json!({"id":name,"name":name,"category":"startup","hive":"HKCU","keyPath":STARTUP_KEY,"view":"shared","valueName":name,"valueType":"REG_EXPAND_SZ","rawValue":value.text().unwrap(),"publisher":null,"version":null,"assessment":{"status":"review","code":"target_missing","explanation":"Owned missing fixture","target":value.text().unwrap()},"appPathRepairable":false,"uninstallRepairable":false,"uninstallHidden":false,"associationRepairable":false,"comRepairable":false,"serviceRepairable":false,"applicationRepairable":false,"applicationHidden":false,"sharedDllRepairable":false,"registeredAppRepairable":false})).unwrap();
        entry.snapshot=Some(value);entry
    }).collect()
}
fn make_manager(config: &Config, crash: bool) -> ChangeManager<ObservedStore, LocalPathProbe> {
    assert!(config.root.starts_with(r"Software\RustRegistryTests\"));
    let suffix = config
        .root
        .strip_prefix(r"Software\RustRegistryTests\")
        .unwrap();
    assert_eq!(uuid::Uuid::parse_str(suffix).unwrap().to_string(), suffix);
    ChangeManager::new(
        ObservedStore {
            native: WindowsRegistryStore {
                path: config.root.clone(),
                ..Default::default()
            },
            count: Cell::new(0),
            crash_at: crash.then_some(500),
            directory: config.directory.clone(),
            operation: RefCell::new(None),
        },
        config.directory.join("backups"),
        LocalPathProbe,
    )
    .with_journal(config.directory.join("operations"))
}
struct Fixture {
    config: Config,
    _temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            root: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
            directory: temp.path().into(),
            action: "clean".into(),
            operation_id: None,
        };
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&config.root)
            .unwrap();
        for entry in entries(temp.path()) {
            let value = entry.snapshot.unwrap();
            key.set_raw_value(
                &entry.value_name,
                &RegValue {
                    vtype: REG_EXPAND_SZ,
                    bytes: Cow::Owned(value.bytes),
                },
            )
            .unwrap();
        }
        Self {
            config,
            _temp: temp,
        }
    }
    fn count(&self) -> usize {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(&self.config.root)
            .unwrap()
            .enum_values()
            .count()
    }
    fn assert_original(&self) {
        let native = WindowsRegistryStore {
            path: self.config.root.clone(),
            ..Default::default()
        };
        assert_eq!(self.count(), 1000);
        for index in 0..1000 {
            assert_eq!(
                native.read(&format!("Owned{index:04}")).unwrap(),
                Some(stored(&self.config.directory))
            );
        }
    }
    fn kill_worker(&self) {
        let config_path = self.config.directory.join("worker.json");
        fs::write(&config_path, serde_json::to_vec(&self.config).unwrap()).unwrap();
        let log = fs::File::create(self.config.directory.join("worker.log")).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_changes::operation_tests::worker_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RUSTREGISTRY_OPERATION_TEST_CONFIG", config_path)
            .stdout(log.try_clone().unwrap())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let started = Instant::now();
        while !self.config.directory.join("committed.marker").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "Worker exited before barrier: {}",
                fs::read_to_string(self.config.directory.join("worker.log")).unwrap()
            );
            if started.elapsed() > Duration::from_secs(60) {
                let _ = child.kill();
                panic!("Worker did not reach the bounded 500-commit barrier");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(self.config.directory.join("committed.marker")).unwrap(),
            "500"
        );
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(&self.config.root)
            .unwrap();
    }
}
#[test]
fn worker_process() {
    let Ok(path) = std::env::var("RUSTREGISTRY_OPERATION_TEST_CONFIG") else {
        return;
    };
    let config: Config = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mut manager = make_manager(&config, true);
    if config.action == "clean" {
        let plan = manager
            .prepare_clean(&entries(&config.directory), "selected")
            .unwrap();
        manager.apply_clean(&plan.token).unwrap();
    } else {
        let plan = manager
            .prepare_undo_operation(config.operation_id.as_ref().unwrap())
            .unwrap();
        manager
            .apply_undo_with_progress(&plan.token, || false, |_| {})
            .unwrap();
    }
    panic!("Worker must be forcibly terminated at its commit barrier");
}
#[test]
fn native_thousand_clean_and_bulk_undo_preserve_exact_bytes() {
    let fixture = Fixture::new();
    let mut manager = make_manager(&fixture.config, false);
    let plan = manager
        .prepare_clean(&entries(&fixture.config.directory), "selected")
        .unwrap();
    assert_eq!(plan.items.len(), 1000);
    let result = manager.apply_clean(&plan.token).unwrap();
    assert_eq!(result.completed.len(), 1000);
    assert_eq!(fixture.count(), 0);
    drop(manager);
    let mut reopened = make_manager(&fixture.config, false);
    let plan = reopened
        .prepare_undo_operation(result.operation_id.as_ref().unwrap())
        .unwrap();
    assert_eq!(
        plan.items
            .iter()
            .filter(|i| i.state == "restore_available")
            .count(),
        1000
    );
    let result = reopened
        .apply_undo_with_progress(&plan.token, || false, |_| {})
        .unwrap();
    assert_eq!(result.restored, 1000);
    assert!(result.blocked.is_empty());
    fixture.assert_original();
}
#[test]
fn killed_clean_recovers_commit_without_applied_checkpoint_after_restart() {
    let fixture = Fixture::new();
    fixture.kill_worker();
    assert_eq!(fixture.count(), 500);
    let mut reopened = make_manager(&fixture.config, false);
    let operations = reopened.operation_inventory().unwrap();
    assert_eq!(operations.operations.len(), 1);
    let op = &operations.operations[0];
    assert_eq!(op.state, "interrupted");
    assert_eq!(op.attempted, 500);
    assert_eq!(op.applied, 499);
    assert_eq!(op.not_attempted, 500);
    let plan = reopened.prepare_undo_operation(&op.id).unwrap();
    assert_eq!(plan.items.len(), 500);
    let result = reopened
        .apply_undo_with_progress(&plan.token, || false, |_| {})
        .unwrap();
    assert_eq!(result.restored, 500);
    fixture.assert_original();
}
#[test]
fn killed_bulk_undo_reconciles_original_values_and_restores_remaining_after_restart() {
    let mut fixture = Fixture::new();
    let mut m = make_manager(&fixture.config, false);
    let plan = m
        .prepare_clean(&entries(&fixture.config.directory), "selected")
        .unwrap();
    let result = m.apply_clean(&plan.token).unwrap();
    drop(m);
    fixture.config.action = "undo".into();
    fixture.config.operation_id = result.operation_id;
    fixture.kill_worker();
    assert_eq!(fixture.count(), 500);
    let mut reopened = make_manager(&fixture.config, false);
    let operations = reopened.operation_inventory().unwrap().operations;
    let interrupted = operations
        .iter()
        .find(|o| {
            o.kind == crate::journal::OperationKind::Undo
                && o.state == "interrupted"
                && o.applied == 499
        })
        .unwrap();
    let plan = reopened.prepare_undo_operation(&interrupted.id).unwrap();
    assert_eq!(
        plan.items
            .iter()
            .filter(|i| i.state == "original_present")
            .count(),
        500
    );
    let result = reopened
        .apply_undo_with_progress(&plan.token, || false, |_| {})
        .unwrap();
    assert_eq!(result.restored, 500);
    assert_eq!(result.already_original, 500);
    fixture.assert_original();
}
