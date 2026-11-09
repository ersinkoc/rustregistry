use super::*;
use crate::journal::{JournalEntry, JournalStore, OperationInventory, OperationKind, OperationRun};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoItem {
    pub backup_id: String,
    pub name: String,
    pub registry_path: String,
    pub value_name: String,
    pub registry_view: String,
    pub original: Option<StoredValue>,
    pub state: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoPlan {
    pub token: String,
    pub source_operation_id: Option<String>,
    pub expires_at: u64,
    pub items: Vec<UndoItem>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoResult {
    pub operation_id: Option<String>,
    pub restored: usize,
    pub already_original: usize,
    pub blocked: Vec<UndoItem>,
    pub not_attempted: usize,
    pub cancelled: bool,
}
pub(super) struct PendingUndo {
    plan: UndoPlan,
    records: Vec<(JournalEntry, Option<BackupRecord>)>,
}
impl<S: RegistryStore, P: PathProbe> ChangeManager<S, P> {
    pub fn with_journal(mut self, directory: PathBuf) -> Self {
        self.journal_directory = Some(directory);
        self
    }
    pub fn operation_inventory(&self) -> Result<OperationInventory, String> {
        JournalStore::new(
            self.journal_directory
                .clone()
                .ok_or("Operation storage is not configured.")?,
        )
        .inventory()
    }
    pub(super) fn journal_entry(record: &BackupRecord, plan: &ChangePlan) -> JournalEntry {
        JournalEntry {
            backup_id: record.id.to_string(),
            integrity_sha256: record.integrity_sha256.clone(),
            name: plan.name.clone(),
            registry_path: plan.registry_path.clone(),
            registry_view: plan.registry_view.clone(),
            value_name: plan.value_name.clone(),
            scope: plan.scope.clone(),
        }
    }
    pub(super) fn start_operation(
        &self,
        kind: OperationKind,
        mode: &str,
        source: Option<String>,
        entries: Vec<JournalEntry>,
    ) -> Result<Option<OperationRun>, String> {
        if entries.is_empty() {
            return Ok(None);
        }
        self.journal_directory
            .as_ref()
            .map(|path| JournalStore::new(path.clone()).start(kind, mode, source, entries))
            .transpose()
    }
    pub(super) fn apply_recorded(
        &mut self,
        token: &str,
        run: &mut Option<OperationRun>,
        index: usize,
    ) -> Result<ChangeResult, String> {
        if let Some(run) = run {
            run.attempt(index)?;
        }
        let result = self.apply_inner(token);
        if let Some(run) = run {
            match &result {
                Ok(_) => run.applied(index)?,
                Err(reason) => run.failed(index, reason)?,
            }
        }
        result.map(|mut result| {
            result.operation_id = run.as_ref().map(|r| r.id().into());
            result
        })
    }
    pub fn prepare_undo_operation(&mut self, id: &str) -> Result<UndoPlan, String> {
        self.cancel();
        let operation = JournalStore::new(
            self.journal_directory
                .clone()
                .ok_or("Operation storage is not configured.")?,
        )
        .read(id)?;
        if !operation.summary.can_undo {
            return Err(
                "Review a stopped cleaning operation or an incomplete bulk Undo for recovery."
                    .into(),
            );
        }
        let restoring = operation.header.kind == OperationKind::Undo;
        let refs = operation
            .header
            .entries
            .into_iter()
            .zip(operation.states)
            .filter(|(_, state)| restoring || [1, 2, 3].contains(state))
            .map(|(entry, _)| entry)
            .collect();
        self.review_undo(refs, Some(id.into()))
    }
    pub fn prepare_undo_backups(&mut self, ids: &[String]) -> Result<UndoPlan, String> {
        self.cancel();
        if ids.is_empty() || ids.len() > crate::journal::MAX_OPERATION_ENTRIES {
            return Err("Select 1–10,000 backups for one bulk restore review.".into());
        }
        let mut seen = std::collections::HashSet::new();
        let mut refs = vec![];
        for id in ids {
            crate::storage::canonical_id(id)?;
            if !seen.insert(id) {
                return Err("Duplicate backup selection.".into());
            }
            // A corrupt or missing backup fails review, never authorizes a partial silent selection.
            let record = self.load(id)?;
            let plan = self.prepare(record.clone(), true)?;
            refs.push(Self::journal_entry(&record, &plan));
        }
        self.review_undo(refs, None)
    }
    fn review_undo(
        &mut self,
        refs: Vec<JournalEntry>,
        source: Option<String>,
    ) -> Result<UndoPlan, String> {
        let mut records = refs
            .into_iter()
            .rev()
            .map(|entry| {
                let record = self
                    .load(&entry.backup_id)
                    .ok()
                    .filter(|r| r.integrity_sha256 == entry.integrity_sha256);
                (entry, record)
            })
            .collect::<Vec<_>>();
        // Restore dependent metadata before the app mapping on which its guard relies.
        records.sort_by_key(
            |(_, record)| match record.as_ref().map(|r| r.schema_version) {
                Some(23 | 24) => 0,
                Some(26) => 1,
                Some(25 | 27) => 2,
                Some(2) => 4,
                _ => 3,
            },
        );
        let items = records
            .iter()
            .map(|(entry, record)| self.undo_state(entry, record.as_ref()))
            .collect();
        let plan = UndoPlan {
            token: Uuid::new_v4().to_string(),
            source_operation_id: source,
            expires_at: now()? + PLAN_LIFETIME,
            items,
        };
        self.pending = None;
        self.batch_pending = None;
        self.undo_pending = Some(PendingUndo {
            plan: plan.clone(),
            records,
        });
        Ok(plan)
    }
    fn undo_state(&self, entry: &JournalEntry, record: Option<&BackupRecord>) -> UndoItem {
        let state = match record {
            None => Err(
                "The immutable backup is missing, invalid or differs from the operation reference."
                    .into(),
            ),
            Some(record) => self.read_record(record).and_then(|value| match value {
                Some(value) if value == record.original => Ok("original_present"),
                None => Ok("restore_available"),
                _ => Err("A different live value is present. Undo never overwrites it.".into()),
            }),
        };
        let (state, reason) = match state {
            Ok(state) => (state.into(), String::new()),
            Err(reason) => ("blocked".into(), reason),
        };
        UndoItem {
            backup_id: entry.backup_id.clone(),
            name: entry.name.clone(),
            registry_path: entry.registry_path.clone(),
            value_name: entry.value_name.clone(),
            registry_view: entry.registry_view.clone(),
            original: record.map(|record| record.original.clone()),
            state,
            reason,
        }
    }
    pub fn apply_undo_with_progress(
        &mut self,
        token: &str,
        cancelled: impl Fn() -> bool,
        progress: impl Fn(CleanProgress),
    ) -> Result<UndoResult, String> {
        let pending = self
            .undo_pending
            .take()
            .ok_or("No bulk Undo review is pending.")?;
        self.pending = None;
        self.batch_pending = None;
        if token != pending.plan.token || now()? > pending.plan.expires_at {
            return Err("The Undo review expired or does not match. Review again.".into());
        }
        let total = pending.records.len();
        let mut run = self.start_operation(
            OperationKind::Undo,
            "bulk",
            pending.plan.source_operation_id,
            pending
                .records
                .iter()
                .map(|(entry, _)| entry.clone())
                .collect(),
        )?;
        let mut result = UndoResult {
            operation_id: run.as_ref().map(|r| r.id().into()),
            restored: 0,
            already_original: 0,
            blocked: vec![],
            not_attempted: total,
            cancelled: false,
        };
        progress(CleanProgress {
            completed: 0,
            total,
            current: String::new(),
        });
        for (index, (entry, reviewed)) in pending.records.into_iter().enumerate() {
            if cancelled() {
                result.cancelled = true;
                break;
            }
            // Reload and validate original evidence and all live guards at the last possible moment.
            let current = self.load(&entry.backup_id).ok().filter(|r| {
                Some(&r.integrity_sha256) == reviewed.as_ref().map(|r| &r.integrity_sha256)
                    && r.integrity_sha256 == entry.integrity_sha256
            });
            let mut item = self.undo_state(&entry, current.as_ref());
            match item.state.as_str() {
                "original_present" => {
                    if let Some(run) = &mut run {
                        run.original(index)?;
                    }
                    result.already_original += 1;
                }
                "restore_available" => {
                    let record = current.ok_or("The reviewed backup is unavailable.")?;
                    match self.prepare(record, true) {
                        Ok(mut plan) => {
                            plan.expires_at = u64::MAX;
                            self.pending
                                .as_mut()
                                .ok_or("Missing restore review.")?
                                .plan
                                .expires_at = u64::MAX;
                            match self.apply_recorded(&plan.token, &mut run, index) {
                                Ok(_) => result.restored += 1,
                                Err(error) => {
                                    // Journal failures stop the entire operation. A valid failed checkpoint permits continuing independent entries.
                                    if let Some(path) = &self.journal_directory {
                                        JournalStore::new(path.clone()).read(
                                            run.as_ref().ok_or("Missing operation journal.")?.id(),
                                        )?;
                                    }
                                    item.state = "blocked".into();
                                    item.reason = error;
                                    result.blocked.push(item);
                                }
                            }
                        }
                        Err(error) => {
                            if let Some(run) = &mut run {
                                run.blocked(index, &error)?;
                            }
                            item.state = "blocked".into();
                            item.reason = error;
                            result.blocked.push(item);
                        }
                    }
                }
                _ => {
                    if let Some(run) = &mut run {
                        run.blocked(index, &item.reason)?;
                    }
                    result.blocked.push(item);
                }
            }
            result.not_attempted = total - index - 1;
            progress(CleanProgress {
                completed: index + 1,
                total,
                current: entry.name,
            });
        }
        self.pending = None;
        if let Some(run) = &mut run {
            run.finish(if result.cancelled {
                "cancelled"
            } else if result.blocked.is_empty() {
                "completed"
            } else {
                "attention"
            })?;
        }
        Ok(result)
    }
}
