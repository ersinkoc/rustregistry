use super::*;

pub const MAX_CLEAN_ENTRIES: usize = 10_000;
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanProgress {
    pub completed: usize,
    pub total: usize,
    pub current: String,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanSkipped {
    pub name: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanPlan {
    pub token: String,
    pub mode: String,
    pub expires_at: u64,
    pub items: Vec<ChangePlan>,
    pub skipped: Vec<CleanSkipped>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanResult {
    pub operation_id: Option<String>,
    pub completed: Vec<ChangeResult>,
    pub failed: Option<CleanSkipped>,
    pub not_attempted: usize,
    pub cancelled: bool,
}
pub(super) struct PendingBatch {
    pub(super) plan: CleanPlan,
    pub(super) records: Vec<(ChangePlan, BackupRecord)>,
}

pub fn is_repair_candidate(entry: &RegistryEntry) -> bool {
    if entry.category == Category::ApplicationLeftovers {
        return entry.hive == "HKCU"
            && entry.view == "shared"
            && entry.leftover_repairable
            && entry.leftover_state.is_some()
            && entry.assessment.status == EntryStatus::Review;
    }
    if entry.category == Category::SoundEvents {
        return entry.hive == "HKCU"
            && entry.view == "shared"
            && entry.sound_repairable
            && entry.sound_state.is_some()
            && entry.assessment.status == EntryStatus::Review;
    }
    if matches!(entry.category, Category::Fonts | Category::HelpFiles) {
        return entry.file_reference_repairable
            && entry.file_reference.is_some()
            && entry.assessment.status == EntryStatus::Review;
    }
    if matches!(entry.category, Category::MuiCache | Category::UsageHistory) {
        return entry.hive == "HKCU"
            && entry.view == "shared"
            && entry.maintenance_repairable
            && entry.maintenance_state.is_some()
            && entry.assessment.status
                == if entry.category == Category::UsageHistory {
                    EntryStatus::Found
                } else {
                    EntryStatus::Review
                };
    }
    if entry.category == Category::SharedDlls {
        return entry.hive == "HKLM"
            && entry.view == "64"
            && entry.shared_dll_repairable
            && entry.assessment.status == EntryStatus::Review;
    }
    if entry.category == Category::Services {
        return entry.hive == "HKLM"
            && entry.view == "shared"
            && entry.service_repairable
            && entry.assessment.status == EntryStatus::Review;
    }
    if entry.hive != "HKCU" || entry.assessment.status != EntryStatus::Review {
        return false;
    }
    match entry.category {
        Category::Startup => {
            entry.view == "shared"
                && entry.key_path.eq_ignore_ascii_case(STARTUP_KEY)
                && entry.snapshot.is_some()
        }
        Category::ShellMenus => {
            entry.view == "shared" && entry.menu_repairable && !entry.menu_hidden
        }
        Category::ApplicationIcons => entry.view == "shared" && entry.icon_repairable,
        Category::ComConversions => entry.view == "64" && entry.conversion_repairable,
        Category::ComRedirections => entry.view == "64" && entry.redirection_repairable,
        Category::ComProxies => entry.view == "64" && entry.proxy_repairable,
        Category::Interfaces => entry.view == "64" && entry.interface_repairable,
        Category::ProgIds => entry.view == "shared" && entry.prog_id_repairable,
        Category::TypeLibraries => entry.view == "shared" && entry.type_library_repairable,
        Category::RegisteredApplications => {
            entry.view == "shared" && entry.registered_app_repairable
        }
        Category::AppPaths => entry.app_path_repairable,
        Category::ApplicationCommands => {
            entry.view == "shared" && entry.application_repairable && !entry.application_hidden
        }
        Category::Uninstall => entry.uninstall_repairable && !entry.uninstall_hidden,
        Category::FileAssociations => entry.association_repairable,
        Category::Com => entry.com_repairable && entry.view == "64",
        _ => false,
    }
}

pub fn is_quick_clean_candidate(entry: &RegistryEntry) -> bool {
    entry.category != Category::UsageHistory && is_repair_candidate(entry)
}

impl<S: RegistryStore, P: PathProbe> ChangeManager<S, P> {
    pub fn prepare_clean(
        &mut self,
        entries: &[RegistryEntry],
        mode: &str,
    ) -> Result<CleanPlan, String> {
        self.cancel();
        if !["quick", "selected", "full"].contains(&mode)
            || entries.is_empty()
            || entries.len() > MAX_CLEAN_ENTRIES
        {
            return Err(
                format!("Select between 1 and {MAX_CLEAN_ENTRIES} eligible entries for one cleaning review."),
            );
        }
        let mut ids = std::collections::HashSet::new();
        let mut guarded_locations = std::collections::HashSet::new();
        let mut records = Vec::new();
        let mut skipped = Vec::new();
        // Preparation is a read-only point-in-time review. Read the shared cache
        // once for all requested groups; applying every record still uses fresh
        // file checks, fresh live values and its own conditional transaction.
        let cache_apps: Vec<_> = entries
            .iter()
            .filter(|entry| entry.category == Category::MuiCache)
            .filter_map(|entry| entry.maintenance_state.as_ref())
            .filter(|app| app.kind == crate::maintenance::MaintenanceKind::MuiCache)
            .cloned()
            .collect();
        let cache_states = if cache_apps.is_empty() {
            vec![]
        } else {
            self.store.read_maintenance_batch(&cache_apps)
        };
        if cache_states.len() != cache_apps.len() {
            return Err("The store returned an incomplete cache review snapshot.".into());
        }
        let prepared_cache: std::collections::HashMap<_, _> = cache_apps
            .iter()
            .zip(cache_states)
            .map(|(app, state)| (app.item.to_ascii_lowercase(), state))
            .collect();
        for entry in entries {
            if mode != "selected" && entry.category == Category::UsageHistory {
                skipped.push(CleanSkipped{name:entry.name.clone(),reason:"Optional history requires an explicit selected or individual review; Quick Clean excludes it.".into()});
                continue;
            }
            if !ids.insert(entry.id.clone()) {
                self.cancel();
                return Err("Duplicate entries are not allowed in one cleaning review.".into());
            }
            let location = format!(
                "{}|{}|{}|{}",
                entry.hive,
                entry.view,
                if matches!(entry.category, Category::Interfaces | Category::ComProxies) {
                    entry
                        .key_path
                        .rsplit_once('\\')
                        .map_or(entry.key_path.as_str(), |(parent, _)| parent)
                        .to_ascii_lowercase()
                } else {
                    entry.key_path.to_ascii_lowercase()
                },
                if (entry.category == Category::ApplicationLeftovers
                    && entry
                        .leftover_state
                        .as_ref()
                        .is_some_and(
                            |app| app.supported_type.is_some() || app.url_metadata.is_some()
                        ))
                    || matches!(
                        entry.category,
                        Category::SharedDlls
                            | Category::RegisteredApplications
                            | Category::MuiCache
                            | Category::Fonts
                            | Category::HelpFiles
                    )
                {
                    entry.value_name.to_ascii_lowercase()
                } else {
                    String::new()
                }
            );
            if entry.category != Category::Startup && guarded_locations.contains(&location) {
                skipped.push(CleanSkipped {name: entry.name.clone(), reason: "Another change to this guarded registration is already included. Scan again after cleaning to review the remaining value.".into()});
                continue;
            }
            let prepared = if entry.category == Category::MuiCache {
                match entry
                    .maintenance_state
                    .as_ref()
                    .and_then(|app| prepared_cache.get(&app.item.to_ascii_lowercase()))
                {
                    Some(Ok(state)) => self.prepare_maintenance(entry, Some(state)),
                    Some(Err(reason)) => Err(reason.clone()),
                    None => self.prepare_quarantine(entry),
                }
            } else {
                self.prepare_quarantine(entry)
            };
            match prepared {
                Ok(plan) => {
                    let pending = self
                        .pending
                        .take()
                        .ok_or("The cleaning review could not be prepared.")?;
                    let PendingAction::Quarantine(record) = pending.action else {
                        return Err("Unexpected cleaning action.".into());
                    };
                    guarded_locations.insert(location);
                    records.push((plan, record));
                }
                Err(reason) => skipped.push(CleanSkipped {
                    name: entry.name.clone(),
                    reason,
                }),
            }
        }
        self.ensure_backup_capacity(records.len())?;
        let expires_at = records
            .iter()
            .map(|(plan, _)| plan.expires_at)
            .min()
            .unwrap_or(now()? + PLAN_LIFETIME);
        let plan = CleanPlan {
            token: Uuid::new_v4().to_string(),
            mode: mode.into(),
            expires_at,
            items: records.iter().map(|(plan, _)| plan.clone()).collect(),
            skipped,
        };
        self.pending = None;
        self.batch_pending = Some(PendingBatch {
            plan: plan.clone(),
            records,
        });
        Ok(plan)
    }

    pub fn apply_clean(&mut self, token: &str) -> Result<CleanResult, String> {
        self.apply_clean_with_progress(token, || false, |_| {})
    }
    pub fn apply_clean_with_progress(
        &mut self,
        token: &str,
        cancelled: impl Fn() -> bool,
        progress: impl Fn(CleanProgress),
    ) -> Result<CleanResult, String> {
        let batch = self
            .batch_pending
            .take()
            .ok_or("No cleaning review is pending.")?;
        self.pending = None;
        if batch.plan.token != token || now()? > batch.plan.expires_at {
            return Err("The cleaning review expired or does not match. Review again.".into());
        }
        let total = batch.records.len();
        self.ensure_backup_capacity(total)?;
        let mut run = self.start_operation(
            crate::journal::OperationKind::Clean,
            &batch.plan.mode,
            None,
            batch
                .records
                .iter()
                .map(|(plan, record)| Self::journal_entry(record, plan))
                .collect(),
        )?;
        let operation_id = run.as_ref().map(|r| r.id().to_string());
        self.batch_applying = true;
        let result = (|| {
            let mut completed = Vec::new();
            progress(CleanProgress {
                completed: 0,
                total,
                current: String::new(),
            });
            for (index, (mut plan, record)) in batch.records.into_iter().enumerate() {
                if cancelled() {
                    self.pending = None;
                    return Ok(CleanResult {
                        operation_id: operation_id.clone(),
                        not_attempted: total - completed.len(),
                        completed,
                        failed: None,
                        cancelled: true,
                    });
                }
                let name = plan.name.clone();
                // The batch review was authorized above. Long-running batches must
                // retain that authorization while every item still checks live data.
                plan.expires_at = u64::MAX;
                let item_token = plan.token.clone();
                self.pending = Some(Pending {
                    plan,
                    action: PendingAction::Quarantine(record),
                });
                match self.apply_recorded(&item_token, &mut run, index) {
                    Ok(result) => {
                        completed.push(result);
                        progress(CleanProgress {
                            completed: completed.len(),
                            total,
                            current: name,
                        });
                    }
                    Err(reason) => {
                        let not_attempted = total - completed.len() - 1;
                        return Ok(CleanResult {
                            operation_id: operation_id.clone(),
                            completed,
                            failed: Some(CleanSkipped { name, reason }),
                            not_attempted,
                            cancelled: false,
                        });
                    }
                }
            }
            Ok(CleanResult {
                operation_id,
                completed,
                failed: None,
                not_attempted: 0,
                cancelled: false,
            })
        })();
        self.batch_applying = false;
        if let Some(run) = &mut run {
            let outcome = match &result {
                Ok(result) if result.cancelled => "cancelled",
                Ok(result) if result.failed.is_none() => "completed",
                _ => "attention",
            };
            run.finish(outcome)?;
        }
        result
    }
}

pub fn select_clean_entries(
    entries: &[RegistryEntry],
    mode: &str,
    ids: &[String],
    category: Option<Category>,
) -> Result<Vec<RegistryEntry>, String> {
    let selected = if mode == "quick" || mode == "full" {
        if !ids.is_empty() || (mode == "full" && category.is_some()) {
            return Err(
                "Automatic cleaning uses current scan candidates; Full Clean spans all categories."
                    .into(),
            );
        }
        entries
            .iter()
            .filter(|e| is_quick_clean_candidate(e) && category.is_none_or(|c| e.category == c))
            .take(MAX_CLEAN_ENTRIES + 1)
            .cloned()
            .collect::<Vec<_>>()
    } else if mode == "selected" && !ids.is_empty() && ids.len() <= MAX_CLEAN_ENTRIES {
        let by_id: std::collections::HashMap<_, _> = entries.iter().map(|e| (&e.id, e)).collect();
        ids.iter()
            .map(|id| {
                by_id
                    .get(id)
                    .map(|e| (*e).clone())
                    .ok_or_else(|| "An entry is not in the latest scan.".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        return Err("Unsupported cleaning mode or selection size.".into());
    };
    if selected.is_empty() || selected.len() > MAX_CLEAN_ENTRIES {
        return Err(format!("One review supports 1–{MAX_CLEAN_ENTRIES} candidates. Narrow the category or select a smaller set; no candidates were silently truncated."));
    }
    Ok(selected)
}
