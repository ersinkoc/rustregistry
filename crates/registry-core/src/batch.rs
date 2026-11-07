use super::*;

pub const MAX_CLEAN_ENTRIES: usize = 100;
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
    pub completed: Vec<ChangeResult>,
    pub failed: Option<CleanSkipped>,
    pub not_attempted: usize,
}
pub(super) struct PendingBatch {
    pub(super) plan: CleanPlan,
    records: Vec<(ChangePlan, BackupRecord)>,
}

pub fn is_repair_candidate(entry: &RegistryEntry) -> bool {
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

impl<S: RegistryStore, P: PathProbe> ChangeManager<S, P> {
    pub fn prepare_clean(
        &mut self,
        entries: &[RegistryEntry],
        mode: &str,
    ) -> Result<CleanPlan, String> {
        self.cancel();
        if !["quick", "selected"].contains(&mode)
            || entries.is_empty()
            || entries.len() > MAX_CLEAN_ENTRIES
        {
            return Err(
                "Select between 1 and 100 eligible entries for one cleaning review.".into(),
            );
        }
        let mut ids = std::collections::HashSet::new();
        let mut guarded_locations = std::collections::HashSet::new();
        let mut records = Vec::new();
        let mut skipped = Vec::new();
        for entry in entries {
            if !ids.insert(entry.id.clone()) {
                self.cancel();
                return Err("Duplicate entries are not allowed in one cleaning review.".into());
            }
            let location = format!(
                "{}|{}|{}",
                entry.hive,
                entry.view,
                entry.key_path.to_ascii_lowercase()
            );
            if entry.category != Category::Startup && guarded_locations.contains(&location) {
                skipped.push(CleanSkipped {name: entry.name.clone(), reason: "Another change to this guarded registration is already included. Scan again after cleaning to review the remaining value.".into()});
                continue;
            }
            match self.prepare_quarantine(entry) {
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
        let batch = self
            .batch_pending
            .take()
            .ok_or("No cleaning review is pending.")?;
        self.pending = None;
        if batch.plan.token != token || now()? > batch.plan.expires_at {
            return Err("The cleaning review expired or does not match. Review again.".into());
        }
        let total = batch.records.len();
        let mut completed = Vec::new();
        for (plan, record) in batch.records {
            let name = plan.name.clone();
            let item_token = plan.token.clone();
            self.pending = Some(Pending {
                plan,
                action: PendingAction::Quarantine(record),
            });
            match self.apply(&item_token) {
                Ok(result) => completed.push(result),
                Err(reason) => {
                    let not_attempted = total - completed.len() - 1;
                    return Ok(CleanResult {
                        completed,
                        failed: Some(CleanSkipped { name, reason }),
                        not_attempted,
                    });
                }
            }
        }
        Ok(CleanResult {
            completed,
            failed: None,
            not_attempted: 0,
        })
    }
}
