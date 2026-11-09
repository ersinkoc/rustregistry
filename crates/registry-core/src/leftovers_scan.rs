use super::*;
use crate::{
    app_leftovers::*,
    changes::{RegistryStore, StoredValue},
    windows_changes::{open_registration_path, WindowsRegistryStore},
};
pub(super) fn scan_leftovers(
    source: &Source,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let store = WindowsRegistryStore::default();
    let Some(root) = (match open_registration_path(
        HKEY_CURRENT_USER,
        crate::changes::APP_PATHS_KEY,
        KEY_WOW64_64KEY,
        None,
        false,
    ) {
        Ok(k) => k,
        Err(e) => {
            scope.status = "error".into();
            scope.notes.push(e);
            return;
        }
    }) else {
        scope.status = "missing".into();
        return;
    };
    let anchors = match store.leftover_anchors(None) {
        Ok(v) => v,
        Err(e) => {
            scope.status = "error".into();
            scope.notes.push(e);
            return;
        }
    };
    let start = entries.len();
    for (i, item) in root.enum_keys().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if i >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
        let name = match item {
            Ok(n) => n,
            Err(e) => {
                scope.notes.push(read_error(&e));
                continue;
            }
        };
        let state = match store.leftover_application(&name, None) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(value) = state.value else { continue };
        let mut entry = make_entry(
            source,
            &name,
            name.clone(),
            &state.name,
            Err("Leftover evidence has not been assessed.".into()),
            environment,
            probe,
        );
        entry.value_type = match value.kind {
            1 => "REG_SZ",
            2 => "REG_EXPAND_SZ",
            _ => "Unsupported",
        }
        .into();
        entry.raw_value = value.text().unwrap_or_default();
        entry.assessment=Assessment{status:EntryStatus::Unknown,code:"leftover_unverified".into(),explanation:"No unique matching uninstall registration and independent missing-file evidence establish this application as a leftover. Names alone are not ownership evidence.".into(),target:None};
        let directories = search_directories(&value).unwrap_or_default();
        let matched: Vec<_> = directories
            .iter()
            .filter(|d| anchors.contains_key(&d.to_ascii_lowercase()))
            .collect();
        let directory = if matched.len() == 1 {
            Some(matched[0].clone())
        } else if !entry.raw_value.contains(';') {
            directories.first().cloned()
        } else {
            None
        };
        if let Some(directory) = directory {
            entry.assessment.target = Some(directory.clone());
            let a = analyze_target(&directory, TargetKind::Directory, environment, probe);
            if a.status == EntryStatus::Found {
                entry.assessment=Assessment{status:EntryStatus::Found,code:"leftover_directory_present".into(),explanation:"The application search directory exists; it is not a confirmed missing-directory leftover.".into(),target:Some(directory.clone())};
            }
            if let Some(matches) = anchors.get(&directory.to_ascii_lowercase()) {
                if matches.len() == 1 {
                    let (anchor_key, snapshot) = &matches[0];
                    let evidence = (|| -> Result<LeftoverEvidence, String> {
                        let snapshot = snapshot.as_ref().map_err(Clone::clone)?;
                        let evidence_value = StoredValue {
                            kind: 1,
                            bytes: directory
                                .encode_utf16()
                                .chain([0])
                                .flat_map(u16::to_le_bytes)
                                .collect(),
                        };
                        let evidence =
                            correlate(&name, &evidence_value, anchor_key, snapshot, probe)?;
                        if let Some(default) = state.other.iter().find(|v| v.name.is_empty()) {
                            if default.value.kind != 1
                                || !default
                                    .value
                                    .text()?
                                    .eq_ignore_ascii_case(&evidence.executable)
                            {
                                return Err("The executable mapping points elsewhere; application ownership remains uncertain.".into());
                            }
                        }
                        Ok(evidence)
                    })();
                    match evidence {
                        Ok(evidence) => {
                            let snapshot = snapshot.as_ref().unwrap();
                            let backup = LeftoverBackup {
                                executable_name: name.clone(),
                                value_name: state.name.clone(),
                                directory: evidence.directory.clone(),
                                uninstall_key: anchor_key.clone(),
                                anchor: normalized_anchor(snapshot).unwrap(),
                                application_values: state.other,
                                path_list: entry.raw_value.contains(';').then_some(value.clone()),
                            };
                            entry.name = evidence.application_name.clone();
                            entry.publisher = snapshot.text("Publisher").ok();
                            entry.version = snapshot.text("DisplayVersion").ok();
                            entry.assessment=Assessment{status:EntryStatus::Review,code:"application_leftover_candidate".into(),explanation:"The same exact missing directory is referenced by an application search path and a unique non-MSI uninstall registration. Its application executable and direct uninstaller are also missing. This is a likely leftover, not proof that every application setting is disposable.".into(),target:Some(directory)};
                            let eligibility = backup
                                .verify_original(&value, probe)
                                .and_then(|_| store.read_leftover(&backup))
                                .and_then(|current| {
                                    if current.as_ref() == Some(&value) {
                                        Ok(())
                                    } else {
                                        Err("The search-path value changed during scanning.".into())
                                    }
                                });
                            match eligibility {
                                Ok(()) => {
                                    entry.leftover_repairable = true;
                                    entry.leftover_state = Some(backup);
                                    entry.snapshot = Some(value)
                                }
                                Err(e) => entry
                                    .assessment
                                    .explanation
                                    .push_str(&format!(" Search-path cleanup unavailable: {e}")),
                            }
                            entry.leftover_evidence = Some(evidence);
                        }
                        Err(e) => entry.assessment.explanation = e,
                    }
                } else {
                    entry.assessment.explanation="More than one uninstall registration references this directory. Shared-directory ownership is ambiguous; no leftover cleanup is offered.".into()
                }
            }
        }
        entries.push(entry);
    }
    scope.entries = entries.len() - start;
    scope.notes.push("This logical check correlates existing current-user App Paths and Uninstall inventory; it does not count a new physical root. Only supported per-value actions are offered. MSI/product-code registrations, machine counterparts, application settings, licenses, user data, installer databases and arbitrary vendor keys are not removed.".into());
}
