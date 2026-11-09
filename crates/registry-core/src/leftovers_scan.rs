use super::*;
use crate::{
    app_leftovers::*,
    changes::{RegistryStore, StoredValue},
    windows_changes::{open_registration_path, WindowsRegistryStore},
};
#[path = "leftover_urls_scan.rs"]
mod urls;
pub(super) fn scan_leftovers(
    source: &Source,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    if source.path == crate::applications::APPLICATIONS_KEY {
        scan_supported_types(source, cancel, environment, entries, scope, probe);
        return;
    }
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
        let remaining = MAX_ENTRIES_PER_SCOPE.saturating_sub(entries.len() - start);
        if remaining == 0 {
            scope.status = "limited".into();
            break;
        }
        urls::UrlInventory {
            source,
            environment,
            probe,
            store: &store,
            anchors: &anchors,
        }
        .append(&name, &state, entries, scope, remaining);
        if entries.len() - start >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
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
                                supported_type: None,
                                url_metadata: None,
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

fn scan_supported_types(
    source: &Source,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let store = WindowsRegistryStore::default();
    let (names, anchors) = match store
        .leftover_type_names()
        .and_then(|names| store.leftover_anchors(None).map(|anchors| (names, anchors)))
    {
        Ok(v) => v,
        Err(e) => {
            scope.status = "error".into();
            scope.notes.push(e);
            return;
        }
    };
    let start = entries.len();
    for name in names {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if entries.len() - start >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
        let mut state = match store.leftover_type_state(&name, None) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Ok(companion) = store.leftover_type_companion(&name, None) {
            state.guard.app_paths = companion.map(Box::new);
        }
        let command = match state.guard.command().and_then(|v| v.text()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let target = crate::applications::assess_command(&command, environment, probe).target;
        let directory = target
            .as_deref()
            .and_then(|s| s.rsplit_once('\\'))
            .map(|(d, _)| d.to_string());
        for hint in &state.hints {
            if entries.len() - start >= MAX_ENTRIES_PER_SCOPE {
                scope.status = "limited".into();
                break;
            }
            let mut e = make_entry(
                source,
                &format!(r"{name}\SupportedTypes"),
                name.clone(),
                &hint.name,
                Err("Suggestion ownership has not been verified.".into()),
                environment,
                probe,
            );
            e.value_type = if hint.value.kind == 1 {
                "REG_SZ"
            } else {
                "Unsupported"
            }
            .into();
            e.raw_value = hint.value.text().unwrap_or_default();
            e.assessment=Assessment{status:EntryStatus::Unknown,code:"leftover_type_unverified".into(),explanation:"A file-type suggestion alone does not establish an uninstalled application. Exact missing application, installation and unique non-MSI uninstall evidence is required.".into(),target:target.clone()};
            if let Some(directory) = &directory {
                if let Some(owners) = anchors.get(&directory.to_ascii_lowercase()) {
                    if owners.len() == 1 {
                        if let Ok(snapshot) = &owners[0].1 {
                            if let Ok(anchor) = normalized_anchor(snapshot) {
                                let app = LeftoverBackup {
                                    executable_name: name.clone(),
                                    value_name: hint.name.clone(),
                                    directory: directory.clone(),
                                    uninstall_key: owners[0].0.clone(),
                                    anchor,
                                    application_values: state.application_values.clone(),
                                    path_list: None,
                                    supported_type: Some(Box::new(state.guard.clone())),
                                    url_metadata: None,
                                };
                                match state.guard.evidence(&app, probe) {
                                    Ok(evidence) => {
                                        e.name = evidence.application_name.clone();
                                        e.publisher = snapshot.text("Publisher").ok();
                                        e.version = snapshot.text("DisplayVersion").ok();
                                        e.assessment=Assessment{status:EntryStatus::Review,code:"application_leftover_candidate".into(),explanation:"A missing literal open-command executable, exact missing installation directory and unique non-MSI uninstall owner suggest an application leftover. Only the selected empty SupportedTypes hint can be removed; this does not prove that all settings are disposable.".into(),target:target.clone()};
                                        match app
                                            .verify_original(&hint.value, probe)
                                            .and_then(|_| store.read_leftover(&app))
                                            .and_then(|v| {
                                                if v.as_ref() == Some(&hint.value) {
                                                    Ok(())
                                                } else {
                                                    Err("The suggestion changed during scanning."
                                                        .into())
                                                }
                                            }) {
                                            Ok(()) => {
                                                e.leftover_repairable = true;
                                                e.leftover_state = Some(app);
                                                e.snapshot = Some(hint.value.clone());
                                            }
                                            Err(reason) => {
                                                e.assessment.explanation.push_str(&format!(
                                                    " Suggestion cleanup unavailable: {reason}"
                                                ))
                                            }
                                        }
                                        e.leftover_evidence = Some(evidence);
                                    }
                                    Err(reason) => e.assessment.explanation = reason,
                                }
                            }
                        }
                    } else {
                        e.assessment.explanation="Multiple uninstall owners share this directory; suggestion cleanup is blocked.".into();
                    }
                }
            }
            entries.push(e);
        }
    }
    scope.entries = entries.len() - start;
    scope.notes.push("This logical check reuses the existing current-user Applications and Uninstall roots. Only bounded empty REG_SZ SupportedTypes values with exact corroborated missing-target evidence support cleanup. Commands, sibling hints, DefaultIcon metadata, application settings/licenses, keys, files, permissions and default selections are preserved.".into());
}
