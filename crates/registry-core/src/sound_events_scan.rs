use super::*;
use crate::{
    sound_events::*,
    windows_changes::{open_registration_path, WindowsRegistryStore},
};

fn visit(scope: &mut ScopeResult, cancel: &AtomicBool, visited: &mut usize) -> bool {
    if cancel.load(Ordering::Relaxed) {
        scope.status = "cancelled".into();
        return false;
    }
    *visited += 1;
    if *visited > MAX_ENTRIES_PER_SCOPE {
        scope.status = "limited".into();
        scope
            .notes
            .push("Sound inventory reached its 10,000-node traversal limit.".into());
        return false;
    }
    true
}

pub(super) fn scan_sounds(
    source: &Source,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let hive = if source.hive == "HKCU" {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    };
    let root = match open_registration_path(hive, SOUND_APPS, KEY_WOW64_64KEY, None, false) {
        Ok(Some(root)) => root,
        Ok(None) => {
            scope.status = "missing".into();
            return;
        }
        Err(e) => {
            scope.status = "error".into();
            scope.notes.push(e);
            return;
        }
    };
    let start = entries.len();
    let mut visited = 0;
    'applications: for app in root.enum_keys().take(MAX_ENTRIES_PER_SCOPE + 1) {
        if !visit(scope, cancel, &mut visited) {
            break;
        }
        let app = match app {
            Ok(n) => n,
            Err(e) => {
                scope.notes.push(read_error(&e));
                continue;
            }
        };
        let app_key = match open_registration_path(
            hive,
            &format!(r"{SOUND_APPS}\{app}"),
            KEY_WOW64_64KEY,
            None,
            false,
        ) {
            Ok(Some(k)) => k,
            Ok(None) => continue,
            Err(e) => {
                scope.notes.push(e);
                continue;
            }
        };
        for event in app_key.enum_keys().take(MAX_ENTRIES_PER_SCOPE + 1) {
            if !visit(scope, cancel, &mut visited) {
                break 'applications;
            }
            let event = match event {
                Ok(n) => n,
                Err(e) => {
                    scope.notes.push(read_error(&e));
                    continue;
                }
            };
            let parent = format!(r"{SOUND_APPS}\{app}\{event}");
            let key = match open_registration_path(hive, &parent, KEY_WOW64_64KEY, None, false) {
                Ok(Some(k)) => k,
                Ok(None) => continue,
                Err(e) => {
                    scope.notes.push(e);
                    continue;
                }
            };
            for scheme in key.enum_keys().take(MAX_ENTRIES_PER_SCOPE + 1) {
                if !visit(scope, cancel, &mut visited) {
                    break 'applications;
                }
                let scheme = match scheme {
                    Ok(n) => n,
                    Err(e) => {
                        scope.notes.push(read_error(&e));
                        continue;
                    }
                };
                let path = format!(r"{parent}\{scheme}");
                let current =
                    match open_registration_path(hive, &path, KEY_WOW64_64KEY, None, false) {
                        Ok(Some(k)) => k,
                        Ok(None) => continue,
                        Err(e) => {
                            scope.notes.push(e);
                            continue;
                        }
                    };
                let value = match current.get_raw_value("") {
                    Ok(v) => Some(crate::changes::StoredValue {
                        kind: v.vtype as u32,
                        bytes: v.bytes.into_owned(),
                    }),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => {
                        scope.notes.push(read_error(&e));
                        continue;
                    }
                };
                let name = format!("{app} / {event} / {scheme}");
                let mut entry = make_entry(
                    source,
                    &format!(r"{app}\{event}\{scheme}"),
                    name.clone(),
                    "",
                    Err("Sound evidence has not been assessed.".into()),
                    environment,
                    probe,
                );
                entry.name = name;
                entry.value_name = String::new();
                entry.raw_value = value
                    .as_ref()
                    .and_then(|v| v.text().ok())
                    .unwrap_or_default();
                entry.value_type = match value.as_ref().map(|v| v.kind) {
                    Some(1) => "REG_SZ",
                    Some(2) => "REG_EXPAND_SZ",
                    Some(4) => "REG_DWORD",
                    Some(_) => "Unsupported",
                    None => "(absent)",
                }
                .into();
                entry.assessment = if value
                    .as_ref()
                    .is_some_and(|v| v.bytes.len() > MAX_VALUE_BYTES)
                {
                    Assessment {
                        status: EntryStatus::Unknown,
                        code: "sound_unverified".into(),
                        explanation:
                            "The sound assignment exceeds inventory limits and remains read-only."
                                .into(),
                        target: None,
                    }
                } else {
                    assess_sound(value.as_ref(), environment, probe)
                };
                if entry.assessment.status == EntryStatus::Review {
                    let eligible = (|| -> Result<SoundBackup, String> {
                        if source.hive != "HKCU" || !scheme.eq_ignore_ascii_case(CURRENT) {
                            return Err("Saved, default, No Sounds and machine sound scheme assignments remain read-only; only current-user .Current mappings have repair.".into());
                        }
                        let state =
                            WindowsRegistryStore::default().sound_snapshot(&app, &event, None)?;
                        if state.value != value {
                            return Err("The sound assignment changed during scanning.".into());
                        }
                        let original = value
                            .as_ref()
                            .ok_or("No explicit sound assignment exists.")?;
                        let backup = SoundBackup {
                            application: app.clone(),
                            event: event.clone(),
                            target: original.text()?,
                            guard: state.guard,
                        };
                        backup.verify_original(original, probe)?;
                        Ok(backup)
                    })();
                    match eligible {
                        Ok(app) => {
                            entry.snapshot = value;
                            entry.sound_state = Some(app);
                            entry.sound_repairable = true
                        }
                        Err(e) => entry
                            .assessment
                            .explanation
                            .push_str(&format!(" Repair unavailable: {e}")),
                    }
                }
                entries.push(entry);
            }
        }
    }
    scope.entries = entries.len() - start;
    scope.notes.push("Persisted sound assignments only. Empty assignments are separate from missing files. Saved/default/No Sounds schemes and machine registrations are read-only. No audio is played, decoded or deleted; devices, volume, event labels, notification settings and runtime caches are not changed.".into());
}
