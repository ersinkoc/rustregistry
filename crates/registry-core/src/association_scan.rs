use super::*;

pub(super) fn scan_associations(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
) {
    use crate::associations::{
        validate_extension, validate_progid, validate_suggestion, OPEN_WITH,
    };
    use crate::changes::{RegistryStore, StoredValue};
    let store = crate::windows_changes::WindowsRegistryStore::default();
    let start = entries.len();
    'extensions: for (index, item) in root.enum_keys().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= 20_000 {
            scope.status = "limited".into();
            break;
        }
        let extension = match item {
            Ok(name) => name,
            Err(error) => {
                scope.notes.push(read_error(&error));
                continue;
            }
        };
        if !extension.starts_with('.') {
            continue;
        }
        if validate_extension(&extension).is_err() {
            scope.notes.push(format!(
                "{extension}: unsupported extension syntax; not inspected."
            ));
            continue;
        }
        let parent =
            match root.open_subkey_with_options_flags(&extension, REG_OPTION_OPEN_LINK, KEY_READ) {
                Ok(key) => key,
                Err(error) => {
                    scope
                        .notes
                        .push(format!("{extension}: {}", read_error(&error)));
                    continue;
                }
            };
        if parent
            .get_raw_value("SymbolicLinkValue")
            .is_ok_and(|v| v.vtype == REG_LINK)
        {
            scope
                .notes
                .push(format!("{extension}: registry link not followed."));
            continue;
        }
        let key = match parent.open_subkey_with_options_flags(
            OPEN_WITH,
            REG_OPTION_OPEN_LINK,
            KEY_READ,
        ) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                scope
                    .notes
                    .push(format!("{extension}: {}", read_error(&error)));
                continue;
            }
        };
        if key
            .get_raw_value("SymbolicLinkValue")
            .is_ok_and(|v| v.vtype == REG_LINK)
        {
            scope.notes.push(format!(
                "{extension}: Open with registry link not followed."
            ));
            continue;
        }
        for item in key.enum_values() {
            if cancel.load(Ordering::Relaxed) {
                scope.status = "cancelled".into();
                break 'extensions;
            }
            if entries.len() - start >= MAX_ENTRIES_PER_SCOPE {
                scope.status = "limited".into();
                break 'extensions;
            }
            let (progid, raw) = match item {
                Ok(value) => value,
                Err(error) => {
                    scope
                        .notes
                        .push(format!("{extension}: {}", read_error(&error)));
                    continue;
                }
            };
            let value_type = format!("{:?}", raw.vtype);
            let original = StoredValue {
                kind: raw.vtype as u32,
                bytes: raw.bytes.into_owned(),
            };
            let mut assessment = match validate_progid(&progid).and_then(|_| validate_suggestion(&original)).and_then(|_| store.association_registered(&progid)) {
                Ok(true) => Assessment {status: EntryStatus::Found, code: "progid_registered".into(), explanation: "The suggested file-type registration exists in the current-user or machine Classes root. Its handler and application functionality were not tested.".into(), target: Some(format!("HKCR\\{progid}"))},
                Ok(false) => Assessment {status: EntryStatus::Review, code: "progid_missing".into(), explanation: "This Open with suggestion refers to a file-type registration missing from both current-user and machine Classes roots. This does not diagnose or change your default application.".into(), target: Some(format!("HKCR\\{progid}"))},
                Err(reason) => Assessment {status: EntryStatus::Unknown, code: "association_unverified".into(), explanation: reason, target: None},
            };
            let state = if source.hive == "HKCU" && assessment.code == "progid_missing" {
                match store.read_association(&extension, &progid) {
                    Ok(state) if state.value.as_ref() == Some(&original) => Some(state),
                    Ok(_) => {
                        assessment.explanation.push_str(
                            " Repair unavailable: the suggestion changed during scanning.",
                        );
                        None
                    }
                    Err(reason) => {
                        assessment
                            .explanation
                            .push_str(&format!(" Repair unavailable: {reason}"));
                        None
                    }
                }
            } else {
                None
            };
            let path = format!("{}\\{extension}\\{OPEN_WITH}", source.path);
            entries.push(RegistryEntry {
                id: format!("{}|shared|{path}|{progid}", source.hive),
                name: format!("{extension} · {progid}"),
                category: Category::FileAssociations,
                hive: source.hive.into(),
                key_path: path,
                view: "shared".into(),
                value_name: progid,
                value_type,
                raw_value: if validate_suggestion(&original).is_ok() {
                    "(empty)".into()
                } else {
                    format!(
                        "Unsupported suggestion data ({} bytes; not interpreted)",
                        original.bytes.len()
                    )
                },
                publisher: None,
                version: None,
                assessment,
                snapshot: None,
                app_path_guard: None,
                app_path_repairable: false,
                uninstall_snapshot: None,
                uninstall_repairable: false,
                uninstall_hidden: false,
                association_repairable: state.is_some(),
                com_state: None,
                com_repairable: false,
                service_state: None,
                application_snapshot: None,
                application_repairable: false,
                application_hidden: false,
                shared_dll_repairable: false,
                registered_app_repairable: false,
                type_library_state: None,
                type_library_repairable: false,
                prog_id_state: None,
                prog_id_repairable: false,
                interface_state: None,
                interface_repairable: false,
                proxy_state: None,
                proxy_repairable: false,
                service_repairable: false,
                association_state: state,
            });
        }
    }
}
