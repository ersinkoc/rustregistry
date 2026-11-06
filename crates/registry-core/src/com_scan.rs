use super::*;

pub(super) fn scan_com(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
) {
    use crate::{
        changes::{RegistryStore, StoredValue},
        com::{validate_clsid, INPROC_SERVER},
    };
    let store = crate::windows_changes::WindowsRegistryStore::default();
    let start_count = entries.len();
    for (index, item) in root.enum_keys().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= MAX_ENTRIES_PER_SCOPE || entries.len() - start_count >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
        let clsid = match item {
            Ok(name) => name,
            Err(error) => {
                scope.notes.push(read_error(&error));
                continue;
            }
        };
        if validate_clsid(&clsid).is_err() {
            scope.notes.push(format!(
                "{clsid}: unsupported class identifier; not inspected."
            ));
            continue;
        }
        let class = match root.open_subkey_with_options_flags(
            &clsid,
            REG_OPTION_OPEN_LINK,
            KEY_READ | source.flag,
        ) {
            Ok(key) => key,
            Err(error) => {
                scope.notes.push(format!("{clsid}: {}", read_error(&error)));
                continue;
            }
        };
        if class
            .get_raw_value("SymbolicLinkValue")
            .is_ok_and(|v| v.vtype == REG_LINK)
        {
            scope
                .notes
                .push(format!("{clsid}: registry link not followed."));
            continue;
        }
        for server_name in [INPROC_SERVER, "LocalServer32", "InprocHandler32"] {
            if entries.len() - start_count >= MAX_ENTRIES_PER_SCOPE {
                scope.status = "limited".into();
                break;
            }
            let server = match class.open_subkey_with_options_flags(
                server_name,
                REG_OPTION_OPEN_LINK,
                KEY_READ | source.flag,
            ) {
                Ok(key) => key,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    scope.notes.push(format!("{clsid}: {}", read_error(&error)));
                    continue;
                }
            };
            if server
                .get_raw_value("SymbolicLinkValue")
                .is_ok_and(|v| v.vtype == REG_LINK)
            {
                scope
                    .notes
                    .push(format!("{clsid}: DLL mapping registry link not followed."));
                continue;
            }
            let raw = server.get_raw_value("");
            let (raw_value, value_type, mut assessment, original) = match raw {
            Ok(value) => {
                let kind = format!("{:?}", value.vtype);
                let original = StoredValue {kind: value.vtype as u32, bytes: value.bytes.into_owned()};
                match original.text() {
                    Ok(raw) => {
                        let assessment = if server_name == "LocalServer32" && server.get_raw_value("ServerExecutable").is_ok() {Assessment {status: EntryStatus::Unknown, code: "com_server_executable_override".into(), explanation: "This local server defines ServerExecutable. Its effective launch configuration was not interpreted or executed.".into(), target: None}} else if source.view == "32" {Assessment {status: EntryStatus::Unknown, code: "com_32bit_unverified".into(), explanation: "The 32-bit DLL mapping was inventoried without probing its target. WOW64 filesystem and environment resolution require a 32-bit context; this view remains read-only.".into(), target: None}} else {analyze_target(&raw, if server_name == "LocalServer32" {TargetKind::Command} else {TargetKind::File}, environment, &LocalPathProbe)};
                        (raw, kind, assessment, Some(original))
                    }
                    Err(reason) => (String::new(), kind, Assessment {status: EntryStatus::Unknown, code: "unsupported_value".into(), explanation: reason, target: None}, None),
                }
            }
            Err(error) => (String::new(), "—".into(), Assessment {status: EntryStatus::Unknown, code: "com_mapping_absent".into(), explanation: format!("No readable default DLL mapping is available. This alone does not prove the COM class is broken. {}", read_error(&error)), target: None}, None),
        };
            let state = if server_name == INPROC_SERVER
                && source.hive == "HKCU"
                && source.view == "64"
                && assessment.code == "target_missing"
            {
                match original.as_ref().ok_or("DLL evidence unavailable.").and_then(|value| crate::com::verify_missing_dll(value, &LocalPathProbe).map_err(|_| "Only explicit missing local DLL targets support repair.")).and_then(|_| store.read_com(&clsid).map_err(|_| "The class has a machine counterpart, alternative activation, unsupported metadata, or unreadable structure.")) {
                Ok(state) if state.value == original => Some(state),
                _ => {assessment.explanation.push_str(" Repair unavailable: only simple current-user 64-bit DLL classes with no machine counterpart and unchanged supported metadata are eligible."); None}
            }
            } else {
                None
            };
            let name = class
                .get_raw_value("")
                .ok()
                .and_then(|value| text(&value).ok())
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| clsid.clone());
            let path = format!("{}\\{clsid}\\{server_name}", source.path);
            entries.push(RegistryEntry {
                id: format!("{}|{}|{path}|", source.hive, source.view),
                name,
                category: Category::Com,
                hive: source.hive.into(),
                key_path: path,
                view: source.view.into(),
                value_name: String::new(),
                value_type,
                raw_value,
                publisher: None,
                version: None,
                assessment,
                snapshot: None,
                app_path_guard: None,
                app_path_repairable: false,
                uninstall_snapshot: None,
                uninstall_repairable: false,
                uninstall_hidden: false,
                association_state: None,
                association_repairable: false,
                com_repairable: state.is_some(),
                com_state: state,
            });
        }
    }
}
