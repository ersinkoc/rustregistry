use super::*;

pub(super) fn scan_shared_dlls(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    for (index, item) in root.enum_values().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
        let (path, value) = match item {
            Ok(item) => item,
            Err(error) => {
                scope.notes.push(read_error(&error));
                continue;
            }
        };
        let valid = value.vtype == REG_DWORD && value.bytes.len() == 4;
        let raw_value = if valid {
            format!(
                "Reference count: {}",
                u32::from_le_bytes(value.bytes[..4].try_into().unwrap())
            )
        } else {
            "Unsupported reference count (not interpreted)".into()
        };
        let mut assessment = if !valid {
            Assessment {status: EntryStatus::Unknown, code: "unsupported_reference_count".into(), explanation: "The usage count is not a supported DWORD. It was not interpreted and remains read-only.".into(), target: None}
        } else if source.view == "32" {
            Assessment {status: EntryStatus::Unknown, code: "shared_dll_32bit_unverified".into(), explanation: "This 32-bit shared-file reference was inventoried without probing its target in a 64-bit filesystem context. Usage counts are never changed.".into(), target: None}
        } else {
            analyze_target(&path, TargetKind::File, environment, probe)
        };
        let snapshot = valid.then(|| crate::changes::StoredValue {
            kind: 4,
            bytes: value.bytes.to_vec(),
        });
        let repairable = source.hive == "HKLM"
            && source.view == "64"
            && assessment.code == "target_missing"
            && root.enum_keys().next().is_none()
            && snapshot.as_ref().is_some_and(|v| {
                crate::shared_dlls::verify_missing_shared_dll(&path, v, &LocalPathProbe).is_ok()
            });
        if source.view == "64" && assessment.status == EntryStatus::Review {
            assessment.explanation.push_str(if repairable { " This zero-count reference can be reviewed for removal. Existing Windows registry write access is required; files are never deleted or loaded." } else { " Repair is limited to exact zero-count, literal local DLL paths outside the Windows directory in a readable flat 64-bit key. Other counters and registrations remain read-only." });
        }
        entries.push(RegistryEntry {
            id: format!("{}|{}|{}|{path}", source.hive, source.view, source.path),
            name: path.rsplit('\\').next().unwrap_or(&path).into(),
            category: Category::SharedDlls,
            hive: source.hive.into(),
            key_path: source.path.into(),
            view: source.view.into(),
            value_name: path,
            value_type: format!("{:?}", value.vtype),
            raw_value,
            publisher: None,
            version: None,
            assessment,
            snapshot,
            app_path_guard: None,
            app_path_repairable: false,
            uninstall_snapshot: None,
            uninstall_repairable: false,
            uninstall_hidden: false,
            association_state: None,
            association_repairable: false,
            com_state: None,
            com_repairable: false,
            service_state: None,
            application_snapshot: None,
            application_repairable: false,
            application_hidden: false,
            shared_dll_repairable: repairable,
            registered_app_repairable: false,
            type_library_state: None,
            type_library_repairable: false,
            prog_id_state: None,
            prog_id_repairable: false,
            interface_state: None,
            interface_repairable: false,
            conversion_state: None,
            maintenance_state: None,
            file_reference: None,
            file_reference_repairable: false,
            sound_state: None,
            sound_repairable: false,
            maintenance_repairable: false,
            conversion_repairable: false,
            redirection_state: None,
            redirection_repairable: false,
            proxy_state: None,
            proxy_repairable: false,
            icon_state: None,
            icon_repairable: false,
            menu_snapshot: None,
            menu_repairable: false,
            menu_hidden: false,
            service_repairable: false,
        });
    }
}
