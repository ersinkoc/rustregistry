use super::*;

pub(super) fn scan_shared_dlls(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
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
        let assessment = if !valid {
            Assessment {status: EntryStatus::Unknown, code: "unsupported_reference_count".into(), explanation: "The usage count is not a supported DWORD. It was not interpreted and remains read-only.".into(), target: None}
        } else if source.view == "32" {
            Assessment {status: EntryStatus::Unknown, code: "shared_dll_32bit_unverified".into(), explanation: "This 32-bit shared-file reference was inventoried without probing its target in a 64-bit filesystem context. Usage counts are never changed.".into(), target: None}
        } else {
            analyze_target(&path, TargetKind::File, environment, &LocalPathProbe)
        };
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
            snapshot: None,
            app_path_guard: None,
            app_path_repairable: false,
            uninstall_snapshot: None,
            uninstall_repairable: false,
            uninstall_hidden: false,
            association_state: None,
            association_repairable: false,
            com_state: None,
            com_repairable: false,
        });
    }
}
