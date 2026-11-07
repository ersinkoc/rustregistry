use super::*;
use crate::{
    changes::RegistryStore,
    prog_ids::*,
    windows_changes::{open_prog_id_child, WindowsRegistryStore},
};

pub(super) fn scan_prog_ids(
    source: &Source,
    root: &RegKey,
    cancel: &AtomicBool,
    environment: &Environment,
    entries: &mut Vec<RegistryEntry>,
    scope: &mut ScopeResult,
    probe: &impl PathProbe,
) {
    let start = entries.len();
    let store = WindowsRegistryStore::default();
    for (index, item) in root.enum_keys().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            scope.status = "cancelled".into();
            break;
        }
        if index >= 30000 || entries.len() - start >= MAX_ENTRIES_PER_SCOPE {
            scope.status = "limited".into();
            break;
        }
        let name = match item {
            Ok(name) => name,
            Err(error) => {
                scope.notes.push(read_error(&error));
                continue;
            }
        };
        if validate_com_progid(&name).is_err() {
            continue;
        }
        let prog_id = match open_prog_id_child(root, &name) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(error) => {
                scope.notes.push(error);
                continue;
            }
        };
        let clsid = match open_prog_id_child(&prog_id, "CLSID") {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(error) => {
                scope.notes.push(error);
                continue;
            }
        };
        let raw = clsid.get_raw_value("");
        let original = raw.as_ref().ok().map(|v| crate::changes::StoredValue {
            kind: v.vtype.clone() as u32,
            bytes: v.bytes.to_vec(),
        });
        let path = format!(r"{name}\CLSID");
        let mut entry = make_entry(
            source,
            &path,
            name.clone(),
            "",
            raw.map_err(|e| read_error(&e)),
            environment,
            probe,
        );
        entry.assessment=match &original{
            None=>Assessment{status:EntryStatus::Unknown,code:"prog_id_mapping_absent".into(),explanation:"No readable default CLSID mapping is present. This alone does not prove an application is broken.".into(),target:None},
            Some(value)=>match mapping_clsid(value){
                Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"prog_id_mapping_unverified".into(),explanation:reason,target:None},
                Ok(id)=>match store.prog_id_target_exists(&id){
                    Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"clsid_unverified".into(),explanation:reason,target:Some(id)},
                    Ok(true)=>Assessment{status:EntryStatus::Found,code:"clsid_found".into(),explanation:"The CLSID key exists in a user or machine 32/64-bit view. This does not prove that COM activation works. No object was activated and no resolution API was called.".into(),target:Some(id)},
                    Ok(false)=>{
                        if source.hive=="HKCU"{
                            let app=ProgIdBackup{prog_id:name.clone(),clsid:id.clone(),guard:ProgIdGuard{values:vec![]}};
                            if let Ok(state)=store.read_prog_id(&app){if state.value==original{entry.prog_id_state=Some(state);entry.prog_id_repairable=true;}}
                        }
                        Assessment{status:EntryStatus::Review,code:"clsid_missing".into(),explanation:if entry.prog_id_repairable{"The referenced CLSID is absent from both hives and both architecture views. This simple current-user mapping can be reviewed for backed-up removal; keys, descriptions, default selections, and files are preserved."}else{"The referenced CLSID is absent from both hives and both architecture views. Machine mappings, machine counterparts, CurVer/shell/complex metadata, and uncertain evidence remain outside repair scope."}.into(),target:Some(id)}
                    }
                }
            }
        };
        entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct NoFileProbe;
    impl PathProbe for NoFileProbe {
        fn probe(&self, _: &str, _: TargetKind) -> crate::ProbeResult {
            panic!("Registry reference inventory must not probe files")
        }
    }
    #[test]
    fn declared_scan_scope_ids_remain_unique_when_checks_share_a_classes_root() {
        let sources = super::super::sources();
        let ids: std::collections::HashSet<_> =
            sources.iter().map(super::super::source_id).collect();
        assert_eq!(ids.len(), sources.len());
    }
    #[test]
    fn prog_id_inventory_is_read_only_and_distinguishes_missing_malformed_and_absent_mappings() {
        let base = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
        let (root, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&base)
            .unwrap();
        let missing = format!("{{{}}}", uuid::Uuid::new_v4());
        let (key, _) = root.create_subkey(r"Example.Missing.1\CLSID").unwrap();
        key.set_value("", &missing).unwrap();
        root.create_subkey(r"Example.Malformed.1\CLSID")
            .unwrap()
            .0
            .set_value("", &"%CLSID%")
            .unwrap();
        root.create_subkey(r"Example.Absent.1\CLSID").unwrap();
        root.create_subkey("Example.NotAReference.1").unwrap();
        let before = key.get_raw_value("").unwrap().bytes.into_owned();
        let source = Source {
            category: Category::ProgIds,
            hive: "HKCU",
            path: PROG_IDS_KEY,
            view: "shared",
            flag: 0,
        };
        let mut scope = ScopeResult {
            id: "owned".into(),
            category: source.category,
            hive: source.hive.into(),
            key_path: source.path.into(),
            view: source.view.into(),
            status: "complete".into(),
            entries: 0,
            notes: vec![],
        };
        let mut entries = vec![];
        scan_prog_ids(
            &source,
            &root,
            &AtomicBool::new(false),
            &Environment::default(),
            &mut entries,
            &mut scope,
            &NoFileProbe,
        );
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "Example.Missing.1")
                .unwrap()
                .assessment
                .code,
            "clsid_missing"
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "Example.Malformed.1")
                .unwrap()
                .assessment
                .code,
            "prog_id_mapping_unverified"
        );
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "Example.Absent.1")
                .unwrap()
                .assessment
                .code,
            "prog_id_mapping_absent"
        );
        assert_eq!(key.get_raw_value("").unwrap().bytes.as_ref(), before);
        let mut canceled = vec![];
        scan_prog_ids(
            &source,
            &root,
            &AtomicBool::new(true),
            &Environment::default(),
            &mut canceled,
            &mut scope,
            &NoFileProbe,
        );
        assert!(canceled.is_empty());
        assert_eq!(scope.status, "cancelled");
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(base)
            .unwrap();
        let sources = super::super::sources();
        assert_eq!(sources.len(), 33);
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::ProgIds && s.view == "shared")
                .count(),
            2
        );
    }
}
