use super::*;
use crate::{
    changes::RegistryStore,
    com_redirects::*,
    windows_changes::{open_interface_child, WindowsRegistryStore},
};

pub(super) fn scan_redirections(
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
        if crate::com::validate_clsid(&name).is_err() {
            continue;
        }
        let interface = match open_interface_child(root, &name, source.flag) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(error) => {
                scope.notes.push(error);
                continue;
            }
        };
        let clsid = match open_interface_child(&interface, "TreatAs", source.flag) {
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
        let path = format!(r"{name}\TreatAs");
        let mut entry = make_entry(
            source,
            &path,
            read_optional(&interface, "", &mut scope.notes).unwrap_or_else(|| name.clone()),
            "",
            raw.map_err(|e| read_error(&e)),
            environment,
            probe,
        );
        let mut exclusion = None;
        entry.assessment=match &original{
            None=>Assessment{status:EntryStatus::Unknown,code:"redirection_mapping_absent".into(),explanation:"No readable default TreatAs redirection is present. This alone does not prove an application is broken.".into(),target:None},
            Some(value)=>match mapping_target(value){
                Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"redirection_mapping_unverified".into(),explanation:reason,target:None},
                Ok(id) if id.eq_ignore_ascii_case(&name)=>Assessment{status:EntryStatus::Unknown,code:"redirection_self_reference".into(),explanation:"Self-referencing TreatAs is not followed and remains read-only.".into(),target:Some(id)},
                Ok(id)=>match store.prog_id_target_exists(&id){
                    Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"redirection_clsid_unverified".into(),explanation:reason,target:Some(id)},
                    Ok(true)=>Assessment{status:EntryStatus::Found,code:"redirection_clsid_found".into(),explanation:"The target class key exists in a user or machine 32/64-bit view. This does not prove that COM activation works. No object was activated and no resolution API was called.".into(),target:Some(id)},
                    Ok(false)=>{
                        if source.hive=="HKCU" && source.view=="64"{
                            let app=RedirectionBackup{owner:name.clone(),target:id.clone(),guard:RedirectionGuard{values:vec![]}};
                            match store.read_redirection(&app) {
                                Ok(state) if state.value==original=>{entry.redirection_state=Some(state);entry.redirection_repairable=true;},
                                Err(reason)=>exclusion=Some(reason),
                                _=>{},
                            }
                        }
                        Assessment{status:EntryStatus::Review,code:"redirection_clsid_missing".into(),explanation:if entry.redirection_repairable{"The local target class is absent from both hives and both architecture views. This simple current-user mapping can be reviewed for backed-up removal; keys, descriptions, and files are preserved. Local absence does not establish remote activation needs or prove an application is broken. Review this redirection before disabling it."}else{"The local target class is absent from both hives and both architecture views. 32-bit/machine mappings, 32-bit user or machine counterparts, complex activation metadata, and uncertain evidence remain outside repair scope."}.into(),target:Some(id)}
                    }
                }
            }
        };
        if let Some(reason) = exclusion {
            entry
                .assessment
                .explanation
                .push_str(&format!(" Recovery unavailable: {reason}"));
        }
        entry.assessment.explanation.push_str(" Only local class-key existence is checked; remote activation needs are not established. No COM activation, resolution API, redirection-chain traversal, or file probe is performed.");
        entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct NoFileProbe;
    impl PathProbe for NoFileProbe {
        fn probe(&self, _: &str, _: TargetKind) -> crate::ProbeResult {
            panic!("TreatAs reference checks must not probe files")
        }
    }
    #[test]
    fn redirection_inventory_is_read_only_and_keeps_malformed_absent_and_cancelled_evidence_unverified(
    ) {
        let base = format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4());
        let root = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&base)
            .unwrap()
            .0;
        let ids: Vec<_> = (0..3)
            .map(|_| format!("{{{}}}", uuid::Uuid::new_v4()))
            .collect();
        let missing = format!("{{{}}}", uuid::Uuid::new_v4());
        for (index, id) in ids.iter().enumerate() {
            let leaf = root.create_subkey(format!(r"{id}\TreatAs")).unwrap().0;
            if index < 2 {
                leaf.set_value("", &if index == 0 { &missing } else { "%LIBID%" })
                    .unwrap();
            }
        }
        let source = Source {
            category: Category::ComRedirections,
            hive: "HKCU",
            path: crate::com::CLSID_KEY,
            flag: KEY_WOW64_64KEY,
            view: "64",
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
        scan_redirections(
            &source,
            &root,
            &AtomicBool::new(false),
            &Environment::default(),
            &mut entries,
            &mut scope,
            &NoFileProbe,
        );
        assert_eq!(entries.len(), 3);
        for (index, code) in [
            "redirection_clsid_missing",
            "redirection_mapping_unverified",
            "redirection_mapping_absent",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                &entries
                    .iter()
                    .find(|e| e.name == ids[index])
                    .unwrap()
                    .assessment
                    .code,
                code
            );
        }
        assert_eq!(
            root.open_subkey(format!(r"{}\TreatAs", ids[0]))
                .unwrap()
                .get_value::<String, _>("")
                .unwrap(),
            missing
        );
        let mut cancelled = vec![];
        scan_redirections(
            &source,
            &root,
            &AtomicBool::new(true),
            &Environment::default(),
            &mut cancelled,
            &mut scope,
            &NoFileProbe,
        );
        assert!(cancelled.is_empty());
        assert_eq!(scope.status, "cancelled");
        RegKey::predef(HKEY_CURRENT_USER)
            .delete_subkey_all(base)
            .unwrap();
        let sources = super::super::sources();
        assert_eq!(sources.len(), 66);
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::ComRedirections)
                .count(),
            4
        );
    }
}
