use super::*;
use crate::{
    changes::RegistryStore,
    com_proxies::*,
    windows_changes::{open_interface_child, WindowsRegistryStore},
};

pub(super) fn scan_proxies(
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
        let clsid = match open_interface_child(&interface, "ProxyStubClsid32", source.flag) {
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
        let path = format!(r"{name}\ProxyStubClsid32");
        let mut entry = make_entry(
            source,
            &path,
            read_optional(&interface, "", &mut scope.notes).unwrap_or_else(|| name.clone()),
            "",
            raw.map_err(|e| read_error(&e)),
            environment,
            probe,
        );
        entry.assessment=match &original{
            None=>Assessment{status:EntryStatus::Unknown,code:"proxy_mapping_absent".into(),explanation:"No readable default proxy mapping is present. This alone does not prove an application is broken.".into(),target:None},
            Some(value)=>match mapping_clsid(value){
                Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"proxy_mapping_unverified".into(),explanation:reason,target:None},
                Ok(id)=>match store.prog_id_target_exists(&id){
                    Err(reason)=>Assessment{status:EntryStatus::Unknown,code:"proxy_clsid_unverified".into(),explanation:reason,target:Some(id)},
                    Ok(true)=>Assessment{status:EntryStatus::Found,code:"proxy_clsid_found".into(),explanation:"The proxy class key exists in a user or machine 32/64-bit view. This does not prove that COM activation works. No object was activated and no resolution API was called.".into(),target:Some(id)},
                    Ok(false)=>{
                        if source.hive=="HKCU" && source.view=="64"{
                            let app=ProxyBackup{iid:name.clone(),clsid:id.clone(),guard:ProxyGuard{values:vec![],type_lib_values:None}};
                            if let Ok(state)=store.read_proxy(&app){if state.value==original{entry.proxy_state=Some(state);entry.proxy_repairable=true;}}
                        }
                        Assessment{status:EntryStatus::Review,code:"proxy_clsid_missing".into(),explanation:if entry.proxy_repairable{"The proxy class is absent from both hives and both architecture views. This simple current-user mapping can be reviewed for backed-up removal; keys, descriptions, TypeLib metadata, default selections, and files are preserved."}else{"The proxy class is absent from both hives and both architecture views. 32-bit/machine mappings, machine counterparts, complex metadata, and uncertain evidence remain outside repair scope."}.into(),target:Some(id)}
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
            panic!("Proxy reference checks must not probe files")
        }
    }
    #[test]
    fn proxy_inventory_is_read_only_and_keeps_malformed_absent_and_cancelled_evidence_unverified() {
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
            let leaf = root
                .create_subkey(format!(r"{id}\ProxyStubClsid32"))
                .unwrap()
                .0;
            if index < 2 {
                leaf.set_value("", &if index == 0 { &missing } else { "%LIBID%" })
                    .unwrap();
            }
        }
        let source = Source {
            category: Category::ComProxies,
            hive: "HKCU",
            path: INTERFACES_KEY,
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
        scan_proxies(
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
            "proxy_clsid_missing",
            "proxy_mapping_unverified",
            "proxy_mapping_absent",
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
            root.open_subkey(format!(r"{}\ProxyStubClsid32", ids[0]))
                .unwrap()
                .get_value::<String, _>("")
                .unwrap(),
            missing
        );
        let mut cancelled = vec![];
        scan_proxies(
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
        assert_eq!(sources.len(), 47);
        assert_eq!(
            sources
                .iter()
                .filter(|s| s.category == Category::ComProxies)
                .count(),
            4
        );
    }
}
