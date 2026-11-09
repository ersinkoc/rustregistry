use super::*;
use crate::{
    changes::NamedValue,
    leftover_urls::*,
    windows_changes::{AnchorIndex, LeftoverAppState},
};

pub(super) struct UrlInventory<'a, P> {
    pub source: &'a Source,
    pub environment: &'a Environment,
    pub probe: &'a P,
    pub store: &'a WindowsRegistryStore,
    pub anchors: &'a AnchorIndex,
}
impl<P: PathProbe> UrlInventory<'_, P> {
    pub fn append(
        &self,
        name: &str,
        state: &LeftoverAppState,
        entries: &mut Vec<RegistryEntry>,
        scope: &mut ScopeResult,
        remaining: usize,
    ) {
        let values: Vec<NamedValue> = state
            .other
            .iter()
            .filter(|v| is_url_value(&v.name))
            .cloned()
            .collect();
        let directory = state.value.as_ref().and_then(|v| literal_directory(v).ok());
        for value in values.iter().take(remaining) {
            let mut entry = make_entry(
                self.source,
                name,
                name.into(),
                &value.name,
                Err("URL metadata ownership has not been verified.".into()),
                self.environment,
                self.probe,
            );
            entry.value_type = match value.value.kind {
                1 => "REG_SZ",
                2 => "REG_EXPAND_SZ",
                4 => "REG_DWORD",
                _ => "Unsupported",
            }
            .into();
            entry.raw_value = display_value(&value.name, &value.value).unwrap_or_else(|_| {
                value
                    .value
                    .text()
                    .unwrap_or_else(|_| "(unsupported raw data)".into())
            });
            entry.assessment = Assessment { status: EntryStatus::Unknown, code: "leftover_url_unverified".into(), explanation: "URL metadata alone does not establish a removed application. A literal missing installation path, missing executable/uninstaller and unique non-MSI owner are required; an existing executable mapping or alternate activation remains protected.".into(), target: directory.clone() };
            if let (Some(directory), Some(path)) = (&directory, &state.value) {
                if let Some(owners) = self.anchors.get(&directory.to_ascii_lowercase()) {
                    if owners.len() == 1 {
                        if let Ok(snapshot) = &owners[0].1 {
                            if let Ok(anchor) = normalized_anchor(snapshot) {
                                let app = LeftoverBackup {
                                    executable_name: name.into(),
                                    value_name: value.name.clone(),
                                    directory: directory.clone(),
                                    uninstall_key: owners[0].0.clone(),
                                    anchor,
                                    application_values: state
                                        .other
                                        .iter()
                                        .filter(|v| !is_url_value(&v.name))
                                        .cloned()
                                        .collect(),
                                    path_list: None,
                                    supported_type: None,
                                    url_metadata: Some(Box::new(UrlMetadataBackup {
                                        path_name: state.name.clone(),
                                        search_path: path.clone(),
                                        values: values.clone(),
                                    })),
                                };
                                match app.verify_original(&value.value, self.probe) {
                                    Ok(evidence) => {
                                        entry.name = evidence.application_name.clone();
                                        entry.publisher = snapshot.text("Publisher").ok();
                                        entry.version = snapshot.text("DisplayVersion").ok();
                                        entry.assessment = Assessment { status: EntryStatus::Review, code: "application_leftover_candidate".into(), explanation: "A unique non-MSI uninstall registration and exact missing installation path/application/uninstaller corroborate leftover URL metadata. Only the selected SupportedProtocols or UseUrl value is removed; protocol handlers and default selections are not changed. A later scan may expose supported search-path cleanup.".into(), target: Some(evidence.executable.clone()) };
                                        match self.store.read_leftover(&app) {
                                            Ok(Some(current)) if current == value.value => {
                                                entry.leftover_repairable = true;
                                                entry.leftover_state = Some(app);
                                                entry.snapshot = Some(value.value.clone());
                                            }
                                            Ok(_) => entry.assessment.explanation.push_str(" Cleanup unavailable: the URL metadata changed while scanning."),
                                            Err(error) => entry.assessment.explanation.push_str(&format!(" Cleanup unavailable: {error}")),
                                        }
                                        entry.leftover_evidence = Some(evidence);
                                    }
                                    Err(error) => entry.assessment.explanation = error,
                                }
                            }
                        }
                    }
                }
            }
            entries.push(entry);
        }
        if values.len() > remaining {
            scope.status = "limited".into();
        }
    }
}
