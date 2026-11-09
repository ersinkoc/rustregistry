use crate::{
    analyze_target,
    changes::{NamedValue, StoredValue},
    uninstall::{UninstallSnapshot, COMPONENT},
    Category, EntryStatus, Environment, PathProbe, RegistryEntry, TargetKind,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LeftoverBackup {
    pub executable_name: String,
    pub value_name: String,
    pub directory: String,
    pub uninstall_key: String,
    pub anchor: UninstallSnapshot,
    pub application_values: Vec<NamedValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_list: Option<StoredValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_type: Option<Box<crate::leftover_types::SupportedTypeBackup>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeftoverEvidence {
    pub application_name: String,
    pub directory: String,
    pub executable: String,
    pub uninstaller: String,
    pub uninstall_path: String,
    pub application_path: String,
    pub related_ids: Vec<String>,
}

pub fn literal_directory(value: &StoredValue) -> Result<String, String> {
    if value.kind != 1 {
        return Err("Leftover search paths require one literal REG_SZ directory.".into());
    }
    let raw = value.text()?;
    let directory = raw.trim_end_matches('\\').to_string();
    if directory.contains(';') || directory.len() > 240 {
        return Err("Multiple or oversized search directories remain read-only.".into());
    }
    crate::shared_dlls::validate_shared_dll_path(&format!(r"{directory}\probe.dll"))
        .map_err(|_| "A bounded literal local ASCII directory outside Windows is required.")?;
    Ok(directory)
}

/// Inventory literal directories without interpreting retained expressions.
pub fn search_directories(value: &StoredValue) -> Result<Vec<String>, String> {
    if value.kind != 1 {
        return Err("Only literal REG_SZ search paths support cleanup.".into());
    }
    let text = value.text()?;
    let parts: Vec<_> = text.split(';').collect();
    if text.len() > 4096
        || parts.len() > 32
        || parts.iter().any(|p| p.trim().is_empty())
        || text.chars().any(|c| c == '"' || c.is_control())
    {
        return Err("Oversized lists and empty search-path segments remain read-only.".into());
    }
    let mut directories = vec![];
    for part in parts {
        let value = StoredValue {
            kind: 1,
            bytes: part
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        if let Ok(directory) = literal_directory(&value) {
            if !directories
                .iter()
                .any(|d: &String| d.eq_ignore_ascii_case(&directory))
            {
                directories.push(directory);
            }
        }
    }
    Ok(directories)
}

pub fn prune_search_path(
    original: &StoredValue,
    directory: &str,
) -> Result<Option<StoredValue>, String> {
    search_directories(original)?;
    let text = original.text()?;
    let parts: Vec<_> = text.split(';').collect();
    if parts.len() < 2 {
        return Err("Path-list cleanup requires at least two segments.".into());
    }
    let mut kept = vec![];
    for part in &parts {
        let value = StoredValue {
            kind: 1,
            bytes: part
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        if !literal_directory(&value).is_ok_and(|d| d.eq_ignore_ascii_case(directory)) {
            kept.push(*part);
        }
    }
    if kept.len() == parts.len() {
        return Err("The owned directory is absent from the original path list.".into());
    }
    if kept.is_empty() {
        return Ok(None);
    }
    let mut bytes: Vec<_> = kept
        .join(";")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    // Preserve the original terminator convention as well as retained segment text.
    bytes.extend_from_slice(&original.bytes[text.encode_utf16().count() * 2..]);
    Ok(Some(StoredValue { kind: 1, bytes }))
}
pub fn normalized_anchor(snapshot: &UninstallSnapshot) -> Result<UninstallSnapshot, String> {
    snapshot.validate()?;
    if let Some(v) = snapshot.get(COMPONENT) {
        if v.kind != 4 || ![vec![0, 0, 0, 0], vec![1, 0, 0, 0]].contains(&v.bytes) {
            return Err("Unsupported uninstall visibility metadata.".into());
        }
    }
    let mut anchor = snapshot.clone();
    anchor
        .values
        .retain(|v| !v.name.eq_ignore_ascii_case(COMPONENT));
    anchor.validate_original()?;
    for field in [
        "DisplayName",
        "InstallLocation",
        "UninstallString",
        "QuietUninstallString",
    ] {
        if let Some(v) = anchor.get(field) {
            if v.kind != 1 {
                return Err(
                    "Expanded uninstall evidence remains outside leftover cleanup scope.".into(),
                );
            }
        }
    }
    Ok(anchor)
}
fn missing(path: &str, kind: TargetKind, probe: &impl PathProbe) -> Result<(), String> {
    let a = analyze_target(path, kind, &Environment::current(), probe);
    if a.status != EntryStatus::Review || a.code != "target_missing" {
        return Err("The correlated installation directory or executable is not confirmed missing. Leftover cleanup or restore is blocked.".into());
    }
    Ok(())
}
pub fn correlate(
    executable_name: &str,
    value: &StoredValue,
    uninstall_key: &str,
    snapshot: &UninstallSnapshot,
    probe: &impl PathProbe,
) -> Result<LeftoverEvidence, String> {
    crate::changes::validate_app_path_name(executable_name)?;
    if !executable_name.is_ascii() {
        return Err(
            "Only unambiguous ASCII executable identifiers support leftover correlation.".into(),
        );
    }
    crate::uninstall::validate_uninstall_name(uninstall_key)?;
    if uuid::Uuid::parse_str(uninstall_key.trim_matches(['{', '}'])).is_ok() {
        return Err("Product-code registrations remain protected.".into());
    }
    let directory = literal_directory(value)?;
    let anchor = normalized_anchor(snapshot)?;
    if !literal_directory(
        anchor
            .get("InstallLocation")
            .ok_or("Missing installation directory evidence.")?,
    )?
    .eq_ignore_ascii_case(&directory)
    {
        return Err("Installation directories do not match exactly. Names alone do not establish application ownership.".into());
    }
    missing(&directory, TargetKind::Directory, probe)?;
    let executable = format!(r"{directory}\{executable_name}");
    missing(&executable, TargetKind::File, probe)?;
    let mut uninstaller = None;
    for field in ["UninstallString", "QuietUninstallString"] {
        let Some(value) = anchor.get(field) else {
            continue;
        };
        let a = analyze_target(
            &value.text()?,
            TargetKind::Command,
            &Environment::current(),
            probe,
        );
        let target = a
            .target
            .ok_or("The uninstaller has no unambiguous local executable target.")?;
        if !target.to_ascii_lowercase().ends_with(".exe") {
            return Err("Only direct executable uninstallers support leftover correlation.".into());
        }
        crate::shared_dlls::validate_shared_dll_path(&format!(
            "{}.dll",
            &target[..target.len() - 4]
        ))
        .map_err(|_| "The uninstaller path is outside supported literal local scope.")?;
        if a.status != EntryStatus::Review
            || a.code != "target_missing"
            || !target
                .to_ascii_lowercase()
                .starts_with(&format!("{}\\", directory.to_ascii_lowercase()))
        {
            return Err("The missing uninstaller must belong to the same exact missing installation directory.".into());
        }
        if field == "UninstallString" {
            uninstaller = Some(target)
        }
    }
    Ok(LeftoverEvidence {
        application_name: anchor.text("DisplayName")?,
        directory,
        executable,
        uninstaller: uninstaller.ok_or("Uninstall evidence is missing.")?,
        uninstall_path: format!(r"HKCU\{}\{uninstall_key}", crate::uninstall::UNINSTALL_KEY),
        application_path: format!(r"{}\{executable_name}", crate::changes::APP_PATHS_KEY),
        related_ids: vec![],
    })
}
impl LeftoverBackup {
    pub fn schema(&self) -> u32 {
        if self.supported_type.is_some() {
            25
        } else if self.path_list.is_some() {
            24
        } else {
            23
        }
    }
    pub fn key_path(&self) -> String {
        if self.supported_type.is_some() {
            return format!(
                r"{}\{}\SupportedTypes",
                crate::applications::APPLICATIONS_KEY,
                self.executable_name
            );
        }
        format!(
            r"{}\{}",
            crate::changes::APP_PATHS_KEY,
            self.executable_name
        )
    }
    pub fn validate(&self) -> Result<(), String> {
        crate::changes::validate_app_path_name(&self.executable_name)?;
        crate::uninstall::validate_uninstall_name(&self.uninstall_key)?;
        if (self.supported_type.is_none() && !self.value_name.eq_ignore_ascii_case("Path"))
            || !self.executable_name.is_ascii()
            || uuid::Uuid::parse_str(self.uninstall_key.trim_matches(['{', '}'])).is_ok()
        {
            return Err("Unsupported leftover backup namespace or identifier.".into());
        }
        if let Some(hint) = &self.supported_type {
            crate::applications::validate_application_name(&self.executable_name)?;
            crate::leftover_types::validate_extension(&self.value_name)?;
            hint.validate()?;
            if self.path_list.is_some() {
                return Err("Search-path and file-type backup namespaces cannot be mixed.".into());
            }
        }
        let value = StoredValue {
            kind: 1,
            bytes: self
                .directory
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        if literal_directory(&value)? != self.directory {
            return Err("Leftover directory evidence is not canonical.".into());
        }
        if let Some(original) = &self.path_list {
            prune_search_path(original, &self.directory)?;
        }
        if normalized_anchor(&self.anchor)? != self.anchor {
            return Err("Leftover anchor contains mutable visibility metadata.".into());
        }
        if self.application_values.len() > 32
            || self
                .application_values
                .iter()
                .map(|v| v.value.bytes.len() + v.name.len())
                .sum::<usize>()
                > 16384
        {
            return Err("Application metadata exceeds leftover verification limits.".into());
        }
        let mut names = std::collections::HashSet::new();
        for v in &self.application_values {
            if (v.name.is_empty() && self.supported_type.is_none())
                || v.name.len() > 256
                || v.name.contains('\0')
                || v.value.kind > 11
                || v.value.kind == 6
                || !names.insert(v.name.to_lowercase())
                || (self.supported_type.is_some() && v.name.eq_ignore_ascii_case("IsHostApp"))
                || ["Path", "DropTarget", "UseUrl", "SupportedProtocols"]
                    .iter()
                    .any(|n| v.name.eq_ignore_ascii_case(n))
            {
                return Err("An executable mapping, alternate activation or ambiguous metadata remains. Review the executable registration first; leftover search-path cleanup is unavailable.".into());
            }
        }
        Ok(())
    }
    pub fn verify_original(
        &self,
        original: &StoredValue,
        probe: &impl PathProbe,
    ) -> Result<LeftoverEvidence, String> {
        self.validate()?;
        if let Some(hint) = &self.supported_type {
            crate::leftover_types::validate_hint(original)?;
            return hint.evidence(self, probe);
        }
        let evidence_value = if let Some(list) = &self.path_list {
            if list != original {
                return Err(
                    "The original search-path list does not match its backup evidence.".into(),
                );
            }
            prune_search_path(original, &self.directory)?;
            StoredValue {
                kind: 1,
                bytes: self
                    .directory
                    .encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }
        } else {
            original.clone()
        };
        if !literal_directory(&evidence_value)?.eq_ignore_ascii_case(&self.directory) {
            return Err("Leftover directory does not match its original value.".into());
        }
        correlate(
            &self.executable_name,
            &evidence_value,
            &self.uninstall_key,
            &self.anchor,
            probe,
        )
    }
    pub fn cleared_value(&self) -> Result<Option<StoredValue>, String> {
        self.path_list
            .as_ref()
            .map_or(Ok(None), |v| prune_search_path(v, &self.directory))
    }
}

pub fn link_related(entries: &mut [RegistryEntry]) {
    use std::collections::HashMap;
    let mut paths: HashMap<String, Vec<String>> = HashMap::new();
    let mut uninstall: HashMap<String, Vec<String>> = HashMap::new();
    let mut cache: HashMap<String, Vec<String>> = HashMap::new();
    let mut hints: HashMap<String, Vec<String>> = HashMap::new();
    for e in entries
        .iter()
        .filter(|e| e.hive == "HKCU" && crate::changes::is_repair_candidate(e))
    {
        match e.category {
            Category::ApplicationLeftovers
                if e.leftover_state
                    .as_ref()
                    .is_some_and(|app| app.supported_type.is_some()) =>
            {
                if let Some(evidence) = &e.leftover_evidence {
                    hints
                        .entry(evidence.application_path.to_ascii_lowercase())
                        .or_default()
                        .push(e.id.clone());
                }
            }
            Category::AppPaths => paths
                .entry(e.key_path.to_ascii_lowercase())
                .or_default()
                .push(e.id.clone()),
            Category::Uninstall => uninstall
                .entry(format!(r"HKCU\{}", e.key_path).to_ascii_lowercase())
                .or_default()
                .push(e.id.clone()),
            Category::MuiCache => {
                if let Some(p) = &e.assessment.target {
                    cache
                        .entry(p.to_ascii_lowercase())
                        .or_default()
                        .push(e.id.clone());
                }
            }
            _ => {}
        }
    }
    for entry in entries {
        if let Some(e) = &mut entry.leftover_evidence {
            let mut ids = vec![];
            for values in [
                paths.get(&e.application_path.to_ascii_lowercase()),
                hints.get(&e.application_path.to_ascii_lowercase()),
                uninstall.get(&e.uninstall_path.to_ascii_lowercase()),
                cache.get(&e.executable.to_ascii_lowercase()),
                cache.get(&e.uninstaller.to_ascii_lowercase()),
            ]
            .into_iter()
            .flatten()
            {
                ids.extend(values.iter().cloned())
            }
            ids.sort();
            ids.dedup();
            e.related_ids = ids;
        }
    }
}
