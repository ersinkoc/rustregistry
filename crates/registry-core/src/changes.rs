use crate::application_icons::{validate_icon_path, verify_missing_icon, IconBackup, IconState};
use crate::applications::{
    validate_application_name, verify_missing_command, ApplicationBackup, ApplicationSnapshot,
    APPLICATIONS_KEY, NO_OPEN_WITH, OPEN_COMMAND,
};
use crate::com_conversions::{
    mapping_target as mapping_conversion_target, ConversionBackup, ConversionState,
};
use crate::com_proxies::{ProxyBackup, ProxyState};
use crate::com_redirects::{mapping_target, RedirectionBackup, RedirectionState};
use crate::interfaces::{mapping_library, InterfaceBackup, InterfaceState, INTERFACES_KEY};
use crate::prog_ids::{mapping_clsid, ProgIdBackup, ProgIdState, PROG_IDS_KEY};
use crate::registered_apps::{
    capabilities_path, validate_registration_name, RegisteredApplicationBackup, REGISTERED_APPS_KEY,
};
use crate::services::{
    validate_service_name, verify_missing_service, ServiceBackup, ServiceSnapshot, ServiceState,
    SERVICES_KEY,
};
use crate::shared_dlls::{
    validate_shared_dll_path, validate_zero_count, verify_missing_shared_dll, SharedDllBackup,
    SHARED_DLLS_KEY,
};
use crate::shell_menus::{
    verify_missing_menu_command, MenuBackup, MenuLocation, MenuSnapshot, PROGRAMMATIC_ONLY,
};
use crate::type_libraries::{
    validate_library_path, verify_missing_library, TypeLibBackup, TypeLibState, TYPE_LIB_KEY,
};
#[path = "batch.rs"]
mod batch;
use crate::associations::{
    validate_extension, validate_suggestion, AssociationBackup, AssociationState, CLASSES_KEY,
    OPEN_WITH,
};
use crate::com::{
    validate_clsid, validate_server, verify_missing_mapping, ComBackup, ComState, CLSID_KEY,
    INPROC_SERVER,
};
use crate::uninstall::{
    validate_uninstall_name, verify_orphan, UninstallBackup, UninstallSnapshot, COMPONENT,
    UNINSTALL_KEY,
};
use crate::{
    analyze_target, Category, EntryStatus, Environment, PathProbe, RegistryEntry, TargetKind,
};
pub use batch::{
    is_quick_clean_candidate, is_repair_candidate, CleanPlan, CleanResult, MAX_CLEAN_ENTRIES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const STARTUP_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const APP_PATHS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
const MAX_BYTES: usize = 32_768;
const MAX_BACKUP_BYTES: u64 = 262_144;
const PLAN_LIFETIME: u64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredValue {
    pub kind: u32,
    pub bytes: Vec<u8>,
}

impl StoredValue {
    pub fn text(&self) -> Result<String, String> {
        if ![1, 2].contains(&self.kind)
            || self.bytes.len() > MAX_BYTES
            || !self.bytes.len().is_multiple_of(2)
        {
            return Err("Only bounded REG_SZ and REG_EXPAND_SZ values can be changed.".into());
        }
        let mut units: Vec<u16> = self
            .bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        let text = String::from_utf16(&units)
            .map_err(|_| "The original value contains invalid UTF-16.".to_string())?;
        if text.trim().is_empty() || text.contains('\0') {
            return Err("An empty or ambiguous value cannot be changed.".into());
        }
        Ok(text)
    }
}

pub fn validate_value_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.contains('\0') || name.encode_utf16().count() > 16_383 {
        Err("A nonempty, valid startup value name is required.".into())
    } else {
        Ok(())
    }
}

pub fn validate_app_path_name(name: &str) -> Result<(), String> {
    if name.len() <= 4
        || name.encode_utf16().count() > 255
        || !name.to_ascii_lowercase().ends_with(".exe")
        || name
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
        || name.starts_with('.')
        || name.trim() != name
    {
        return Err(
            "Only a single executable name under the current user's App Paths key is supported."
                .into(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamedValue {
    pub name: String,
    pub value: StoredValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppPathGuard {
    pub values: Vec<NamedValue>,
}

impl AppPathGuard {
    pub fn validate(&self) -> Result<(), String> {
        if self.values.len() > 32
            || self
                .values
                .iter()
                .map(|v| v.value.bytes.len())
                .sum::<usize>()
                > 16_384
        {
            return Err("App Paths metadata exceeds the supported backup limits.".into());
        }
        let mut names = std::collections::HashSet::new();
        for item in &self.values {
            if item.name.is_empty()
                || item.name.encode_utf16().count() > 256
                || item.name.contains('\0')
                || item.value.kind > 11
                || item.value.kind == 6
                || !names.insert(item.name.to_lowercase())
            {
                return Err("App Paths metadata is unsupported or ambiguous.".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPathState {
    pub value: Option<StoredValue>,
    pub guard: AppPathGuard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppPathBackup {
    executable: String,
    guard: AppPathGuard,
}

pub trait RegistryStore {
    fn read_maintenance_batch(
        &self,
        apps: &[crate::maintenance::MaintenanceBackup],
    ) -> Vec<Result<crate::maintenance::MaintenanceSnapshot, String>> {
        apps.iter().map(|app| self.read_maintenance(app)).collect()
    }
    fn read_maintenance(
        &self,
        _app: &crate::maintenance::MaintenanceBackup,
    ) -> Result<crate::maintenance::MaintenanceSnapshot, String> {
        Err("Maintenance is unavailable.".into())
    }
    fn check_maintenance_write_access(
        &self,
        _app: &crate::maintenance::MaintenanceBackup,
    ) -> Result<(), String> {
        Err("Maintenance is unavailable.".into())
    }
    fn compare_exchange_maintenance(
        &self,
        _app: &crate::maintenance::MaintenanceBackup,
        _expected: &crate::maintenance::MaintenanceSnapshot,
        _replacement: &crate::maintenance::MaintenanceSnapshot,
    ) -> Result<(), String> {
        Err("Maintenance is unavailable.".into())
    }

    fn read_conversion(&self, _app: &ConversionBackup) -> Result<ConversionState, String> {
        Err("COM conversion recovery is unavailable.".into())
    }
    fn check_conversion_write_access(&self, _app: &ConversionBackup) -> Result<(), String> {
        Err("COM conversion recovery is unavailable.".into())
    }
    fn compare_exchange_conversion(
        &self,
        _app: &ConversionBackup,
        _expected: &ConversionState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("COM conversion recovery is unavailable.".into())
    }

    fn read_redirection(&self, _app: &RedirectionBackup) -> Result<RedirectionState, String> {
        Err("COM redirection recovery is unavailable.".into())
    }
    fn check_redirection_write_access(&self, _app: &RedirectionBackup) -> Result<(), String> {
        Err("COM redirection recovery is unavailable.".into())
    }
    fn compare_exchange_redirection(
        &self,
        _app: &RedirectionBackup,
        _expected: &RedirectionState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("COM redirection recovery is unavailable.".into())
    }

    fn read_menu(&self, _app: &MenuBackup) -> Result<MenuSnapshot, String> {
        Err("Context-menu recovery is unavailable.".into())
    }
    fn check_menu_write_access(&self, _app: &MenuBackup) -> Result<(), String> {
        Err("Context-menu recovery is unavailable.".into())
    }
    fn set_menu_hidden(&self, _app: &MenuBackup, _hidden: bool) -> Result<(), String> {
        Err("Context-menu recovery is unavailable.".into())
    }

    fn read_proxy(&self, _app: &ProxyBackup) -> Result<ProxyState, String> {
        Err("COM proxy recovery is unavailable.".into())
    }
    fn check_proxy_write_access(&self, _app: &ProxyBackup) -> Result<(), String> {
        Err("COM proxy recovery is unavailable.".into())
    }
    fn compare_exchange_proxy(
        &self,
        _app: &ProxyBackup,
        _expected: &ProxyState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("COM proxy recovery is unavailable.".into())
    }
    fn read_icon(&self, _app: &IconBackup) -> Result<IconState, String> {
        Err("application icon recovery is unavailable.".into())
    }
    fn check_icon_write_access(&self, _app: &IconBackup) -> Result<(), String> {
        Err("application icon recovery is unavailable.".into())
    }
    fn compare_exchange_icon(
        &self,
        _app: &IconBackup,
        _expected: &IconState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("application icon recovery is unavailable.".into())
    }
    fn read_interface(&self, _app: &InterfaceBackup) -> Result<InterfaceState, String> {
        Err("Interface TypeLib recovery is unavailable.".into())
    }
    fn check_interface_write_access(&self, _app: &InterfaceBackup) -> Result<(), String> {
        Err("Interface TypeLib recovery is unavailable.".into())
    }
    fn compare_exchange_interface(
        &self,
        _app: &InterfaceBackup,
        _expected: &InterfaceState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("Interface TypeLib recovery is unavailable.".into())
    }
    fn read_prog_id(&self, _app: &ProgIdBackup) -> Result<ProgIdState, String> {
        Err("ProgID recovery is unavailable.".into())
    }
    fn check_prog_id_write_access(&self, _app: &ProgIdBackup) -> Result<(), String> {
        Err("ProgID recovery is unavailable.".into())
    }
    fn compare_exchange_prog_id(
        &self,
        _app: &ProgIdBackup,
        _expected: &ProgIdState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("ProgID recovery is unavailable.".into())
    }

    fn read_type_library(&self, _app: &TypeLibBackup) -> Result<TypeLibState, String> {
        Err("Type library recovery is unavailable.".into())
    }
    fn check_type_library_write_access(&self, _app: &TypeLibBackup) -> Result<(), String> {
        Err("Type library recovery is unavailable.".into())
    }
    fn compare_exchange_type_library(
        &self,
        _app: &TypeLibBackup,
        _expected: &TypeLibState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("Type library recovery is unavailable.".into())
    }

    fn read_registered_app(
        &self,
        _name: &str,
        _original: &StoredValue,
    ) -> Result<Option<StoredValue>, String> {
        Err("Application registration recovery is unavailable.".into())
    }
    fn check_registered_app_write_access(&self) -> Result<(), String> {
        Err("Application registration recovery is unavailable.".into())
    }
    fn compare_exchange_registered_app(
        &self,
        _name: &str,
        _original: &StoredValue,
        _expected: Option<&StoredValue>,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("Application registration recovery is unavailable.".into())
    }

    fn read_shared_dll(&self, _path: &str) -> Result<Option<StoredValue>, String> {
        Err("Shared DLL recovery is unavailable in this registry store.".into())
    }
    fn check_shared_dll_write_access(&self) -> Result<(), String> {
        Err("Shared DLL recovery is unavailable in this registry store.".into())
    }
    fn compare_exchange_shared_dll(
        &self,
        _path: &str,
        _expected: Option<&StoredValue>,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("Shared DLL recovery is unavailable in this registry store.".into())
    }
    fn read_application(&self, _name: &str) -> Result<ApplicationSnapshot, String> {
        Err("Application recovery is unavailable in this registry store.".into())
    }
    fn set_application_hidden(
        &self,
        _name: &str,
        _original: &ApplicationSnapshot,
        _hide: bool,
    ) -> Result<(), String> {
        Err("Application recovery is unavailable in this registry store.".into())
    }
    fn read_service(&self, _name: &str) -> Result<ServiceState, String> {
        Err("Service recovery is unavailable in this registry store.".into())
    }
    fn set_service_disabled(
        &self,
        _name: &str,
        _original: &ServiceSnapshot,
        _disabled: bool,
    ) -> Result<(), String> {
        Err("Service recovery is unavailable in this registry store.".into())
    }

    fn read_com(&self, _clsid: &str, _server: &str) -> Result<ComState, String> {
        Err("COM recovery is unavailable in this registry store.".into())
    }
    fn compare_exchange_com(
        &self,
        _clsid: &str,
        _server: &str,
        _expected: &ComState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("COM recovery is unavailable in this registry store.".into())
    }

    fn read_association(
        &self,
        _extension: &str,
        _progid: &str,
    ) -> Result<AssociationState, String> {
        Err("File association recovery is unavailable in this registry store.".into())
    }
    fn compare_exchange_association(
        &self,
        _extension: &str,
        _progid: &str,
        _expected: &AssociationState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("File association recovery is unavailable in this registry store.".into())
    }

    fn read_uninstall(&self, _key_name: &str) -> Result<UninstallSnapshot, String> {
        Err("Uninstall recovery is unavailable in this registry store.".into())
    }
    fn set_uninstall_hidden(
        &self,
        _key_name: &str,
        _original: &UninstallSnapshot,
        _hide: bool,
    ) -> Result<(), String> {
        Err("Uninstall recovery is unavailable in this registry store.".into())
    }
    fn read(&self, name: &str) -> Result<Option<StoredValue>, String>;
    /// Atomically enforce the expected value, mutate it, and commit, or change nothing.
    fn compare_exchange(
        &self,
        name: &str,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String>;
    fn read_app_path(&self, _executable: &str) -> Result<AppPathState, String> {
        Err("App Paths changes are unavailable in this registry store.".into())
    }
    fn compare_exchange_app_path(
        &self,
        _executable: &str,
        _expected: &AppPathState,
        _replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        Err("App Paths changes are unavailable in this registry store.".into())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePlan {
    pub token: String,
    pub action: String,
    pub name: String,
    pub value_name: String,
    pub registry_path: String,
    pub registry_view: String,
    pub original_value: String,
    pub value_type: String,
    pub expires_at: u64,
    pub scope: String,
    pub preserved_values: usize,
    pub uninstall_command: Option<String>,
    pub component_was_present: bool,
    pub service_executable: Option<String>,
    pub application_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupRecord {
    schema_version: u32,
    id: Uuid,
    name: String,
    value_name: String,
    created_at: u64,
    original: StoredValue,
    integrity_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    app_path: Option<AppPathBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uninstall: Option<UninstallBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    association: Option<AssociationBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    com: Option<ComBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service: Option<ServiceBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application: Option<ApplicationBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shared_dll: Option<SharedDllBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registered_app: Option<RegisteredApplicationBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    type_library: Option<TypeLibBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prog_id: Option<ProgIdBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interface: Option<InterfaceBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy: Option<ProxyBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    icon: Option<IconBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    menu: Option<MenuBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirection: Option<RedirectionBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    conversion: Option<ConversionBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    maintenance: Option<crate::maintenance::MaintenanceBackup>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub id: String,
    pub name: String,
    pub value_name: String,
    pub created_at: u64,
    pub state: String,
    pub note: String,
    pub scope: String,
    pub registry_path: String,
    pub registry_view: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInventory {
    pub storage_path: String,
    pub backups: Vec<BackupSummary>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeResult {
    pub backup_id: String,
    pub action: String,
    pub message: String,
}

enum PendingAction {
    Quarantine(BackupRecord),
    Restore(BackupRecord),
}
struct Pending {
    plan: ChangePlan,
    action: PendingAction,
}

pub struct ChangeManager<S: RegistryStore, P: PathProbe> {
    store: S,
    directory: PathBuf,
    probe: P,
    pending: Option<Pending>,
    batch_pending: Option<batch::PendingBatch>,
}

fn now() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64)
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

impl<S: RegistryStore, P: PathProbe> ChangeManager<S, P> {
    pub fn new(store: S, directory: PathBuf, probe: P) -> Self {
        Self {
            store,
            directory,
            probe,
            pending: None,
            batch_pending: None,
        }
    }

    fn ensure_directory(&self, create: bool) -> Result<(), String> {
        if create {
            fs::create_dir_all(&self.directory)
                .map_err(|e| format!("Cannot create the backup directory: {e}"))?;
        }
        match fs::symlink_metadata(&self.directory) {
            Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => Ok(()),
            Ok(_) => Err("The backup location must be a regular local directory.".into()),
            Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("Cannot access the backup directory: {error}")),
        }
    }

    fn validate_record(record: &BackupRecord) -> Result<(), String> {
        if record.name.len() > 65_536 {
            return Err("Unsupported backup format.".into());
        }
        if let Some(app) = &record.maintenance {
            if record.schema_version != 20
                || [
                    record.app_path.is_some(),
                    record.uninstall.is_some(),
                    record.association.is_some(),
                    record.com.is_some(),
                    record.service.is_some(),
                    record.application.is_some(),
                    record.shared_dll.is_some(),
                    record.registered_app.is_some(),
                    record.type_library.is_some(),
                    record.prog_id.is_some(),
                    record.interface.is_some(),
                    record.proxy.is_some(),
                    record.icon.is_some(),
                    record.menu.is_some(),
                    record.redirection.is_some(),
                    record.conversion.is_some(),
                ]
                .into_iter()
                .any(|v| v)
            {
                return Err("Unsupported maintenance backup namespace or format.".into());
            }
            app.validate()?;
            if record.value_name != app.item || record.original != app.sentinel() {
                return Err("Maintenance backup evidence does not match.".into());
            }
            if record.integrity_sha256 != Self::checksum(record)? {
                return Err(
                    "The backup integrity checksum does not match. Restore is blocked.".into(),
                );
            }
            return Ok(());
        }
        match (
            &record.app_path,
            &record.uninstall,
            &record.association,
            &record.com,
            &record.service,
            &record.application,
            &record.shared_dll,
            &record.registered_app,
            &record.type_library,
            &record.prog_id,
            &record.interface,
            &record.proxy,
            &record.icon,
            &record.menu,
            &record.redirection,
            &record.conversion,
            record.schema_version,
        ) {
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                1,
            ) => validate_value_name(&record.value_name)?,
            (
                Some(app),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                2,
            ) if record.value_name.is_empty() => {
                validate_app_path_name(&app.executable)?;
                app.guard.validate()?;
            }
            (
                None,
                Some(uninstall),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                3,
            ) if record.value_name == COMPONENT => {
                validate_uninstall_name(&uninstall.key_name)?;
                uninstall.snapshot.validate_original()?;
                if uninstall.snapshot.get("InstallLocation") != Some(&record.original) {
                    return Err(
                        "Uninstall backup evidence does not match its original path.".into(),
                    );
                }
            }
            (
                None,
                None,
                Some(association),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                4,
            ) => {
                validate_extension(&association.extension)?;
                association.guard.validate(&record.value_name)?;
                validate_suggestion(&record.original)?;
            }
            (
                None,
                None,
                None,
                Some(com),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                5 | 7,
            ) if record.value_name.is_empty() => {
                if (record.schema_version == 5) != (com.server == INPROC_SERVER) {
                    return Err("COM backup version and server scope do not match.".into());
                }
                com.validate()?;
            }
            (
                None,
                None,
                None,
                None,
                Some(service),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                6,
            ) if record.value_name == "Start" => {
                validate_service_name(&service.service_name)?;
                service.snapshot.validate_original()?;
                if service.snapshot.get("Start") != Some(&record.original) {
                    return Err("Service backup startup evidence does not match.".into());
                }
            }
            (
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                8,
            ) if record.value_name == NO_OPEN_WITH => {
                validate_application_name(&app.executable)?;
                app.snapshot.validate_original()?;
                if app.snapshot.command()? != &record.original {
                    return Err("Application backup command evidence does not match.".into());
                }
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                Some(shared),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                9,
            ) if record.value_name == shared.path && shared.view == "64" => {
                validate_shared_dll_path(&shared.path)?;
                validate_zero_count(&record.original)?;
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                10,
            ) => {
                validate_registration_name(&record.value_name)?;
                if capabilities_path(&record.original)? != app.capabilities_path {
                    return Err("Application capabilities backup evidence does not match.".into());
                }
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                11,
            ) if record.value_name.is_empty() => {
                app.validate()?;
                validate_library_path(&record.original.text()?)?;
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                None,
                None,
                None,
                None,
                None,
                12,
            ) if record.value_name.is_empty() => {
                app.validate()?;
                if mapping_clsid(&record.original)? != app.clsid {
                    return Err("ProgID backup CLSID evidence does not match.".into());
                }
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                None,
                None,
                None,
                None,
                13,
            ) if record.value_name.is_empty() => {
                app.validate()?;
                if mapping_library(&record.original)? != app.library_id {
                    return Err("Interface backup library evidence does not match.".into());
                }
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                None,
                None,
                None,
                14,
            ) if record.value_name.is_empty() => {
                app.validate()?;
                if mapping_clsid(&record.original)? != app.clsid {
                    return Err("Proxy backup CLSID evidence does not match.".into());
                }
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                None,
                None,
                15,
            ) if record.value_name.is_empty() => {
                app.validate()?;
                validate_icon_path(&record.original.text()?)?;
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                None,
                16 | 18,
            ) if record.value_name == PROGRAMMATIC_ONLY => {
                app.validate_schema(record.schema_version)?;
                if app.snapshot.command()? != &record.original {
                    return Err("Menu command backup evidence does not match.".into());
                }
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                None,
                17,
            ) if record.value_name.is_empty() => {
                app.validate()?;
                if mapping_target(&record.original)? != app.target {
                    return Err("TreatAs target backup evidence does not match.".into());
                }
            }
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(app),
                19,
            ) if record.value_name.is_empty() => {
                app.validate()?;
                if mapping_conversion_target(&record.original)? != app.target {
                    return Err("AutoConvertTo target backup evidence does not match.".into());
                }
            }
            _ => return Err("Unsupported backup format or registry scope.".into()),
        }
        if record.association.is_none() && record.service.is_none() && record.shared_dll.is_none() {
            record.original.text()?;
        }
        if record.integrity_sha256 != Self::checksum(record)? {
            return Err("The backup integrity checksum does not match. Restore is blocked.".into());
        }
        Ok(())
    }

    fn checksum(record: &BackupRecord) -> Result<String, String> {
        let bytes = serde_json::to_vec(&(
            record.schema_version,
            record.id,
            &record.name,
            &record.value_name,
            record.created_at,
            &record.original,
        ))
        .map_err(|e| e.to_string())?;
        let bytes = if record.schema_version == 20 {
            serde_json::to_vec(&(bytes, &record.maintenance)).map_err(|e| e.to_string())?
        } else if record.schema_version == 2 {
            serde_json::to_vec(&(bytes, &record.app_path)).map_err(|e| e.to_string())?
        } else if record.schema_version == 3 {
            serde_json::to_vec(&(bytes, &record.uninstall)).map_err(|e| e.to_string())?
        } else if record.schema_version == 4 {
            serde_json::to_vec(&(bytes, &record.association)).map_err(|e| e.to_string())?
        } else if matches!(record.schema_version, 5 | 7) {
            serde_json::to_vec(&(bytes, &record.com)).map_err(|e| e.to_string())?
        } else if record.schema_version == 19 {
            serde_json::to_vec(&(bytes, &record.conversion)).map_err(|e| e.to_string())?
        } else if record.schema_version == 17 {
            serde_json::to_vec(&(bytes, &record.redirection)).map_err(|e| e.to_string())?
        } else if matches!(record.schema_version, 16 | 18) {
            serde_json::to_vec(&(bytes, &record.menu)).map_err(|e| e.to_string())?
        } else if record.schema_version == 15 {
            serde_json::to_vec(&(bytes, &record.icon)).map_err(|e| e.to_string())?
        } else if record.schema_version == 14 {
            serde_json::to_vec(&(bytes, &record.proxy)).map_err(|e| e.to_string())?
        } else if record.schema_version == 13 {
            serde_json::to_vec(&(bytes, &record.interface)).map_err(|e| e.to_string())?
        } else if record.schema_version == 12 {
            serde_json::to_vec(&(bytes, &record.prog_id)).map_err(|e| e.to_string())?
        } else if record.schema_version == 11 {
            serde_json::to_vec(&(bytes, &record.type_library)).map_err(|e| e.to_string())?
        } else if record.schema_version == 10 {
            serde_json::to_vec(&(bytes, &record.registered_app)).map_err(|e| e.to_string())?
        } else if record.schema_version == 9 {
            serde_json::to_vec(&(bytes, &record.shared_dll)).map_err(|e| e.to_string())?
        } else if record.schema_version == 8 {
            serde_json::to_vec(&(bytes, &record.application)).map_err(|e| e.to_string())?
        } else if record.schema_version == 6 {
            serde_json::to_vec(&(bytes, &record.service)).map_err(|e| e.to_string())?
        } else {
            bytes
        };
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    fn load(&self, id: &str) -> Result<BackupRecord, String> {
        let id = Uuid::parse_str(id).map_err(|_| "Invalid backup identifier.".to_string())?;
        self.ensure_directory(false)?;
        let path = self.directory.join(format!("{id}.json"));
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000);
        }
        let file = options
            .open(path)
            .map_err(|e| format!("Cannot open this backup: {e}"))?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_BACKUP_BYTES {
            return Err("The backup is not a supported regular file.".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BACKUP_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_BACKUP_BYTES {
            return Err("The backup exceeds the size limit.".into());
        }
        let record: BackupRecord = serde_json::from_slice(&bytes)
            .map_err(|_| "This backup is corrupted or has an unsupported format.".to_string())?;
        if record.id != id {
            return Err("The backup identifier does not match its file.".into());
        }
        Self::validate_record(&record)?;
        Ok(record)
    }

    fn save(&self, record: &BackupRecord) -> Result<(), String> {
        self.ensure_directory(true)?;
        Self::validate_record(record)?;
        let path = self.directory.join(format!("{}.json", record.id));
        let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_BACKUP_BYTES {
            return Err("The backup exceeds the size limit.".into());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                format!("Cannot create a new backup. No registry value was changed: {e}")
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| {
                format!("Cannot flush the backup to disk. No registry value was changed: {e}")
            })?;
        drop(file);
        let verified = self.load(&record.id.to_string())?;
        if verified.original != record.original || verified.value_name != record.value_name {
            return Err("Backup verification failed. No registry value was changed.".into());
        }
        Ok(())
    }

    fn verify_missing(&self, value: &StoredValue, app_path: bool) -> Result<(), String> {
        let check = analyze_target(
            &value.text()?,
            if app_path {
                TargetKind::File
            } else {
                TargetKind::Command
            },
            &Environment::current(),
            &self.probe,
        );
        if check.status != EntryStatus::Review
            || check.code != "target_missing"
            || (app_path
                && !check
                    .target
                    .as_deref()
                    .is_some_and(|target| target.to_ascii_lowercase().ends_with(".exe")))
        {
            return Err("The target is no longer confirmed missing. Scan again; this entry cannot be changed.".into());
        }
        Ok(())
    }

    pub fn prepare_quarantine(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if matches!(entry.category, Category::MuiCache | Category::UsageHistory) {
            self.cancel();
            return self.prepare_maintenance(entry, None);
        }
        self.pending = None;
        self.batch_pending = None;
        if entry.category == Category::ComConversions {
            return self.prepare_conversion(entry);
        }
        if entry.category == Category::ComRedirections {
            return self.prepare_redirection(entry);
        }
        if entry.category == Category::ShellMenus {
            return self.prepare_menu(entry);
        }
        if entry.category == Category::ApplicationIcons {
            return self.prepare_icon(entry);
        }
        if entry.category == Category::ComProxies {
            return self.prepare_proxy(entry);
        }
        if entry.category == Category::Interfaces {
            return self.prepare_interface(entry);
        }
        if entry.category == Category::ProgIds {
            return self.prepare_prog_id(entry);
        }
        if entry.category == Category::TypeLibraries {
            return self.prepare_type_library(entry);
        }
        if entry.category == Category::RegisteredApplications {
            return self.prepare_registered_app(entry);
        }
        if entry.category == Category::SharedDlls {
            return self.prepare_shared_dll(entry);
        }
        if entry.category == Category::Services {
            return self.prepare_service(entry);
        }
        if entry.hive != "HKCU"
            || (if entry.category == Category::Com {
                entry.view != "64"
            } else {
                entry.view != "shared"
            })
            || entry.assessment.status != EntryStatus::Review
            || (entry.category != Category::FileAssociations
                && entry.assessment.code != "target_missing")
        {
            return Err(
                "Only confirmed missing-target entries in supported current-user locations are eligible."
                    .into(),
            );
        }
        if entry.category == Category::ApplicationCommands {
            return self.prepare_application(entry);
        }
        if entry.category == Category::Com {
            return self.prepare_com(entry);
        }
        if entry.category == Category::FileAssociations {
            return self.prepare_association(entry);
        }
        if entry.category == Category::Uninstall {
            return self.prepare_uninstall(entry);
        }
        let app_path = match entry.category {
            Category::Startup if entry.key_path.eq_ignore_ascii_case(STARTUP_KEY) => {
                validate_value_name(&entry.value_name)?;
                None
            }
            Category::AppPaths if entry.value_name.is_empty() => {
                let prefix = format!("{APP_PATHS_KEY}\\");
                let executable = entry
                    .key_path
                    .get(prefix.len()..)
                    .filter(|_| {
                        entry
                            .key_path
                            .get(..prefix.len())
                            .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
                    })
                    .ok_or("Unsupported App Paths location.")?;
                validate_app_path_name(executable)?;
                let guard = entry
                    .app_path_guard
                    .clone()
                    .ok_or("App Paths metadata could not be fully verified. Run a fresh scan.")?;
                guard.validate()?;
                Some(AppPathBackup {
                    executable: executable.into(),
                    guard,
                })
            }
            _ => {
                return Err("This registry location is outside the protected change scope.".into())
            }
        };
        let original = entry
            .snapshot
            .clone()
            .ok_or("Scan evidence is unavailable. Run a fresh scan.")?;
        let current = if let Some(app) = &app_path {
            let state = self.store.read_app_path(&app.executable)?;
            if state.guard != app.guard {
                return Err("App Paths metadata changed after the scan. Run a fresh scan.".into());
            }
            state.value
        } else {
            self.store.read(&entry.value_name)?
        };
        if original.text()? != entry.raw_value || current.as_ref() != Some(&original) {
            return Err(
                "This entry changed after the scan. Run a fresh scan before reviewing a change."
                    .into(),
            );
        }
        self.verify_missing(&original, app_path.is_some())?;
        let mut record = BackupRecord {
            schema_version: if app_path.is_some() { 2 } else { 1 },
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: entry.value_name.clone(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: None,
            registered_app: None,
            shared_dll: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_maintenance(
        &mut self,
        entry: &RegistryEntry,
        prepared_state: Option<&crate::maintenance::MaintenanceSnapshot>,
    ) -> Result<ChangePlan, String> {
        let app = entry
            .maintenance_state
            .clone()
            .ok_or("Maintenance scan evidence is unavailable.")?;
        app.verify_target(&self.probe)?;
        let history = app.kind.history();
        if entry.hive != "HKCU"
            || entry.view != "shared"
            || entry.key_path != app.kind.path()
            || entry.value_name != app.item
            || !entry.maintenance_repairable
            || entry.raw_value != app.summary()?
            || entry.assessment.status
                != if history {
                    EntryStatus::Found
                } else {
                    EntryStatus::Review
                }
            || entry.assessment.code
                != if history {
                    "optional_history"
                } else {
                    "cache_target_missing"
                }
            || entry.category
                != if history {
                    Category::UsageHistory
                } else {
                    Category::MuiCache
                }
        {
            return Err("Unsupported maintenance location or scan evidence. Scan again.".into());
        }
        let current = match prepared_state {
            Some(state) => state.clone(),
            None => self.store.read_maintenance(&app)?,
        };
        if current != app.snapshot {
            return Err("Maintenance data changed after scanning. Nothing was changed.".into());
        }
        let mut record = BackupRecord {
            schema_version: 20,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: app.item.clone(),
            created_at: now()?,
            original: app.sentinel(),
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            type_library: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: Some(app),
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_conversion(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        let prefix = format!("{}\\", crate::com::CLSID_KEY);
        let tail = entry
            .key_path
            .strip_prefix(&prefix)
            .ok_or("Unsupported COM AutoConvertTo conversion location.")?;
        let parts: Vec<_> = tail.split('\\').collect();
        if entry.hive != "HKCU"
            || entry.view != "64"
            || !entry.value_name.is_empty()
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "conversion_clsid_missing"
            || !entry.conversion_repairable
            || parts.len() != 2
            || !parts[1].eq_ignore_ascii_case("AutoConvertTo")
        {
            return Err(
                "Only guarded current-user missing-local-target AutoConvertTo mappings support recovery."
                    .into(),
            );
        }
        let state = entry
            .conversion_state
            .as_ref()
            .ok_or("COM AutoConvertTo conversion scan evidence is unavailable.")?;
        let original = state
            .value
            .clone()
            .ok_or("The COM AutoConvertTo conversion mapping is absent.")?;
        let app = ConversionBackup {
            owner: parts[0].into(),
            target: mapping_conversion_target(&original)?,
            guard: state.guard.clone(),
        };
        app.validate()?;
        if original.text()? != entry.raw_value || self.store.read_conversion(&app)? != *state {
            return Err(
                "COM AutoConvertTo conversion evidence changed after scanning. Scan again.".into(),
            );
        }
        let mut record = BackupRecord {
            schema_version: 19,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: String::new(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            type_library: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: Some(app),
            maintenance: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }
    fn prepare_redirection(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        let prefix = format!("{}\\", crate::com::CLSID_KEY);
        let tail = entry
            .key_path
            .strip_prefix(&prefix)
            .ok_or("Unsupported COM TreatAs redirection location.")?;
        let parts: Vec<_> = tail.split('\\').collect();
        if entry.hive != "HKCU"
            || entry.view != "64"
            || !entry.value_name.is_empty()
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "redirection_clsid_missing"
            || !entry.redirection_repairable
            || parts.len() != 2
            || !parts[1].eq_ignore_ascii_case("TreatAs")
        {
            return Err(
                "Only guarded current-user missing-local-target TreatAs mappings support recovery."
                    .into(),
            );
        }
        let state = entry
            .redirection_state
            .as_ref()
            .ok_or("COM TreatAs redirection scan evidence is unavailable.")?;
        let original = state
            .value
            .clone()
            .ok_or("The COM TreatAs redirection mapping is absent.")?;
        let app = RedirectionBackup {
            owner: parts[0].into(),
            target: mapping_target(&original)?,
            guard: state.guard.clone(),
        };
        app.validate()?;
        if original.text()? != entry.raw_value || self.store.read_redirection(&app)? != *state {
            return Err(
                "COM TreatAs redirection evidence changed after scanning. Scan again.".into(),
            );
        }
        let mut record = BackupRecord {
            schema_version: 17,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: String::new(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            type_library: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: Some(app),
            conversion: None,
            maintenance: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }
    fn prepare_proxy(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        let prefix = format!("{INTERFACES_KEY}\\");
        let tail = entry
            .key_path
            .strip_prefix(&prefix)
            .ok_or("Unsupported COM proxy location.")?;
        let parts: Vec<_> = tail.split('\\').collect();
        if entry.hive != "HKCU"
            || entry.view != "64"
            || !entry.value_name.is_empty()
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "proxy_clsid_missing"
            || !entry.proxy_repairable
            || parts.len() != 2
            || !parts[1].eq_ignore_ascii_case("ProxyStubClsid32")
        {
            return Err(
                "Only guarded current-user orphaned COM proxy mappings support recovery.".into(),
            );
        }
        let state = entry
            .proxy_state
            .as_ref()
            .ok_or("COM proxy scan evidence is unavailable.")?;
        let original = state
            .value
            .clone()
            .ok_or("The COM proxy mapping is absent.")?;
        let app = ProxyBackup {
            iid: parts[0].into(),
            clsid: mapping_clsid(&original)?,
            guard: state.guard.clone(),
        };
        app.validate()?;
        if original.text()? != entry.raw_value || self.store.read_proxy(&app)? != *state {
            return Err("COM proxy evidence changed after scanning. Scan again.".into());
        }
        let mut record = BackupRecord {
            schema_version: 14,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: String::new(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            type_library: None,
            prog_id: None,
            interface: None,
            proxy: Some(app),
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_icon(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        let prefix = format!("{APPLICATIONS_KEY}\\");
        let tail = entry
            .key_path
            .strip_prefix(&prefix)
            .ok_or("Unsupported application icon location.")?;
        let parts: Vec<_> = tail.split('\\').collect();
        if entry.hive != "HKCU"
            || entry.view != "shared"
            || !entry.value_name.is_empty()
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "target_missing"
            || !entry.icon_repairable
            || parts.len() != 2
            || !parts[1].eq_ignore_ascii_case("DefaultIcon")
        {
            return Err(
                "Only guarded current-user missing application icon mappings support recovery."
                    .into(),
            );
        }
        let state = entry
            .icon_state
            .as_ref()
            .ok_or("application icon scan evidence is unavailable.")?;
        let original = state
            .value
            .clone()
            .ok_or("The application icon mapping is absent.")?;
        let app = IconBackup {
            executable: parts[0].into(),
            guard: state.guard.clone(),
        };
        app.validate()?;
        verify_missing_icon(&original, &self.probe)?;
        if original.text()? != entry.raw_value || self.store.read_icon(&app)? != *state {
            return Err("application icon evidence changed after scanning. Scan again.".into());
        }
        let mut record = BackupRecord {
            schema_version: 15,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: String::new(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            type_library: None,
            prog_id: None,
            interface: None,
            icon: Some(app),
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            proxy: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_interface(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        let prefix = format!("{INTERFACES_KEY}\\");
        let tail = entry
            .key_path
            .strip_prefix(&prefix)
            .ok_or("Unsupported Interface TypeLib location.")?;
        let parts: Vec<_> = tail.split('\\').collect();
        if entry.hive != "HKCU"
            || entry.view != "64"
            || !entry.value_name.is_empty()
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "interface_library_missing"
            || !entry.interface_repairable
            || parts.len() != 2
            || !parts[1].eq_ignore_ascii_case("TypeLib")
        {
            return Err(
                "Only guarded current-user orphaned COM Interface TypeLib mappings support recovery.".into(),
            );
        }
        let state = entry
            .interface_state
            .as_ref()
            .ok_or("Interface TypeLib scan evidence is unavailable.")?;
        let original = state
            .value
            .clone()
            .ok_or("The Interface TypeLib mapping is absent.")?;
        let app = InterfaceBackup {
            iid: parts[0].into(),
            library_id: mapping_library(&original)?,
            guard: state.guard.clone(),
        };
        app.validate()?;
        if original.text()? != entry.raw_value || self.store.read_interface(&app)? != *state {
            return Err("Interface TypeLib evidence changed after scanning. Scan again.".into());
        }
        let mut record = BackupRecord {
            schema_version: 13,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: String::new(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            type_library: None,
            prog_id: None,
            interface: Some(app),
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_prog_id(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        let prefix = format!("{PROG_IDS_KEY}\\");
        let tail = entry
            .key_path
            .strip_prefix(&prefix)
            .ok_or("Unsupported ProgID location.")?;
        let parts: Vec<_> = tail.split('\\').collect();
        if entry.hive != "HKCU"
            || entry.view != "shared"
            || !entry.value_name.is_empty()
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "clsid_missing"
            || !entry.prog_id_repairable
            || parts.len() != 2
            || !parts[1].eq_ignore_ascii_case("CLSID")
        {
            return Err(
                "Only guarded current-user orphaned COM ProgID mappings support recovery.".into(),
            );
        }
        let state = entry
            .prog_id_state
            .as_ref()
            .ok_or("ProgID scan evidence is unavailable.")?;
        let original = state.value.clone().ok_or("The ProgID mapping is absent.")?;
        let app = ProgIdBackup {
            prog_id: parts[0].into(),
            clsid: mapping_clsid(&original)?,
            guard: state.guard.clone(),
        };
        app.validate()?;
        if original.text()? != entry.raw_value || self.store.read_prog_id(&app)? != *state {
            return Err("ProgID evidence changed after scanning. Scan again.".into());
        }
        let mut record = BackupRecord {
            schema_version: 12,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: String::new(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            type_library: None,
            prog_id: Some(app),
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_type_library(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        let prefix = format!("{TYPE_LIB_KEY}\\");
        let tail = entry
            .key_path
            .strip_prefix(&prefix)
            .ok_or("Unsupported type library location.")?;
        let parts: Vec<_> = tail.split('\\').collect();
        if entry.hive != "HKCU"
            || entry.view != "shared"
            || !entry.value_name.is_empty()
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "target_missing"
            || !entry.type_library_repairable
            || parts.len() != 4
            || parts[2] != "0"
            || parts[3] != "win64"
        {
            return Err(
                "Only guarded neutral current-user win64 type library mappings support recovery."
                    .into(),
            );
        }
        let state = entry
            .type_library_state
            .as_ref()
            .ok_or("Type library scan evidence is unavailable.")?;
        let original = state
            .value
            .clone()
            .ok_or("The original type library mapping is absent.")?;
        let app = TypeLibBackup {
            library_id: parts[0].into(),
            version: parts[1].into(),
            locale: "0".into(),
            platform: "win64".into(),
            guard: state.guard.clone(),
        };
        app.validate()?;
        verify_missing_library(&original, &self.probe)?;
        if original.text()? != entry.raw_value || self.store.read_type_library(&app)? != *state {
            return Err("Type library metadata changed after scanning. Scan again.".into());
        }
        let mut record = BackupRecord {
            schema_version: 11,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: String::new(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: Some(app),
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_registered_app(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if entry.hive != "HKCU"
            || entry.view != "shared"
            || entry.key_path != REGISTERED_APPS_KEY
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "capabilities_missing"
            || !entry.registered_app_repairable
        {
            return Err(
                "Only verified current-user orphaned application registrations support recovery."
                    .into(),
            );
        }
        validate_registration_name(&entry.value_name)?;
        let original = entry
            .snapshot
            .clone()
            .ok_or("Application registration evidence is unavailable. Scan again.")?;
        let path = capabilities_path(&original)?;
        if original.text()? != entry.raw_value
            || self
                .store
                .read_registered_app(&entry.value_name, &original)?
                .as_ref()
                != Some(&original)
        {
            return Err("Application registration changed after the scan.".into());
        }
        let mut record = BackupRecord {
            schema_version: 10,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: entry.value_name.clone(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: None,
            registered_app: Some(RegisteredApplicationBackup {
                capabilities_path: path,
            }),
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_shared_dll(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if entry.hive != "HKLM"
            || entry.view != "64"
            || entry.key_path != SHARED_DLLS_KEY
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "target_missing"
        {
            return Err("Only confirmed missing DLL references in the fixed HKLM 64-bit SharedDLLs location support repair.".into());
        }
        let original = entry
            .snapshot
            .clone()
            .ok_or("Shared DLL scan evidence is unavailable. Run a fresh scan.")?;
        verify_missing_shared_dll(&entry.value_name, &original, &self.probe)?;
        if entry.raw_value != "Reference count: 0"
            || self.store.read_shared_dll(&entry.value_name)?.as_ref() != Some(&original)
        {
            return Err("The shared DLL counter changed after scanning. Run a fresh scan.".into());
        }
        let mut record = BackupRecord {
            schema_version: 9,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: entry.value_name.clone(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: None,
            registered_app: None,
            shared_dll: Some(SharedDllBackup {
                path: entry.value_name.clone(),
                view: "64".into(),
            }),
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_menu(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if entry.hive != "HKCU"
            || entry.view != "shared"
            || !entry.value_name.is_empty()
            || !entry.menu_repairable
            || entry.menu_hidden
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "target_missing"
        {
            return Err(
                "Only guarded visible current-user custom context-menu commands support recovery."
                    .into(),
            );
        }
        let (location, verb_name) = MenuLocation::ALL
            .into_iter()
            .find_map(|location| {
                entry
                    .key_path
                    .strip_prefix(&format!("{}\\", location.path()))
                    .and_then(|tail| tail.strip_suffix("\\command"))
                    .map(|name| (location, name))
            })
            .ok_or("Unsupported context-menu location.")?;
        let snapshot = entry
            .menu_snapshot
            .clone()
            .ok_or("Menu scan evidence is unavailable.")?;
        let app = MenuBackup {
            location,
            verb_name: verb_name.into(),
            snapshot,
        };
        app.validate()?;
        let original = app.snapshot.command()?.clone();
        verify_missing_menu_command(&original, &self.probe)?;
        if original.text()? != entry.raw_value || self.store.read_menu(&app)? != app.snapshot {
            return Err("Menu evidence changed after scanning. Scan again.".into());
        }
        let mut record = BackupRecord {
            schema_version: location.backup_schema(),
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: PROGRAMMATIC_ONLY.into(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            application: None,
            shared_dll: None,
            registered_app: None,
            type_library: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: Some(app),
            redirection: None,
            conversion: None,
            maintenance: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_application(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if !entry.value_name.is_empty() {
            return Err("Only the default application open command supports repair.".into());
        }
        let name = entry
            .key_path
            .strip_prefix(&format!("{APPLICATIONS_KEY}\\"))
            .and_then(|path| path.strip_suffix(&format!("\\{OPEN_COMMAND}")))
            .ok_or("Unsupported application command location.")?;
        validate_application_name(name)?;
        let snapshot = entry
            .application_snapshot
            .clone()
            .ok_or("Application evidence is unavailable. Run a fresh scan.")?;
        snapshot.validate_original()?;
        let original = snapshot.command()?.clone();
        verify_missing_command(&original, &self.probe)?;
        if original.text()? != entry.raw_value || self.store.read_application(name)? != snapshot {
            return Err("The application changed after scanning. Run a fresh scan.".into());
        }
        let mut record = BackupRecord {
            schema_version: 8,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: NO_OPEN_WITH.into(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            service: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: None,
            registered_app: None,
            shared_dll: None,
            application: Some(ApplicationBackup {
                executable: name.into(),
                snapshot,
            }),
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_uninstall(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if entry.value_name != "InstallLocation" {
            return Err("Unsupported uninstall scan evidence.".into());
        }
        let prefix = format!("{UNINSTALL_KEY}\\");
        let key_name = entry
            .key_path
            .get(prefix.len()..)
            .filter(|_| {
                entry
                    .key_path
                    .get(..prefix.len())
                    .is_some_and(|path| path.eq_ignore_ascii_case(&prefix))
            })
            .ok_or("Unsupported uninstall registry location.")?;
        validate_uninstall_name(key_name)?;
        let snapshot = entry
            .uninstall_snapshot
            .clone()
            .ok_or("The uninstall entry could not be fully verified. Scan again.")?;
        verify_orphan(&snapshot, &self.probe)?;
        if snapshot.text("InstallLocation")? != entry.raw_value
            || snapshot.text("DisplayName")? != entry.name
            || self.store.read_uninstall(key_name)? != snapshot
        {
            return Err("The uninstall entry changed after the scan. Nothing was repaired.".into());
        }
        let mut record = BackupRecord {
            schema_version: 3,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: COMPONENT.into(),
            created_at: now()?,
            original: snapshot
                .get("InstallLocation")
                .cloned()
                .ok_or("Missing installation path evidence.")?,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: Some(UninstallBackup {
                key_name: key_name.into(),
                snapshot,
            }),
            association: None,
            com: None,
            service: None,
            application: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: None,
            registered_app: None,
            shared_dll: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_association(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if entry.assessment.code != "progid_missing" {
            return Err("The association is not confirmed orphaned.".into());
        }
        let prefix = format!("{CLASSES_KEY}\\");
        let suffix = format!("\\{OPEN_WITH}");
        let extension = entry
            .key_path
            .strip_prefix(&prefix)
            .and_then(|p| p.strip_suffix(&suffix))
            .ok_or("Unsupported file association location.")?;
        validate_extension(extension)?;
        let state = entry
            .association_state
            .clone()
            .ok_or("File association evidence is unavailable. Scan again.")?;
        state.guard.validate(&entry.value_name)?;
        let original = state
            .value
            .clone()
            .ok_or("The suggestion no longer exists.")?;
        validate_suggestion(&original)?;
        if self.store.read_association(extension, &entry.value_name)? != state {
            return Err("The file association changed after the scan. Scan again.".into());
        }
        let mut record = BackupRecord {
            schema_version: 4,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: entry.value_name.clone(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: Some(AssociationBackup {
                extension: extension.into(),
                guard: state.guard,
            }),
            com: None,
            service: None,
            application: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: None,
            registered_app: None,
            shared_dll: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_com(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if !entry.value_name.is_empty() {
            return Err("Only the default COM mapping is supported.".into());
        }
        let prefix = format!("{CLSID_KEY}\\");
        let (clsid, server) = entry
            .key_path
            .strip_prefix(&prefix)
            .and_then(|p| p.split_once('\\'))
            .ok_or("Unsupported COM registry location.")?;
        validate_clsid(clsid)?;
        validate_server(server)?;
        let state = entry
            .com_state
            .clone()
            .ok_or("COM evidence is unavailable. Run a fresh scan.")?;
        state.guard.validate_for(server)?;
        let original = state
            .value
            .clone()
            .ok_or("The COM mapping no longer exists.")?;
        if original.text()? != entry.raw_value || self.store.read_com(clsid, server)? != state {
            return Err("The COM mapping changed after scanning. Nothing was changed.".into());
        }
        verify_missing_mapping(server, &original, &self.probe)?;
        let mut record = BackupRecord {
            schema_version: if server == INPROC_SERVER { 5 } else { 7 },
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: String::new(),
            created_at: now()?,
            original,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: Some(ComBackup {
                server: server.into(),
                clsid: clsid.into(),
                view: "64".into(),
                guard: state.guard,
            }),
            service: None,
            application: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: None,
            registered_app: None,
            shared_dll: None,
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    fn prepare_service(&mut self, entry: &RegistryEntry) -> Result<ChangePlan, String> {
        if entry.hive != "HKLM"
            || entry.view != "shared"
            || entry.value_name != "ImagePath"
            || entry.assessment.status != EntryStatus::Review
            || entry.assessment.code != "target_missing"
        {
            return Err("Only a verified missing service image in the fixed shared service location is supported.".into());
        }
        let name = entry
            .key_path
            .strip_prefix(&format!("{SERVICES_KEY}\\"))
            .ok_or("Unsupported service registry location.")?;
        validate_service_name(name)?;
        let evidence = entry
            .service_state
            .clone()
            .ok_or("Service configuration evidence is unavailable. Scan again.")?;
        evidence.validate_change()?;
        verify_missing_service(&evidence.snapshot, &self.probe)?;
        let current = self.store.read_service(name)?;
        current.validate_change()?;
        if current.snapshot != evidence.snapshot
            || entry.raw_value != evidence.snapshot.config.binary_path
            || entry.name != evidence.snapshot.config.display_name
        {
            return Err("The service changed after scanning. Nothing was changed.".into());
        }
        let mut record = BackupRecord {
            schema_version: 6,
            id: Uuid::new_v4(),
            name: entry.name.clone(),
            value_name: "Start".into(),
            created_at: now()?,
            original: evidence
                .snapshot
                .get("Start")
                .cloned()
                .ok_or("Missing startup evidence.")?,
            integrity_sha256: String::new(),
            app_path: None,
            uninstall: None,
            association: None,
            com: None,
            application: None,
            prog_id: None,
            interface: None,
            proxy: None,
            icon: None,
            menu: None,
            redirection: None,
            conversion: None,
            maintenance: None,
            type_library: None,
            registered_app: None,
            shared_dll: None,
            service: Some(ServiceBackup {
                service_name: name.into(),
                snapshot: evidence.snapshot,
            }),
        };
        record.integrity_sha256 = Self::checksum(&record)?;
        self.prepare(record, false)
    }

    pub fn prepare_restore(&mut self, id: &str) -> Result<ChangePlan, String> {
        self.pending = None;
        self.batch_pending = None;
        let record = self.load(id)?;
        if self.read_record(&record)?.is_some() {
            return Err("A value with this name already exists. Restore never overwrites an existing value.".into());
        }
        self.prepare(record, true)
    }

    fn prepare(&mut self, record: BackupRecord, restore: bool) -> Result<ChangePlan, String> {
        if let Some(app) = &record.maintenance {
            self.store.check_maintenance_write_access(app)?;
        }
        if let Some(app) = &record.conversion {
            self.store.check_conversion_write_access(app)?;
        }
        if let Some(app) = &record.redirection {
            self.store.check_redirection_write_access(app)?;
        }
        if let Some(app) = &record.menu {
            self.store.check_menu_write_access(app)?;
        }
        if let Some(app) = &record.icon {
            self.store.check_icon_write_access(app)?;
        }
        if let Some(app) = &record.proxy {
            self.store.check_proxy_write_access(app)?;
        }
        if let Some(app) = &record.interface {
            self.store.check_interface_write_access(app)?;
        }
        if let Some(app) = &record.prog_id {
            self.store.check_prog_id_write_access(app)?;
        }
        if let Some(app) = &record.type_library {
            self.store.check_type_library_write_access(app)?;
        }
        if record.registered_app.is_some() {
            self.store.check_registered_app_write_access()?;
        }
        if record.shared_dll.is_some() {
            self.store.check_shared_dll_write_access()?;
        }
        let plan = ChangePlan {
            token: Uuid::new_v4().to_string(),
            action: if restore { "restore" } else { "quarantine" }.into(),
            name: record.name.clone(),
            value_name: record.value_name.clone(),
            registry_path: Self::registry_path(&record),
            registry_view: if record.com.is_some()
                || record.shared_dll.is_some()
                || record.interface.is_some()
                || record.proxy.is_some()
                || record.redirection.is_some()
                || record.conversion.is_some()
            {
                "64"
            } else {
                "shared"
            }
            .into(),
            original_value: if let Some(app) = &record.maintenance {
                app.summary()?
            } else if record.shared_dll.is_some() {
                "0".into()
            } else if record.application.is_some() || record.menu.is_some() {
                "(absent)".into()
            } else if record.service.is_some() {
                "3 (Manual)".into()
            } else if record.association.is_some() {
                "(empty)".into()
            } else {
                record.original.text()?
            },
            value_type: if record.application.is_some() || record.menu.is_some() {
                "REG_SZ"
            } else if record.service.is_some() || record.shared_dll.is_some() {
                "REG_DWORD"
            } else if record.association.is_some() && record.original.kind == 0 {
                "REG_NONE"
            } else if record.uninstall.is_some() {
                "REG_DWORD"
            } else if record.original.kind == 1 {
                "REG_SZ"
            } else {
                "REG_EXPAND_SZ"
            }
            .into(),
            expires_at: now()? + PLAN_LIFETIME,
            scope: if let Some(app) = &record.maintenance {
                app.kind.scope()
            } else if record.conversion.is_some() {
                "com_conversion"
            } else if record.redirection.is_some() {
                "com_redirection"
            } else if record.menu.is_some() {
                "shell_menu"
            } else if record.icon.is_some() {
                "application_icon"
            } else if record.proxy.is_some() {
                "com_proxy"
            } else if record.interface.is_some() {
                "interface"
            } else if record.prog_id.is_some() {
                "prog_id"
            } else if record.type_library.is_some() {
                "type_library"
            } else if record.registered_app.is_some() {
                "registered_app"
            } else if record.shared_dll.is_some() {
                "shared_dll"
            } else if record.application.is_some() {
                "application"
            } else if record.service.is_some() {
                "service"
            } else if record.com.is_some() {
                "com"
            } else if record.association.is_some() {
                "association"
            } else if record.uninstall.is_some() {
                "uninstall"
            } else if record.app_path.is_some() {
                "app_path"
            } else {
                "startup"
            }
            .into(),
            preserved_values: if let Some(app) = &record.maintenance {
                app.snapshot.preserved.len()
            } else if let Some(app) = &record.conversion {
                app.guard.values.len()
            } else if let Some(app) = &record.redirection {
                app.guard.values.len()
            } else if let Some(app) = &record.menu {
                app.snapshot.value_count()
            } else if let Some(app) = &record.icon {
                app.guard.value_count()
            } else if let Some(app) = &record.proxy {
                app.guard.value_count()
            } else if let Some(app) = &record.interface {
                app.guard.value_count()
            } else if let Some(app) = &record.prog_id {
                app.guard.values.len()
            } else if let Some(app) = &record.type_library {
                app.guard.nodes.iter().map(|node| node.values.len()).sum()
            } else if let Some(app) = &record.application {
                app.snapshot.value_count()
            } else if let Some(service) = &record.service {
                service.snapshot.values.len()
                    + service
                        .snapshot
                        .security_values
                        .as_ref()
                        .map_or(0, Vec::len)
            } else if let Some(com) = &record.com {
                com.guard.class_values.len() + com.guard.server_values.len()
            } else if let Some(association) = &record.association {
                association.guard.suggestions.len()
            } else if let Some(uninstall) = &record.uninstall {
                uninstall.snapshot.values.len()
            } else {
                record
                    .app_path
                    .as_ref()
                    .map_or(0, |app| app.guard.values.len())
            },
            uninstall_command: record
                .uninstall
                .as_ref()
                .map(|uninstall| uninstall.snapshot.text("UninstallString"))
                .transpose()?,
            application_command: if record.menu.is_some() {
                Some(record.original.text()?)
            } else {
                record
                    .application
                    .as_ref()
                    .map(|_| record.original.text())
                    .transpose()?
            },
            service_executable: record
                .service
                .as_ref()
                .map(|service| service.snapshot.config.binary_path.clone()),
            component_was_present: record
                .uninstall
                .as_ref()
                .is_some_and(|uninstall| uninstall.snapshot.get(COMPONENT).is_some()),
        };
        self.pending = Some(Pending {
            plan: plan.clone(),
            action: if restore {
                PendingAction::Restore(record)
            } else {
                PendingAction::Quarantine(record)
            },
        });
        Ok(plan)
    }

    pub fn cancel(&mut self) {
        self.pending = None;
        self.batch_pending = None;
    }

    fn registry_path(record: &BackupRecord) -> String {
        if let Some(app) = &record.maintenance {
            return format!("HKCU\\{}", app.kind.path());
        }
        if let Some(app) = &record.conversion {
            return format!(
                "HKCU\\{}\\{}\\AutoConvertTo",
                crate::com::CLSID_KEY,
                app.owner
            );
        }
        if let Some(app) = &record.redirection {
            return format!("HKCU\\{}\\{}\\TreatAs", crate::com::CLSID_KEY, app.owner);
        }
        if let Some(app) = &record.menu {
            return format!("HKCU\\{}\\{}", app.location.path(), app.verb_name);
        }
        if let Some(app) = &record.icon {
            return format!("HKCU\\{APPLICATIONS_KEY}\\{}\\DefaultIcon", app.executable);
        }
        if let Some(app) = &record.proxy {
            return format!("HKCU\\{INTERFACES_KEY}\\{}\\ProxyStubClsid32", app.iid);
        }
        if let Some(app) = &record.interface {
            return format!("HKCU\\{INTERFACES_KEY}\\{}\\TypeLib", app.iid);
        }
        if let Some(app) = &record.prog_id {
            return format!("HKCU\\{PROG_IDS_KEY}\\{}\\CLSID", app.prog_id);
        }
        if let Some(app) = &record.type_library {
            return format!(
                "HKCU\\{TYPE_LIB_KEY}\\{}\\{}\\0\\win64",
                app.library_id, app.version
            );
        }
        if record.registered_app.is_some() {
            return format!("HKCU\\{REGISTERED_APPS_KEY}");
        }
        if record.shared_dll.is_some() {
            return format!("HKLM\\{SHARED_DLLS_KEY}");
        }
        if let Some(app) = &record.application {
            return format!("HKCU\\{APPLICATIONS_KEY}\\{}", app.executable);
        }
        if let Some(service) = &record.service {
            return format!("HKLM\\{SERVICES_KEY}\\{}", service.service_name);
        }
        if let Some(com) = &record.com {
            return format!("HKCU\\{CLSID_KEY}\\{}\\{}", com.clsid, com.server);
        }
        if let Some(association) = &record.association {
            return format!(
                "HKCU\\{CLASSES_KEY}\\{}\\{OPEN_WITH}",
                association.extension
            );
        }
        if let Some(uninstall) = &record.uninstall {
            return format!("HKCU\\{UNINSTALL_KEY}\\{}", uninstall.key_name);
        }
        record.app_path.as_ref().map_or_else(
            || format!("HKCU\\{STARTUP_KEY}"),
            |app| format!("HKCU\\{APP_PATHS_KEY}\\{}", app.executable),
        )
    }

    fn read_record(&self, record: &BackupRecord) -> Result<Option<StoredValue>, String> {
        if let Some(app) = &record.maintenance {
            app.verify_target(&self.probe)?;
            let state = self.store.read_maintenance(app)?;
            if state == app.snapshot {
                return Ok(Some(record.original.clone()));
            }
            if state == app.cleared() {
                return Ok(None);
            }
            return Err("Maintenance data changed. Cleaning and restore are blocked; new history is never overwritten.".into());
        }

        if let Some(app) = &record.conversion {
            let state = self.store.read_conversion(app)?;
            if state.guard != app.guard {
                return Err("COM class metadata changed. Repair or restore is blocked.".into());
            }
            return Ok(state.value);
        }

        if let Some(app) = &record.redirection {
            let state = self.store.read_redirection(app)?;
            if state.guard != app.guard {
                return Err("COM class metadata changed. Repair or restore is blocked.".into());
            }
            return Ok(state.value);
        }

        if let Some(app) = &record.menu {
            verify_missing_menu_command(&record.original, &self.probe)?;
            let state = self.store.read_menu(app)?;
            if state == app.snapshot {
                return Ok(Some(record.original.clone()));
            }
            if state == app.snapshot.hidden()? {
                return Ok(None);
            }
            return Err("Menu command, visibility, root or display metadata changed. Repair or restore is blocked.".into());
        }

        if let Some(app) = &record.proxy {
            let state = self.store.read_proxy(app)?;
            if state.guard != app.guard {
                return Err("Interface metadata changed. Repair or restore is blocked.".into());
            }
            return Ok(state.value);
        }

        if let Some(app) = &record.icon {
            verify_missing_icon(&record.original, &self.probe)?;
            let state = self.store.read_icon(app)?;
            if state.guard != app.guard {
                return Err("Interface metadata changed. Repair or restore is blocked.".into());
            }
            return Ok(state.value);
        }

        if let Some(app) = &record.interface {
            let state = self.store.read_interface(app)?;
            if state.guard != app.guard {
                return Err("Interface metadata changed. Repair or restore is blocked.".into());
            }
            return Ok(state.value);
        }

        if let Some(app) = &record.prog_id {
            let state = self.store.read_prog_id(app)?;
            if state.guard != app.guard {
                return Err(
                    "ProgID description metadata changed. Repair or restore is blocked.".into(),
                );
            }
            return Ok(state.value);
        }

        if let Some(app) = &record.type_library {
            verify_missing_library(&record.original, &self.probe)?;
            let state = self.store.read_type_library(app)?;
            if state.guard != app.guard {
                return Err("Type library metadata changed. Repair or restore is blocked.".into());
            }
            return Ok(state.value);
        }

        if record.registered_app.is_some() {
            return self
                .store
                .read_registered_app(&record.value_name, &record.original);
        }
        if record.shared_dll.is_some() {
            verify_missing_shared_dll(&record.value_name, &record.original, &self.probe)?;
            return self.store.read_shared_dll(&record.value_name);
        }
        if let Some(app) = &record.application {
            let state = self.store.read_application(&app.executable)?;
            if state == app.snapshot {
                return Ok(Some(record.original.clone()));
            }
            if state == app.snapshot.hidden()? {
                return Ok(None);
            }
            return Err("The application command, visibility, or guarded metadata changed. Repair and restore are blocked.".into());
        }
        if let Some(service) = &record.service {
            let state = self.store.read_service(&service.service_name)?;
            state.validate_change()?;
            if state.snapshot == service.snapshot {
                return Ok(Some(record.original.clone()));
            }
            if state.snapshot == service.snapshot.disabled()? {
                return Ok(None);
            }
            return Err("The service metadata, security, or startup configuration changed. Repair or restore is blocked.".into());
        }
        if let Some(com) = &record.com {
            let state = self.store.read_com(&com.clsid, &com.server)?;
            if state.guard != com.guard {
                return Err("COM metadata changed. Repair or restore is blocked.".into());
            }
            return Ok(state.value);
        }
        if let Some(association) = &record.association {
            let state = self
                .store
                .read_association(&association.extension, &record.value_name)?;
            if state.guard != association.guard {
                return Err("The association metadata or application selection changed. Repair or restore is blocked.".into());
            }
            return Ok(state.value);
        }
        if let Some(uninstall) = &record.uninstall {
            let actual = self.store.read_uninstall(&uninstall.key_name)?;
            if actual == uninstall.snapshot {
                return Ok(Some(record.original.clone()));
            }
            if actual == uninstall.snapshot.hidden()? {
                return Ok(None);
            }
            return Err("The uninstall record changed. Repair or restore is blocked; no existing value was overwritten.".into());
        }
        if let Some(app) = &record.app_path {
            let state = self.store.read_app_path(&app.executable)?;
            if state.guard != app.guard {
                return Err("App Paths metadata changed. Repair or restore is blocked; existing values were preserved.".into());
            }
            Ok(state.value)
        } else {
            self.store.read(&record.value_name)
        }
    }

    fn exchange_record(
        &self,
        record: &BackupRecord,
        expected: Option<StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        if let Some(app) = &record.maintenance {
            app.verify_target(&self.probe)?;
            let cleared = app.cleared();
            return self.store.compare_exchange_maintenance(
                app,
                if expected.is_some() {
                    &app.snapshot
                } else {
                    &cleared
                },
                if replacement.is_some() {
                    &app.snapshot
                } else {
                    &cleared
                },
            );
        }
        if let Some(app) = &record.conversion {
            return self.store.compare_exchange_conversion(
                app,
                &ConversionState {
                    value: expected,
                    guard: app.guard.clone(),
                },
                replacement,
            );
        }
        if let Some(app) = &record.redirection {
            return self.store.compare_exchange_redirection(
                app,
                &RedirectionState {
                    value: expected,
                    guard: app.guard.clone(),
                },
                replacement,
            );
        }
        if let Some(app) = &record.proxy {
            return self.store.compare_exchange_proxy(
                app,
                &ProxyState {
                    value: expected,
                    guard: app.guard.clone(),
                },
                replacement,
            );
        }
        if let Some(app) = &record.icon {
            return self.store.compare_exchange_icon(
                app,
                &IconState {
                    value: expected,
                    guard: app.guard.clone(),
                },
                replacement,
            );
        }
        if let Some(app) = &record.interface {
            return self.store.compare_exchange_interface(
                app,
                &InterfaceState {
                    value: expected,
                    guard: app.guard.clone(),
                },
                replacement,
            );
        }
        if let Some(app) = &record.prog_id {
            return self.store.compare_exchange_prog_id(
                app,
                &ProgIdState {
                    value: expected,
                    guard: app.guard.clone(),
                },
                replacement,
            );
        }
        if let Some(app) = &record.type_library {
            return self.store.compare_exchange_type_library(
                app,
                &TypeLibState {
                    value: expected,
                    guard: app.guard.clone(),
                },
                replacement,
            );
        }
        if record.registered_app.is_some() {
            return self.store.compare_exchange_registered_app(
                &record.value_name,
                &record.original,
                expected.as_ref(),
                replacement,
            );
        }
        if record.shared_dll.is_some() {
            return self.store.compare_exchange_shared_dll(
                &record.value_name,
                expected.as_ref(),
                replacement,
            );
        }
        if let Some(app) = &record.menu {
            return self.store.set_menu_hidden(app, replacement.is_none());
        }
        if let Some(app) = &record.application {
            return self.store.set_application_hidden(
                &app.executable,
                &app.snapshot,
                replacement.is_none(),
            );
        }
        if let Some(service) = &record.service {
            return self.store.set_service_disabled(
                &service.service_name,
                &service.snapshot,
                replacement.is_none(),
            );
        }
        if let Some(com) = &record.com {
            return self.store.compare_exchange_com(
                &com.clsid,
                &com.server,
                &ComState {
                    value: expected,
                    guard: com.guard.clone(),
                },
                replacement,
            );
        }
        if let Some(association) = &record.association {
            return self.store.compare_exchange_association(
                &association.extension,
                &record.value_name,
                &AssociationState {
                    value: expected,
                    guard: association.guard.clone(),
                },
                replacement,
            );
        }
        if let Some(uninstall) = &record.uninstall {
            return self.store.set_uninstall_hidden(
                &uninstall.key_name,
                &uninstall.snapshot,
                replacement.is_none(),
            );
        }
        if let Some(app) = &record.app_path {
            self.store.compare_exchange_app_path(
                &app.executable,
                &AppPathState {
                    value: expected,
                    guard: app.guard.clone(),
                },
                replacement,
            )
        } else {
            self.store
                .compare_exchange(&record.value_name, expected.as_ref(), replacement)
        }
    }

    pub fn apply(&mut self, token: &str) -> Result<ChangeResult, String> {
        let pending = self
            .pending
            .take()
            .ok_or("No pending change. Review the entry again.")?;
        if pending.plan.token != token || now()? > pending.plan.expires_at {
            return Err("This review expired or does not match. Review the change again.".into());
        }
        let (record, restore) = match pending.action {
            PendingAction::Quarantine(record) => (record, false),
            PendingAction::Restore(record) => (record, true),
        };
        if restore {
            // Re-read immutable backup evidence immediately before restoring.
            let disk = self.load(&record.id.to_string())?;
            if disk.integrity_sha256 != record.integrity_sha256 {
                return Err("The backup changed after review. Nothing was restored.".into());
            }
            self.read_record(&record)?;
            self.exchange_record(&record, None, Some(&record.original))?;
        } else {
            if let Some(app) = &record.maintenance {
                app.verify_target(&self.probe)?;
            } else if let Some(app) = &record.conversion {
                self.store.read_conversion(app)?;
            } else if let Some(app) = &record.redirection {
                self.store.read_redirection(app)?;
            } else if let Some(app) = &record.menu {
                verify_missing_menu_command(app.snapshot.command()?, &self.probe)?;
            } else if record.icon.is_some() {
                verify_missing_icon(&record.original, &self.probe)?;
            } else if let Some(app) = &record.proxy {
                self.store.read_proxy(app)?;
            } else if let Some(app) = &record.interface {
                self.store.read_interface(app)?;
            } else if let Some(app) = &record.prog_id {
                self.store.read_prog_id(app)?;
            } else if record.type_library.is_some() {
                verify_missing_library(&record.original, &self.probe)?;
            } else if record.registered_app.is_some() {
                self.store
                    .read_registered_app(&record.value_name, &record.original)?;
            } else if record.shared_dll.is_some() {
                verify_missing_shared_dll(&record.value_name, &record.original, &self.probe)?;
            } else if record.application.is_some() {
                verify_missing_command(&record.original, &self.probe)?;
            } else if let Some(service) = &record.service {
                verify_missing_service(&service.snapshot, &self.probe)?;
            } else if let Some(uninstall) = &record.uninstall {
                verify_orphan(&uninstall.snapshot, &self.probe)?;
            } else if let Some(com) = &record.com {
                verify_missing_mapping(&com.server, &record.original, &self.probe)?;
            } else if record.association.is_none() {
                self.verify_missing(&record.original, record.app_path.is_some())?;
            }
            if self.read_record(&record)?.as_ref() != Some(&record.original) {
                return Err(
                    "The registry value changed after review. Nothing was disabled.".into(),
                );
            }
            self.save(&record)?;
            self.exchange_record(&record, Some(record.original.clone()), None)?;
        }
        let actual = self.read_record(&record)?;
        let expected = if restore {
            Some(record.original.clone())
        } else {
            None
        };
        if actual != expected {
            return Err(format!("The change committed, but the current value has changed again. Backup {} is preserved; refresh and inspect the result.", record.id));
        }
        Ok(ChangeResult {
            backup_id: record.id.to_string(),
            action: pending.plan.action,
            message: if let Some(app)=&record.maintenance { if restore {"Original maintenance values restored and verified. No command was executed."}else if app.kind.history(){"Selected registry history cleared after a verified backup. Other history stores and files were preserved."}else{"Stale application cache values removed after a verified backup. Other cache values, files, and permissions were preserved."} }else if record.conversion.is_some(){if restore{"Original AutoConvertTo reference restored and verified. No document was opened or converted."}else{"Missing-local-target AutoConvertTo value removed after a verified backup. Class keys, descriptions, documents, files and permissions were preserved."}}else if record.redirection.is_some(){if restore{"Original TreatAs redirection restored and verified. No COM class was activated."}else{"Missing-local-target TreatAs value removed after a verified backup. Keys, descriptions, files, and permissions were preserved."}}else if record.menu.is_some(){if restore{"Original context-menu visibility restored and verified. No command was run."}else{"Missing-target menu marked programmatic-only after a verified backup. Its command, keys, files, and metadata were preserved."}}else if record.icon.is_some(){if restore{"Original application icon reference restored and verified."}else{"Missing icon reference removed after a verified backup. The open command, metadata, keys, and files were preserved."}}else if record.proxy.is_some(){if restore{"Original COM proxy reference restored and verified."}else{"Orphaned COM proxy reference disabled after a verified backup. TypeLib metadata, keys, files, and permissions were preserved."}}else if record.interface.is_some(){if restore{"Original interface TypeLib reference restored and verified."}else{"Orphaned interface TypeLib reference disabled after a verified backup. Version, proxy, keys, and files were preserved."}}else if record.prog_id.is_some(){if restore{"Original COM ProgID mapping restored and verified. No COM object was activated."}else{"Orphaned COM ProgID mapping disabled after a verified backup. Keys, metadata, class registrations, and files were preserved."}}else if record.type_library.is_some() { if restore { "Original win64 type library mapping restored and verified. No library was loaded or registered." } else { "Missing win64 type library mapping disabled after a verified backup. Metadata, win32 mappings, keys, files, and permissions were preserved." } } else if record.registered_app.is_some() { if restore { "Original application registration restored and verified. Default selections were preserved." } else { "Orphaned application registration removed after a verified backup. Capabilities, defaults, files, and permissions were preserved." } } else if record.shared_dll.is_some() { if restore { "Original zero-count shared DLL reference restored and verified. No file was loaded or changed." } else { "Missing zero-count shared DLL reference removed after a verified backup. All other counters and files were preserved." } } else if record.application.is_some() { if restore {"Original application suggestion visibility restored and verified. The open command was preserved."} else {"Broken application marked NoOpenWith after a verified backup. The open command and default application selections were preserved."} } else if record.service.is_some() {if restore {"Original Manual startup restored and verified through SCM. The service was not started."} else {"Missing-target service disabled after a verified backup. No service was started, stopped, or deleted."}} else if record.com.is_some() {
                if restore {"Original 64-bit COM mapping restored and verified. No COM object was activated."} else {"Broken 64-bit COM mapping disabled after a verified backup. The class key and metadata were preserved."}
            } else if record.association.is_some() {
                if restore { "Original Open with suggestion restored and verified. Default applications were preserved." } else { "Orphaned Open with suggestion removed after a verified backup. Default applications were preserved." }
            } else if record.uninstall.is_some() {
                if restore { "Original uninstall metadata and visibility restored and verified." } else { "Orphaned uninstall entry hidden after a full verified backup. No uninstall command was executed." }
            } else if restore {
                "Original registry value restored and verified."
            } else {
                "Broken mapping disabled. Its exact original bytes are saved in a verified backup."
            }
            .into(),
        })
    }

    pub fn inventory(&self) -> Result<BackupInventory, String> {
        self.ensure_directory(false)?;
        let mut inventory = BackupInventory {
            storage_path: self.directory.to_string_lossy().into(),
            backups: Vec::new(),
            warnings: Vec::new(),
        };
        let files = match fs::read_dir(&self.directory) {
            Ok(files) => files,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(inventory),
            Err(error) => return Err(format!("Cannot list backups: {error}")),
        };
        for (index, file) in files.enumerate() {
            if index >= 1000 {
                inventory
                    .warnings
                    .push("Only the first 1,000 backup directory entries were inspected.".into());
                break;
            }
            let file = match file {
                Ok(file) => file,
                Err(_) => {
                    inventory
                        .warnings
                        .push("A backup directory entry could not be read.".into());
                    continue;
                }
            };
            let path = file.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let record = match self.load(id) {
                Ok(record) => record,
                Err(error) => {
                    inventory.warnings.push(format!("{id}: {error}"));
                    continue;
                }
            };
            let (state, note) = match self.read_record(&record) {
                Ok(None) => (
                    "restore_available",
                    if record.menu.is_some(){"The menu matches its backed-up programmatic-only state. Original visibility can be reviewed for restore."}else if record.application.is_some() { "The application matches its backed-up NoOpenWith state. Its original suggestion visibility can be restored." } else if record.service.is_some() { "The service matches its backed-up Disabled state. Its original Manual startup can be restored." } else if record.uninstall.is_some() { "The uninstall entry matches its backed-up hidden state. Its original visibility can be restored." } else { "The value is absent. Its original can be reviewed for restore." }.into(),
                ),
                Ok(Some(value)) if value == record.original => (
                    "original_present",
                    "The live value matches this backup. No restore is needed.".into(),
                ),
                Ok(Some(_)) => (
                    "conflict",
                    "A different value with the same name exists. Restore is blocked.".into(),
                ),
                Err(error) => ("unverified", error),
            };
            let scope = if let Some(app) = &record.maintenance {
                app.kind.scope()
            } else if record.conversion.is_some() {
                "com_conversion"
            } else if record.redirection.is_some() {
                "com_redirection"
            } else if record.menu.is_some() {
                "shell_menu"
            } else if record.icon.is_some() {
                "application_icon"
            } else if record.proxy.is_some() {
                "com_proxy"
            } else if record.interface.is_some() {
                "interface"
            } else if record.prog_id.is_some() {
                "prog_id"
            } else if record.type_library.is_some() {
                "type_library"
            } else if record.registered_app.is_some() {
                "registered_app"
            } else if record.shared_dll.is_some() {
                "shared_dll"
            } else if record.application.is_some() {
                "application"
            } else if record.service.is_some() {
                "service"
            } else if record.com.is_some() {
                "com"
            } else if record.association.is_some() {
                "association"
            } else if record.uninstall.is_some() {
                "uninstall"
            } else if record.app_path.is_some() {
                "app_path"
            } else {
                "startup"
            }
            .into();
            let registry_path = Self::registry_path(&record);
            let registry_view = if record.com.is_some()
                || record.shared_dll.is_some()
                || record.interface.is_some()
                || record.proxy.is_some()
                || record.redirection.is_some()
                || record.conversion.is_some()
            {
                "64"
            } else {
                "shared"
            }
            .into();
            inventory.backups.push(BackupSummary {
                id: record.id.to_string(),
                name: record.name,
                value_name: record.value_name,
                created_at: record.created_at,
                state: state.into(),
                note,
                scope,
                registry_path,
                registry_view,
            });
        }
        inventory
            .backups
            .sort_by_key(|record| std::cmp::Reverse(record.created_at));
        Ok(inventory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Assessment, ProbeResult};
    use std::{
        cell::{Cell, RefCell},
        collections::HashMap,
        path::Path,
        rc::Rc,
    };
    #[derive(Clone, Default)]
    struct Memory(
        Rc<RefCell<HashMap<String, StoredValue>>>,
        Rc<RefCell<HashMap<String, AppPathState>>>,
        Rc<RefCell<HashMap<String, UninstallSnapshot>>>,
        Rc<RefCell<HashMap<(String, String), AssociationState>>>,
        Rc<RefCell<HashMap<String, ServiceState>>>,
        Rc<RefCell<HashMap<String, ComState>>>,
    );
    impl RegistryStore for Memory {
        fn read_service(&self, name: &str) -> Result<ServiceState, String> {
            self.4
                .borrow()
                .get(name)
                .cloned()
                .ok_or("Service missing".into())
        }
        fn set_service_disabled(
            &self,
            name: &str,
            original: &ServiceSnapshot,
            disabled: bool,
        ) -> Result<(), String> {
            let mut services = self.4.borrow_mut();
            let state = services.get_mut(name).ok_or("Service missing")?;
            state.validate_change()?;
            let expected = if disabled {
                original.clone()
            } else {
                original.disabled()?
            };
            if state.snapshot != expected {
                return Err("Service conflict".into());
            }
            state.snapshot = if disabled {
                original.disabled()?
            } else {
                original.clone()
            };
            Ok(())
        }
        fn read_com(&self, name: &str, _server: &str) -> Result<ComState, String> {
            self.5
                .borrow()
                .get(name)
                .cloned()
                .ok_or("COM key missing".into())
        }
        fn compare_exchange_com(
            &self,
            name: &str,
            _server: &str,
            expected: &ComState,
            replacement: Option<&StoredValue>,
        ) -> Result<(), String> {
            let mut records = self.5.borrow_mut();
            let current = records.get_mut(name).ok_or("COM key missing")?;
            if current != expected {
                return Err("COM conflict".into());
            }
            current.value = replacement.cloned();
            Ok(())
        }

        fn read_association(
            &self,
            extension: &str,
            progid: &str,
        ) -> Result<AssociationState, String> {
            self.3
                .borrow()
                .get(&(extension.into(), progid.into()))
                .cloned()
                .ok_or("Association key is absent".into())
        }
        fn compare_exchange_association(
            &self,
            extension: &str,
            progid: &str,
            expected: &AssociationState,
            replacement: Option<&StoredValue>,
        ) -> Result<(), String> {
            let mut records = self.3.borrow_mut();
            let actual = records
                .get_mut(&(extension.into(), progid.into()))
                .ok_or("Association key is absent")?;
            if actual != expected {
                return Err("Association conflict".into());
            }
            actual.value = replacement.cloned();
            Ok(())
        }

        fn read_uninstall(&self, key_name: &str) -> Result<UninstallSnapshot, String> {
            self.2
                .borrow()
                .get(key_name)
                .cloned()
                .ok_or("Uninstall key is absent".into())
        }
        fn set_uninstall_hidden(
            &self,
            key_name: &str,
            original: &UninstallSnapshot,
            hide: bool,
        ) -> Result<(), String> {
            let mut records = self.2.borrow_mut();
            let current = records.get_mut(key_name).ok_or("Uninstall key is absent")?;
            let hidden = original.hidden()?;
            if current != if hide { original } else { &hidden } {
                return Err("Uninstall conflict".into());
            }
            *current = if hide { hidden } else { original.clone() };
            Ok(())
        }
        fn read_app_path(&self, executable: &str) -> Result<AppPathState, String> {
            self.1
                .borrow()
                .get(executable)
                .cloned()
                .ok_or("App Paths key is absent".into())
        }
        fn compare_exchange_app_path(
            &self,
            executable: &str,
            expected: &AppPathState,
            replacement: Option<&StoredValue>,
        ) -> Result<(), String> {
            let mut values = self.1.borrow_mut();
            let current = values
                .get_mut(executable)
                .ok_or("App Paths key is absent")?;
            if current != expected {
                return Err("App Paths conflict".into());
            }
            current.value = replacement.cloned();
            Ok(())
        }
        fn read(&self, name: &str) -> Result<Option<StoredValue>, String> {
            Ok(self.0.borrow().get(name).cloned())
        }
        fn compare_exchange(
            &self,
            name: &str,
            expected: Option<&StoredValue>,
            replacement: Option<&StoredValue>,
        ) -> Result<(), String> {
            let mut values = self.0.borrow_mut();
            if values.get(name) != expected {
                return Err("Conflict".into());
            }
            match replacement {
                Some(value) => {
                    values.insert(name.into(), value.clone());
                }
                None => {
                    values.remove(name);
                }
            }
            Ok(())
        }
    }
    struct Probe(Rc<Cell<ProbeResult>>);
    impl PathProbe for Probe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            self.0.get()
        }
    }
    fn original() -> StoredValue {
        StoredValue {
            kind: 2,
            bytes: "C:\\Missing\\app.exe\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    fn entry() -> RegistryEntry {
        RegistryEntry {
            id: "entry".into(),
            name: "Example".into(),
            category: Category::Startup,
            hive: "HKCU".into(),
            key_path: STARTUP_KEY.into(),
            view: "shared".into(),
            value_name: "Example".into(),
            value_type: "REG_EXPAND_SZ".into(),
            raw_value: r"C:\Missing\app.exe".into(),
            publisher: None,
            version: None,
            assessment: Assessment {
                status: EntryStatus::Review,
                code: "target_missing".into(),
                explanation: "Missing".into(),
                target: Some(r"C:\Missing\app.exe".into()),
            },
            snapshot: Some(original()),
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
            shared_dll_repairable: false,
            registered_app_repairable: false,
            type_library_state: None,
            type_library_repairable: false,
            prog_id_state: None,
            prog_id_repairable: false,
            interface_state: None,
            interface_repairable: false,
            conversion_state: None,
            maintenance_state: None,
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
        }
    }
    fn setup(path: &Path) -> (Memory, Rc<Cell<ProbeResult>>, ChangeManager<Memory, Probe>) {
        let store = Memory::default();
        store.0.borrow_mut().insert("Example".into(), original());
        let state = Rc::new(Cell::new(ProbeResult::Missing));
        (
            store.clone(),
            state.clone(),
            ChangeManager::new(store, path.into(), Probe(state)),
        )
    }

    #[test]
    fn review_is_read_only_and_verified_backup_survives_restart_for_exact_restore() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backups");
        let (store, state, mut manager) = setup(&path);
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        assert!(!path.exists());
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        let result = manager.apply(&plan.token).unwrap();
        assert!(store.read("Example").unwrap().is_none());
        assert_eq!(
            manager.inventory().unwrap().backups[0].state,
            "restore_available"
        );
        let mut reopened = ChangeManager::new(store.clone(), path, Probe(state));
        let restore = reopened.prepare_restore(&result.backup_id).unwrap();
        reopened.apply(&restore.token).unwrap();
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        assert_eq!(
            reopened.inventory().unwrap().backups[0].state,
            "original_present"
        );
    }
    #[test]
    fn registry_and_filesystem_changes_after_review_block_disable() {
        for registry_changed in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let (store, state, mut manager) = setup(dir.path());
            let plan = manager.prepare_quarantine(&entry()).unwrap();
            if registry_changed {
                store.0.borrow_mut().insert(
                    "Example".into(),
                    StoredValue {
                        kind: 1,
                        bytes: original().bytes,
                    },
                );
            } else {
                state.set(ProbeResult::Found);
            }
            assert!(manager.apply(&plan.token).is_err());
            assert!(store.read("Example").unwrap().is_some());
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }
    #[test]
    fn never_disables_out_of_scope_or_uncertain_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        for change in 0..6 {
            let mut record = entry();
            match change {
                0 => record.hive = "HKLM".into(),
                1 => record.key_path.push_str("Once"),
                2 => record.category = Category::AppPaths,
                3 => record.assessment.status = EntryStatus::Unknown,
                4 => record.snapshot = None,
                _ => record.view = "32".into(),
            }
            assert!(manager.prepare_quarantine(&record).is_err());
        }
        assert_eq!(store.read("Example").unwrap(), Some(original()));
    }
    #[test]
    fn backup_failure_prevents_registry_change_and_plans_are_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-directory");
        fs::write(&path, "occupied").unwrap();
        let (store, _, mut manager) = setup(&path);
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        assert!(manager.apply(&plan.token).is_err());
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        assert!(manager.apply(&plan.token).is_err());
    }
    #[test]
    fn restore_conflict_and_backup_tampering_do_not_overwrite_live_values() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let restore = manager.prepare_restore(&result.backup_id).unwrap();
        let other = StoredValue {
            kind: 1,
            bytes: original().bytes,
        };
        store.0.borrow_mut().insert("Example".into(), other.clone());
        assert!(manager.apply(&restore.token).is_err());
        assert_eq!(store.read("Example").unwrap(), Some(other));
        assert_eq!(manager.inventory().unwrap().backups[0].state, "conflict");
        store.0.borrow_mut().clear();
        let restore = manager.prepare_restore(&result.backup_id).unwrap();
        fs::write(
            dir.path().join(format!("{}.json", result.backup_id)),
            "corrupted",
        )
        .unwrap();
        assert!(manager.apply(&restore.token).is_err());
        assert!(store.read("Example").unwrap().is_none());
        assert_eq!(manager.inventory().unwrap().warnings.len(), 1);
    }
    #[test]
    fn cancellation_expiry_wrong_tokens_and_path_traversal_cannot_apply_changes() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        manager.prepare_quarantine(&entry()).unwrap();
        assert!(manager.apply("wrong-token").is_err());
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        manager.cancel();
        assert!(manager.apply(&plan.token).is_err());
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        manager.pending.as_mut().unwrap().plan.expires_at = 0;
        assert!(manager.apply(&plan.token).is_err());
        assert!(manager.prepare_restore("../outside").is_err());
        assert_eq!(store.read("Example").unwrap(), Some(original()));
    }

    #[test]
    fn valid_json_with_changed_backup_bytes_fails_integrity_verification() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let plan = manager.prepare_quarantine(&entry()).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let path = dir.path().join(format!("{}.json", result.backup_id));
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        json["original"]["bytes"][0] = serde_json::json!(68);
        fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(manager
            .prepare_restore(&result.backup_id)
            .unwrap_err()
            .contains("integrity"));
        assert!(store.read("Example").unwrap().is_none());
    }

    fn app_entry() -> RegistryEntry {
        let mut record = entry();
        record.category = Category::AppPaths;
        record.name = "broken.exe".into();
        record.key_path = format!("{APP_PATHS_KEY}\\broken.exe");
        record.value_name.clear();
        record.app_path_guard = Some(AppPathGuard {
            values: vec![NamedValue {
                name: "Path".into(),
                value: StoredValue {
                    kind: 2,
                    bytes: vec![65, 0, 0, 0],
                },
            }],
        });
        record.app_path_repairable = true;
        record
    }

    fn app_setup(path: &Path) -> (Memory, Rc<Cell<ProbeResult>>, ChangeManager<Memory, Probe>) {
        let (store, state, manager) = setup(path);
        store.1.borrow_mut().insert(
            "broken.exe".into(),
            AppPathState {
                value: Some(original()),
                guard: app_entry().app_path_guard.unwrap(),
            },
        );
        (store, state, manager)
    }

    #[test]
    fn app_path_repair_and_restart_restore_preserve_default_bytes_and_other_values() {
        let dir = tempfile::tempdir().unwrap();
        let (store, state, mut manager) = app_setup(dir.path());
        let before = store.read_app_path("broken.exe").unwrap();
        let plan = manager.prepare_quarantine(&app_entry()).unwrap();
        assert_eq!(plan.scope, "app_path");
        assert_eq!(plan.value_name, "");
        assert_eq!(store.read_app_path("broken.exe").unwrap(), before);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        let result = manager.apply(&plan.token).unwrap();
        let disabled = store.read_app_path("broken.exe").unwrap();
        assert_eq!(disabled.value, None);
        assert_eq!(disabled.guard, before.guard);
        let mut reopened = ChangeManager::new(store.clone(), dir.path().into(), Probe(state));
        let restore = reopened.prepare_restore(&result.backup_id).unwrap();
        reopened.apply(&restore.token).unwrap();
        assert_eq!(store.read_app_path("broken.exe").unwrap(), before);
    }

    #[test]
    fn app_path_metadata_changes_before_apply_and_restore_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = app_setup(dir.path());
        let plan = manager.prepare_quarantine(&app_entry()).unwrap();
        store
            .1
            .borrow_mut()
            .get_mut("broken.exe")
            .unwrap()
            .guard
            .values
            .clear();
        assert!(manager
            .apply(&plan.token)
            .unwrap_err()
            .contains("metadata changed"));
        assert!(store.read_app_path("broken.exe").unwrap().value.is_some());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        store.1.borrow_mut().get_mut("broken.exe").unwrap().guard =
            app_entry().app_path_guard.unwrap();
        let plan = manager.prepare_quarantine(&app_entry()).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let restore = manager.prepare_restore(&result.backup_id).unwrap();
        store
            .1
            .borrow_mut()
            .get_mut("broken.exe")
            .unwrap()
            .guard
            .values
            .clear();
        assert!(manager
            .apply(&restore.token)
            .unwrap_err()
            .contains("metadata changed"));
        assert!(store.read_app_path("broken.exe").unwrap().value.is_none());
        assert!(manager.prepare_restore(&result.backup_id).is_err());
    }

    #[test]
    fn app_path_rejects_conflicting_restore_and_unsupported_selectors() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = app_setup(dir.path());
        let plan = manager.prepare_quarantine(&app_entry()).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let restore = manager.prepare_restore(&result.backup_id).unwrap();
        let other = StoredValue {
            kind: 1,
            bytes: original().bytes,
        };
        store.1.borrow_mut().get_mut("broken.exe").unwrap().value = Some(other.clone());
        assert!(manager.apply(&restore.token).is_err());
        assert_eq!(
            store.read_app_path("broken.exe").unwrap().value,
            Some(other)
        );
        for key in [
            format!("{APP_PATHS_KEY}\\..\\Run"),
            format!("{APP_PATHS_KEY}\\nested\\app.exe"),
            format!("{APP_PATHS_KEY}\\not-an-executable"),
            format!("{APP_PATHS_KEY}Extra\\app.exe"),
        ] {
            let mut record = app_entry();
            record.key_path = key;
            assert!(manager.prepare_quarantine(&record).is_err());
        }
        let mut record = app_entry();
        record.app_path_guard = None;
        assert!(manager.prepare_quarantine(&record).is_err());
        record = app_entry();
        record.hive = "HKLM".into();
        assert!(manager.prepare_quarantine(&record).is_err());
    }

    #[test]
    fn app_path_does_not_repair_an_extensionless_mapping_with_shell_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = app_setup(dir.path());
        let mut record = app_entry();
        record.raw_value = r"C:\Missing\app".into();
        let value = StoredValue {
            kind: 1,
            bytes: record
                .raw_value
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        record.snapshot = Some(value.clone());
        store.1.borrow_mut().get_mut("broken.exe").unwrap().value = Some(value);
        assert!(manager.prepare_quarantine(&record).is_err());
    }

    #[test]
    fn restores_unchanged_v011_backup_format_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        store.0.borrow_mut().clear();
        let id = "11111111-1111-4111-8111-111111111111";
        let legacy = include_str!("../tests/fixtures/startup-backup-v1.json");
        let path = dir.path().join(format!("{id}.json"));
        fs::write(&path, legacy).unwrap();
        assert_eq!(manager.inventory().unwrap().backups[0].scope, "startup");
        let plan = manager.prepare_restore(id).unwrap();
        manager.apply(&plan.token).unwrap();
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        assert_eq!(fs::read_to_string(path).unwrap(), legacy);
    }

    #[test]
    fn app_path_guard_is_covered_by_backup_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, mut manager) = app_setup(dir.path());
        let plan = manager.prepare_quarantine(&app_entry()).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let path = dir.path().join(format!("{}.json", result.backup_id));
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        json["appPath"]["executable"] = serde_json::json!("different.exe");
        fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(manager
            .prepare_restore(&result.backup_id)
            .unwrap_err()
            .contains("integrity"));
    }

    #[test]
    fn app_path_guard_refuses_links_duplicates_and_excessive_metadata() {
        let value = NamedValue {
            name: "Path".into(),
            value: StoredValue {
                kind: 1,
                bytes: vec![65, 0],
            },
        };
        for values in [
            vec![NamedValue {
                value: StoredValue {
                    kind: 6,
                    bytes: vec![65, 0],
                },
                ..value.clone()
            }],
            vec![
                value.clone(),
                NamedValue {
                    name: "PATH".into(),
                    ..value.clone()
                },
            ],
            vec![NamedValue {
                value: StoredValue {
                    kind: 1,
                    bytes: vec![0; 16_385],
                },
                ..value.clone()
            }],
            (0..33)
                .map(|i| NamedValue {
                    name: format!("Value{i}"),
                    ..value.clone()
                })
                .collect(),
        ] {
            assert!(AppPathGuard { values }.validate().is_err());
        }
    }

    fn uninstall_entry(snapshot: UninstallSnapshot) -> RegistryEntry {
        let mut record = entry();
        record.category = Category::Uninstall;
        record.name = snapshot.text("DisplayName").unwrap();
        record.key_path = format!("{UNINSTALL_KEY}\\ExampleUninstall");
        record.value_name = "InstallLocation".into();
        record.raw_value = snapshot.text("InstallLocation").unwrap();
        record.snapshot = None;
        record.uninstall_snapshot = Some(snapshot);
        record.uninstall_repairable = true;
        record
    }

    #[test]
    fn uninstall_full_backup_hide_restart_and_restore_preserve_every_original_value() {
        for component in [None, Some(0)] {
            let dir = tempfile::tempdir().unwrap();
            let (store, state, mut manager) = setup(dir.path());
            let original = crate::uninstall::fixture_snapshot(component);
            store
                .2
                .borrow_mut()
                .insert("ExampleUninstall".into(), original.clone());
            let plan = manager
                .prepare_quarantine(&uninstall_entry(original.clone()))
                .unwrap();
            assert_eq!(plan.scope, "uninstall");
            assert_eq!(plan.value_name, COMPONENT);
            assert_eq!(plan.value_type, "REG_DWORD");
            assert_eq!(plan.component_was_present, component.is_some());
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
            assert_eq!(store.read_uninstall("ExampleUninstall").unwrap(), original);
            let result = manager.apply(&plan.token).unwrap();
            assert_eq!(
                store.read_uninstall("ExampleUninstall").unwrap(),
                original.hidden().unwrap()
            );
            let path = dir.path().join(format!("{}.json", result.backup_id));
            let backup_text = fs::read_to_string(&path).unwrap();
            let backup: serde_json::Value = serde_json::from_str(&backup_text).unwrap();
            assert_eq!(backup["schemaVersion"], 3);
            assert_eq!(
                backup["uninstall"]["snapshot"],
                serde_json::to_value(&original).unwrap()
            );
            let mut reopened = ChangeManager::new(store.clone(), dir.path().into(), Probe(state));
            let restore = reopened.prepare_restore(&result.backup_id).unwrap();
            reopened.apply(&restore.token).unwrap();
            assert_eq!(store.read_uninstall("ExampleUninstall").unwrap(), original);
            assert_eq!(fs::read_to_string(path).unwrap(), backup_text);
        }
    }
    #[test]
    fn uninstall_stale_metadata_target_reappearance_and_backup_failure_block_changes() {
        for failure in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("backups");
            let (store, state, mut manager) = setup(&path);
            let original = crate::uninstall::fixture_snapshot(None);
            store
                .2
                .borrow_mut()
                .insert("ExampleUninstall".into(), original.clone());
            let plan = manager
                .prepare_quarantine(&uninstall_entry(original.clone()))
                .unwrap();
            if failure == 0 {
                store
                    .2
                    .borrow_mut()
                    .get_mut("ExampleUninstall")
                    .unwrap()
                    .values[0]
                    .value
                    .bytes
                    .push(1);
            }
            if failure == 1 {
                state.set(ProbeResult::Found);
            }
            if failure == 2 {
                fs::write(&path, "occupied").unwrap();
            }
            assert!(manager.apply(&plan.token).is_err());
            assert!(!store
                .read_uninstall("ExampleUninstall")
                .unwrap()
                .is_hidden());
        }
    }
    #[test]
    fn uninstall_restore_blocks_metadata_changes_missing_keys_and_corrupted_backups() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let original = crate::uninstall::fixture_snapshot(None);
        store
            .2
            .borrow_mut()
            .insert("ExampleUninstall".into(), original.clone());
        let plan = manager
            .prepare_quarantine(&uninstall_entry(original.clone()))
            .unwrap();
        let result = manager.apply(&plan.token).unwrap();
        let restore = manager.prepare_restore(&result.backup_id).unwrap();
        store
            .2
            .borrow_mut()
            .get_mut("ExampleUninstall")
            .unwrap()
            .values[0]
            .value
            .bytes
            .push(1);
        assert!(manager.apply(&restore.token).is_err());
        store.2.borrow_mut().clear();
        assert!(manager.prepare_restore(&result.backup_id).is_err());
        store
            .2
            .borrow_mut()
            .insert("ExampleUninstall".into(), original.hidden().unwrap());
        let path = dir.path().join(format!("{}.json", result.backup_id));
        let mut backup: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        backup["uninstall"]["keyName"] = serde_json::json!("OtherEntry");
        fs::write(path, serde_json::to_vec(&backup).unwrap()).unwrap();
        assert!(manager
            .prepare_restore(&result.backup_id)
            .unwrap_err()
            .contains("integrity"));
        assert!(store
            .read_uninstall("ExampleUninstall")
            .unwrap()
            .is_hidden());
    }

    #[test]
    fn restores_unchanged_v012_app_path_backup_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = app_setup(dir.path());
        store.1.borrow_mut().get_mut("broken.exe").unwrap().value = None;
        let id = "22222222-2222-4222-8222-222222222222";
        let legacy = include_str!("../tests/fixtures/app-path-backup-v2.json");
        let path = dir.path().join(format!("{id}.json"));
        fs::write(&path, legacy).unwrap();
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "app_path");
        manager.apply(&plan.token).unwrap();
        assert_eq!(
            store.read_app_path("broken.exe").unwrap().value,
            Some(original())
        );
        assert_eq!(fs::read_to_string(path).unwrap(), legacy);
    }
    #[test]
    fn restores_unchanged_v013_uninstall_backup_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let original = crate::uninstall::fixture_snapshot(None);
        store
            .2
            .borrow_mut()
            .insert("ExampleUninstall".into(), original.hidden().unwrap());
        let id = "33333333-3333-4333-8333-333333333333";
        let legacy = include_str!("../tests/fixtures/uninstall-backup-v3.json");
        let path = dir.path().join(format!("{id}.json"));
        fs::write(&path, legacy).unwrap();
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "uninstall");
        manager.apply(&plan.token).unwrap();
        assert_eq!(store.read_uninstall("ExampleUninstall").unwrap(), original);
        assert_eq!(fs::read_to_string(path).unwrap(), legacy);
    }
    #[test]
    fn restores_unchanged_v014_association_backup_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let guard = crate::associations::AssociationGuard {
            suggestions: vec![],
            extension_values: vec![],
            machine_extension_values: None,
            user_choice: None,
        };
        store.3.borrow_mut().insert(
            (".rrlegacy".into(), "Example.Document".into()),
            AssociationState { value: None, guard },
        );
        let id = "44444444-4444-4444-8444-444444444444";
        let legacy = include_str!("../tests/fixtures/association-backup-v4.json");
        let path = dir.path().join(format!("{id}.json"));
        fs::write(&path, legacy).unwrap();
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "association");
        manager.apply(&plan.token).unwrap();
        assert_eq!(
            store
                .read_association(".rrlegacy", "Example.Document")
                .unwrap()
                .value,
            Some(StoredValue {
                kind: 0,
                bytes: vec![]
            })
        );
        assert_eq!(fs::read_to_string(path).unwrap(), legacy);
    }
    #[test]
    fn cleaning_review_cancel_and_tokens_do_not_create_backups_or_mutate_values() {
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        let (store, _, mut manager) = setup(&backups);
        let review = manager.prepare_clean(&[entry()], "quick").unwrap();
        assert_eq!(review.items.len(), 1);
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        assert!(!backups.exists());
        manager.cancel();
        assert!(manager.apply_clean(&review.token).is_err());
        assert!(!backups.exists());
        let review = manager.prepare_clean(&[entry()], "selected").unwrap();
        assert!(manager.apply_clean("wrong-token").is_err());
        assert!(manager.apply_clean(&review.token).is_err());
        assert!(manager
            .prepare_clean(&[entry(), entry()], "selected")
            .is_err());
        assert!(!backups.exists());
    }
    #[test]
    fn cleaning_stops_at_a_conflict_and_keeps_completed_changes_individually_restorable() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let mut second = entry();
        second.id = "second".into();
        second.name = "Second".into();
        second.value_name = "Second".into();
        let mut third = second.clone();
        third.id = "third".into();
        third.name = "Third".into();
        third.value_name = "Third".into();
        for name in ["Second", "Third"] {
            store.0.borrow_mut().insert(name.into(), original());
        }
        let review = manager
            .prepare_clean(&[entry(), second, third], "selected")
            .unwrap();
        assert_eq!(review.items.len(), 3);
        let conflict = StoredValue {
            kind: 1,
            bytes: "C:\\Keep\\existing.exe\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        store
            .0
            .borrow_mut()
            .insert("Second".into(), conflict.clone());
        let result = manager.apply_clean(&review.token).unwrap();
        assert_eq!(result.completed.len(), 1);
        assert_eq!(result.failed.unwrap().name, "Second");
        assert_eq!(result.not_attempted, 1);
        assert_eq!(store.read("Example").unwrap(), None);
        assert_eq!(store.read("Second").unwrap(), Some(conflict));
        assert_eq!(store.read("Third").unwrap(), Some(original()));
        let restore = manager
            .prepare_restore(&result.completed[0].backup_id)
            .unwrap();
        manager.apply(&restore.token).unwrap();
        assert_eq!(store.read("Example").unwrap(), Some(original()));
    }
    #[test]
    fn cleaning_skips_ineligible_entries_and_enforces_expiry_and_size_limits() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let mut machine = entry();
        machine.id = "machine".into();
        machine.hive = "HKLM".into();
        let review = manager.prepare_clean(&[entry(), machine], "quick").unwrap();
        assert_eq!(review.items.len(), 1);
        assert_eq!(review.skipped.len(), 1);
        manager.batch_pending.as_mut().unwrap().plan.expires_at = 0;
        assert!(manager.apply_clean(&review.token).is_err());
        assert_eq!(store.read("Example").unwrap(), Some(original()));
        assert!(manager.prepare_clean(&vec![entry(); 101], "quick").is_err());
        assert!(manager.prepare_clean(&[], "selected").is_err());
    }
    #[test]
    fn cleaning_defers_sibling_suggestions_to_keep_metadata_guards_independent() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let original = StoredValue {
            kind: 0,
            bytes: vec![],
        };
        let names = ["Example.First", "Example.Second"];
        let mut entries = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let state = AssociationState {
                value: Some(original.clone()),
                guard: crate::associations::AssociationGuard {
                    suggestions: vec![NamedValue {
                        name: names[1 - index].into(),
                        value: original.clone(),
                    }],
                    extension_values: vec![],
                    machine_extension_values: None,
                    user_choice: None,
                },
            };
            store
                .3
                .borrow_mut()
                .insert((".rrexample".into(), (*name).into()), state.clone());
            let mut item = entry();
            item.id = (*name).into();
            item.name = (*name).into();
            item.category = Category::FileAssociations;
            item.key_path = format!("{CLASSES_KEY}\\.rrexample\\{OPEN_WITH}");
            item.value_name = (*name).into();
            item.raw_value = "(empty)".into();
            item.assessment.code = "progid_missing".into();
            item.association_state = Some(state);
            item.association_repairable = true;
            entries.push(item);
        }
        let plan = manager.prepare_clean(&entries, "selected").unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.skipped.len(), 1);
        let result = manager.apply_clean(&plan.token).unwrap();
        assert_eq!(result.completed.len(), 1);
        assert!(result.failed.is_none());
        assert!(store
            .read_association(".rrexample", names[0])
            .unwrap()
            .value
            .is_none());
        assert_eq!(
            store
                .read_association(".rrexample", names[1])
                .unwrap()
                .value,
            Some(original)
        );
    }
    fn service_entry(snapshot: ServiceSnapshot) -> RegistryEntry {
        let mut record = entry();
        record.id = "service".into();
        record.name = "Example service".into();
        record.category = Category::Services;
        record.hive = "HKLM".into();
        record.key_path = format!("{SERVICES_KEY}\\ExampleService");
        record.value_name = "ImagePath".into();
        record.raw_value = snapshot.config.binary_path.clone();
        record.snapshot = None;
        record.service_state = Some(ServiceState {
            snapshot,
            stopped: true,
            has_dependents: false,
            change_allowed: true,
        });
        record.service_repairable = true;
        record
    }
    #[test]
    fn service_quick_clean_backup_restart_and_restore_preserve_full_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        let (store, _, mut manager) = setup(&backups);
        let snapshot = crate::services::fixture_snapshot();
        let entry = service_entry(snapshot.clone());
        store.4.borrow_mut().insert(
            "ExampleService".into(),
            entry.service_state.clone().unwrap(),
        );
        assert!(is_repair_candidate(&entry));
        let plan = manager
            .prepare_clean(std::slice::from_ref(&entry), "quick")
            .unwrap();
        assert_eq!(plan.items[0].scope, "service");
        assert!(!backups.exists());
        manager.cancel();
        assert!(manager.apply_clean(&plan.token).is_err());
        let plan = manager.prepare_clean(&[entry], "quick").unwrap();
        let result = manager.apply_clean(&plan.token).unwrap();
        assert!(result.failed.is_none());
        assert_eq!(result.completed.len(), 1);
        assert_eq!(
            store.read_service("ExampleService").unwrap().snapshot,
            snapshot.disabled().unwrap()
        );
        let id = &result.completed[0].backup_id;
        let path = backups.join(format!("{id}.json"));
        let record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(record["schemaVersion"], 6);
        assert_eq!(
            record["service"]["snapshot"],
            serde_json::to_value(&snapshot).unwrap()
        );
        drop(manager);
        let mut manager = ChangeManager::new(
            store.clone(),
            backups,
            Probe(Rc::new(Cell::new(ProbeResult::Missing))),
        );
        let restore = manager.prepare_restore(id).unwrap();
        manager.apply(&restore.token).unwrap();
        let state = store.read_service("ExampleService").unwrap();
        assert_eq!(state.snapshot, snapshot);
        assert!(state.stopped);
    }
    #[test]
    fn service_repair_refuses_status_rights_dependency_target_and_backup_conflicts() {
        for scenario in 0..6 {
            let dir = tempfile::tempdir().unwrap();
            let backups = dir.path().join("backups");
            let (store, probe, mut manager) = setup(&backups);
            let entry = service_entry(crate::services::fixture_snapshot());
            store.4.borrow_mut().insert(
                "ExampleService".into(),
                entry.service_state.clone().unwrap(),
            );
            let plan = manager.prepare_quarantine(&entry).unwrap();
            match scenario {
                0 => {
                    store
                        .4
                        .borrow_mut()
                        .get_mut("ExampleService")
                        .unwrap()
                        .stopped = false
                }
                1 => {
                    store
                        .4
                        .borrow_mut()
                        .get_mut("ExampleService")
                        .unwrap()
                        .change_allowed = false
                }
                2 => {
                    store
                        .4
                        .borrow_mut()
                        .get_mut("ExampleService")
                        .unwrap()
                        .has_dependents = true
                }
                3 => store
                    .4
                    .borrow_mut()
                    .get_mut("ExampleService")
                    .unwrap()
                    .snapshot
                    .config
                    .security
                    .push(1),
                4 => probe.set(ProbeResult::Found),
                5 => fs::write(&backups, b"not a directory").unwrap(),
                _ => unreachable!(),
            }
            assert!(manager.apply(&plan.token).is_err(), "scenario {scenario}");
            assert_eq!(
                store
                    .read_service("ExampleService")
                    .unwrap()
                    .snapshot
                    .config
                    .start_type,
                3
            );
        }
    }
    #[test]
    fn service_restore_rejects_changed_security_missing_services_and_corrupted_backups() {
        for scenario in 0..5 {
            let dir = tempfile::tempdir().unwrap();
            let (store, _, mut manager) = setup(dir.path());
            let entry = service_entry(crate::services::fixture_snapshot());
            store.4.borrow_mut().insert(
                "ExampleService".into(),
                entry.service_state.clone().unwrap(),
            );
            let plan = manager.prepare_quarantine(&entry).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            match scenario {
                0 => store
                    .4
                    .borrow_mut()
                    .get_mut("ExampleService")
                    .unwrap()
                    .snapshot
                    .config
                    .security
                    .push(1),
                1 => {
                    store
                        .4
                        .borrow_mut()
                        .get_mut("ExampleService")
                        .unwrap()
                        .stopped = false
                }
                2 => {
                    store
                        .4
                        .borrow_mut()
                        .get_mut("ExampleService")
                        .unwrap()
                        .change_allowed = false
                }
                3 => {
                    store.4.borrow_mut().clear();
                }
                4 => {
                    let path = dir.path().join(format!("{}.json", result.backup_id));
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    record["service"]["serviceName"] = serde_json::json!("OtherService");
                    fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                manager.prepare_restore(&result.backup_id).is_err(),
                "scenario {scenario}"
            );
            if scenario != 3 {
                assert_eq!(
                    store
                        .read_service("ExampleService")
                        .unwrap()
                        .snapshot
                        .config
                        .start_type,
                    4
                );
            }
        }
    }
    #[test]
    fn restores_unchanged_v015_com_backup_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let id = "55555555-5555-4555-8555-555555555555";
        let clsid = "{55555555-5555-4555-8555-555555555555}";
        let guard = crate::com::ComGuard {
            class_values: vec![],
            server_values: vec![],
        };
        store
            .5
            .borrow_mut()
            .insert(clsid.into(), ComState { value: None, guard });
        let legacy = include_str!("../tests/fixtures/com-backup-v5.json");
        let path = dir.path().join(format!("{id}.json"));
        fs::write(&path, legacy).unwrap();
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "com");
        manager.apply(&plan.token).unwrap();
        assert_eq!(
            store
                .read_com(clsid, INPROC_SERVER)
                .unwrap()
                .value
                .unwrap()
                .text()
                .unwrap(),
            r"C:\RustRegistryMissing\server.dll"
        );
        assert_eq!(fs::read_to_string(path).unwrap(), legacy);
    }
    #[test]
    fn restores_unchanged_v017_com_backup_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, mut manager) = setup(dir.path());
        let id = "77777777-7777-4777-8777-777777777777";
        let clsid = "{77777777-7777-4777-8777-777777777777}";
        let guard = crate::com::ComGuard {
            class_values: vec![],
            server_values: vec![],
        };
        store
            .5
            .borrow_mut()
            .insert(clsid.into(), ComState { value: None, guard });
        let legacy = include_str!("../tests/fixtures/com-backup-v7.json");
        let path = dir.path().join(format!("{id}.json"));
        fs::write(&path, legacy).unwrap();
        let plan = manager.prepare_restore(id).unwrap();
        assert_eq!(plan.scope, "com");
        manager.apply(&plan.token).unwrap();
        assert_eq!(
            store
                .read_com(clsid, crate::com::INPROC_HANDLER)
                .unwrap()
                .value
                .unwrap()
                .text()
                .unwrap(),
            r"C:\RustRegistryMissing\server.dll"
        );
        assert_eq!(fs::read_to_string(path).unwrap(), legacy);
    }
}
