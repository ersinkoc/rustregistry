use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Startup,
    AppPaths,
    ApplicationCommands,
    ApplicationIcons,
    Uninstall,
    FileAssociations,
    Com,
    Services,
    SharedDlls,
    RegisteredApplications,
    TypeLibraries,
    ProgIds,
    Interfaces,
    ComProxies,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    Found,
    Review,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub status: EntryStatus,
    pub code: String,
    pub explanation: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryEntry {
    pub id: String,
    pub name: String,
    pub category: Category,
    pub hive: String,
    pub key_path: String,
    pub view: String,
    pub value_name: String,
    pub value_type: String,
    pub raw_value: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub assessment: Assessment,
    #[serde(skip)]
    pub snapshot: Option<crate::changes::StoredValue>,
    #[serde(skip)]
    pub app_path_guard: Option<crate::changes::AppPathGuard>,
    pub app_path_repairable: bool,
    #[serde(skip)]
    pub uninstall_snapshot: Option<crate::uninstall::UninstallSnapshot>,
    pub uninstall_repairable: bool,
    pub uninstall_hidden: bool,
    #[serde(skip)]
    pub association_state: Option<crate::associations::AssociationState>,
    pub association_repairable: bool,
    #[serde(skip)]
    pub com_state: Option<crate::com::ComState>,
    pub com_repairable: bool,
    #[serde(skip)]
    pub service_state: Option<crate::services::ServiceState>,
    pub service_repairable: bool,
    #[serde(skip)]
    pub application_snapshot: Option<crate::applications::ApplicationSnapshot>,
    pub application_repairable: bool,
    pub application_hidden: bool,
    pub shared_dll_repairable: bool,
    pub registered_app_repairable: bool,
    #[serde(skip)]
    pub type_library_state: Option<crate::type_libraries::TypeLibState>,
    #[serde(default)]
    pub type_library_repairable: bool,
    #[serde(skip)]
    pub prog_id_state: Option<crate::prog_ids::ProgIdState>,
    #[serde(default)]
    pub prog_id_repairable: bool,
    #[serde(skip)]
    pub interface_state: Option<crate::interfaces::InterfaceState>,
    #[serde(default)]
    pub interface_repairable: bool,
    #[serde(skip)]
    pub proxy_state: Option<crate::com_proxies::ProxyState>,
    #[serde(default)]
    pub proxy_repairable: bool,
    #[serde(skip)]
    pub icon_state: Option<crate::application_icons::IconState>,
    #[serde(default)]
    pub icon_repairable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeResult {
    pub id: String,
    pub category: Category,
    pub hive: String,
    pub key_path: String,
    pub view: String,
    pub status: String,
    pub entries: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub completed: usize,
    pub total: usize,
    pub entries: usize,
    pub current: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub id: String,
    pub started_at: u64,
    pub duration_ms: u64,
    pub cancelled: bool,
    pub read_only: bool,
    pub architecture: String,
    pub entries: Vec<RegistryEntry>,
    pub scopes: Vec<ScopeResult>,
}
