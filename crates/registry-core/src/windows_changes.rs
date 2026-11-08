#[path = "windows_menus.rs"]
mod menus;
pub(crate) use menus::open_menu_source;
#[path = "windows_icons.rs"]
mod icons;
pub(crate) use icons::open_icon_child;
#[path = "windows_conversions.rs"]
mod conversions;
#[path = "windows_maintenance.rs"]
mod maintenance;
pub(crate) use maintenance::{open_maintenance_source, read_maintenance_snapshot};
#[path = "windows_interfaces.rs"]
mod interfaces;
#[path = "windows_proxies.rs"]
mod proxies;
#[path = "windows_redirects.rs"]
mod redirections;
pub(crate) use interfaces::open_interface_child;
#[path = "windows_applications.rs"]
mod applications;
#[path = "windows_associations.rs"]
mod associations;
#[path = "windows_com.rs"]
mod com;
#[path = "windows_prog_ids.rs"]
mod prog_ids;
#[path = "windows_registered_apps.rs"]
mod registered_apps;
#[path = "windows_services.rs"]
mod services;
#[path = "windows_shared_dlls.rs"]
mod shared_dlls;
#[path = "windows_type_libraries.rs"]
mod type_libraries;
use crate::changes::{
    validate_app_path_name, validate_value_name, AppPathGuard, AppPathState, NamedValue,
    RegistryStore, StoredValue, APP_PATHS_KEY, STARTUP_KEY,
};
use crate::uninstall::{validate_uninstall_name, UninstallSnapshot, COMPONENT, UNINSTALL_KEY};
pub(crate) use prog_ids::open_prog_id_child;
pub(crate) use registered_apps::open_registration_path;
use std::borrow::Cow;
pub(crate) use type_libraries::open_type_lib;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

pub struct WindowsRegistryStore {
    #[cfg(test)]
    maintenance_test_root: Option<String>,
    path: String,
    app_paths_path: String,
    uninstall_path: String,
    #[cfg(test)]
    icon_test_machine_user: bool,
    #[cfg(test)]
    menu_test_machine_user: bool,
    classes_path: String,
    machine_classes_path: String,
    file_exts_path: String,
    #[cfg(test)]
    redirection_test_machine_user: bool,
    #[cfg(test)]
    redirection_test_user32: Option<String>,
    com_path: String,
    machine_com_path: String,
    services_path: String,
    registered_app_path: String,
    machine_registered_app_path: String,
    #[cfg(test)]
    registered_app_test_machine: Option<String>,
    interfaces_path: String,
    machine_interfaces_path: String,
    interface_libraries_path: String,
    machine_interface_libraries_path: String,
    #[cfg(test)]
    interface_test_machine_user: bool,
    prog_ids_path: String,
    machine_prog_ids_path: String,
    #[cfg(test)]
    prog_id_test_machine_user: bool,
    type_lib_path: String,
    machine_type_lib_path: String,
    #[cfg(test)]
    type_lib_test_machine_user: bool,
    shared_dll_path: String,
    #[cfg(test)]
    shared_dll_test_user: bool,
}
impl Default for WindowsRegistryStore {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            maintenance_test_root: None,
            path: STARTUP_KEY.into(),
            app_paths_path: APP_PATHS_KEY.into(),
            uninstall_path: UNINSTALL_KEY.into(),
            #[cfg(test)]
            icon_test_machine_user: false,
            #[cfg(test)]
            menu_test_machine_user: false,
            classes_path: crate::associations::CLASSES_KEY.into(),
            machine_classes_path: crate::associations::CLASSES_KEY.into(),
            file_exts_path: crate::associations::FILE_EXTS_KEY.into(),
            #[cfg(test)]
            redirection_test_machine_user: false,
            #[cfg(test)]
            redirection_test_user32: None,
            com_path: crate::com::CLSID_KEY.into(),
            machine_com_path: crate::com::CLSID_KEY.into(),
            services_path: crate::services::SERVICES_KEY.into(),
            registered_app_path: crate::registered_apps::REGISTERED_APPS_KEY.into(),
            machine_registered_app_path: crate::registered_apps::REGISTERED_APPS_KEY.into(),
            #[cfg(test)]
            registered_app_test_machine: None,
            interfaces_path: crate::interfaces::INTERFACES_KEY.into(),
            machine_interfaces_path: crate::interfaces::INTERFACES_KEY.into(),
            interface_libraries_path: crate::type_libraries::TYPE_LIB_KEY.into(),
            machine_interface_libraries_path: crate::type_libraries::TYPE_LIB_KEY.into(),
            #[cfg(test)]
            interface_test_machine_user: false,
            prog_ids_path: crate::prog_ids::PROG_IDS_KEY.into(),
            machine_prog_ids_path: crate::prog_ids::PROG_IDS_KEY.into(),
            #[cfg(test)]
            prog_id_test_machine_user: false,
            type_lib_path: crate::type_libraries::TYPE_LIB_KEY.into(),
            machine_type_lib_path: crate::type_libraries::TYPE_LIB_KEY.into(),
            #[cfg(test)]
            type_lib_test_machine_user: false,
            shared_dll_path: crate::shared_dlls::SHARED_DLLS_KEY.into(),
            #[cfg(test)]
            shared_dll_test_user: false,
        }
    }
}

pub(crate) fn read_uninstall_snapshot(key: &RegKey) -> Result<UninstallSnapshot, String> {
    if key.enum_keys().next().is_some() {
        return Err(
            "Uninstall entries with child keys or unreadable metadata cannot be repaired.".into(),
        );
    }
    let mut values = Vec::new();
    let mut size = 0;
    for item in key.enum_values() {
        let (name, value) =
            item.map_err(|_| "Uninstall metadata could not be read completely.".to_string())?;
        size += value.bytes.len();
        if values.len() >= 64 || size > 32_768 {
            return Err("Uninstall metadata exceeds the supported backup limits.".into());
        }
        values.push(NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        });
    }
    values.sort_by_key(|item| item.name.to_lowercase());
    let snapshot = UninstallSnapshot { values };
    snapshot.validate()?;
    for name in [
        COMPONENT,
        "WindowsInstaller",
        "NoRemove",
        "ParentKeyName",
        "ParentDisplayName",
        "ReleaseType",
        "DisplayName",
        "InstallLocation",
        "UninstallString",
        "QuietUninstallString",
    ] {
        if read_value(key, name)?.as_ref() != snapshot.get(name) {
            return Err("Uninstall field aliases are ambiguous. Repair is blocked.".into());
        }
    }
    Ok(snapshot)
}

pub(crate) fn read_app_path_guard(key: &RegKey) -> Result<AppPathGuard, String> {
    if key.enum_keys().next().is_some() {
        return Err(
            "App Paths entries with child keys or unreadable metadata cannot be repaired.".into(),
        );
    }
    let mut values = Vec::new();
    let mut size = 0;
    for item in key.enum_values() {
        let (name, value) =
            item.map_err(|_| "App Paths metadata could not be read completely.".to_string())?;
        if name.is_empty() {
            continue;
        }
        size += value.bytes.len();
        if values.len() >= 32 || size > 16_384 {
            return Err("App Paths metadata exceeds the supported backup limits.".into());
        }
        values.push(NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        });
    }
    values.sort_by_key(|value| value.name.to_lowercase());
    let guard = AppPathGuard { values };
    guard.validate()?;
    Ok(guard)
}

fn read_app_state(key: &RegKey) -> Result<AppPathState, String> {
    Ok(AppPathState {
        value: read_value(key, "")?,
        guard: read_app_path_guard(key)?,
    })
}
fn read_value(key: &RegKey, name: &str) -> Result<Option<StoredValue>, String> {
    match key.get_raw_value(name) {
        Ok(value) => Ok(Some(StoredValue {
            kind: value.vtype as u32,
            bytes: value.bytes.into_owned(),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "Cannot read the registry value (Windows error {}).",
            error.raw_os_error().unwrap_or(0)
        )),
    }
}
impl RegistryStore for WindowsRegistryStore {
    fn read_maintenance_batch(
        &self,
        apps: &[crate::maintenance::MaintenanceBackup],
    ) -> Vec<Result<crate::maintenance::MaintenanceSnapshot, String>> {
        self.maintenance_batch(apps)
    }
    fn read_maintenance(
        &self,
        app: &crate::maintenance::MaintenanceBackup,
    ) -> Result<crate::maintenance::MaintenanceSnapshot, String> {
        self.maintenance_state(app)
    }
    fn check_maintenance_write_access(
        &self,
        app: &crate::maintenance::MaintenanceBackup,
    ) -> Result<(), String> {
        self.maintenance_access(app)
    }
    fn compare_exchange_maintenance(
        &self,
        app: &crate::maintenance::MaintenanceBackup,
        expected: &crate::maintenance::MaintenanceSnapshot,
        replacement: &crate::maintenance::MaintenanceSnapshot,
    ) -> Result<(), String> {
        self.exchange_maintenance(app, expected, replacement)
    }

    fn read_conversion(
        &self,
        app: &crate::com_conversions::ConversionBackup,
    ) -> Result<crate::com_conversions::ConversionState, String> {
        self.conversion_state(app)
    }
    fn check_conversion_write_access(
        &self,
        app: &crate::com_conversions::ConversionBackup,
    ) -> Result<(), String> {
        self.conversion_write_access(app)
    }
    fn compare_exchange_conversion(
        &self,
        app: &crate::com_conversions::ConversionBackup,
        expected: &crate::com_conversions::ConversionState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_conversion(app, expected, replacement)
    }

    fn read_redirection(
        &self,
        app: &crate::com_redirects::RedirectionBackup,
    ) -> Result<crate::com_redirects::RedirectionState, String> {
        self.redirection_state(app)
    }
    fn check_redirection_write_access(
        &self,
        app: &crate::com_redirects::RedirectionBackup,
    ) -> Result<(), String> {
        self.redirection_write_access(app)
    }
    fn compare_exchange_redirection(
        &self,
        app: &crate::com_redirects::RedirectionBackup,
        expected: &crate::com_redirects::RedirectionState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_redirection(app, expected, replacement)
    }

    fn read_menu(
        &self,
        app: &crate::shell_menus::MenuBackup,
    ) -> Result<crate::shell_menus::MenuSnapshot, String> {
        self.menu_snapshot(app)
    }
    fn check_menu_write_access(&self, app: &crate::shell_menus::MenuBackup) -> Result<(), String> {
        self.menu_write_access(app)
    }
    fn set_menu_hidden(
        &self,
        app: &crate::shell_menus::MenuBackup,
        hidden: bool,
    ) -> Result<(), String> {
        self.change_menu_hidden(app, hidden)
    }

    fn read_proxy(
        &self,
        app: &crate::com_proxies::ProxyBackup,
    ) -> Result<crate::com_proxies::ProxyState, String> {
        self.proxy_state(app)
    }
    fn check_proxy_write_access(
        &self,
        app: &crate::com_proxies::ProxyBackup,
    ) -> Result<(), String> {
        self.proxy_write_access(app)
    }
    fn compare_exchange_proxy(
        &self,
        app: &crate::com_proxies::ProxyBackup,
        expected: &crate::com_proxies::ProxyState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_proxy(app, expected, replacement)
    }
    fn read_icon(
        &self,
        app: &crate::application_icons::IconBackup,
    ) -> Result<crate::application_icons::IconState, String> {
        self.icon_state(app)
    }
    fn check_icon_write_access(
        &self,
        app: &crate::application_icons::IconBackup,
    ) -> Result<(), String> {
        self.icon_write_access(app)
    }
    fn compare_exchange_icon(
        &self,
        app: &crate::application_icons::IconBackup,
        expected: &crate::application_icons::IconState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_icon(app, expected, replacement)
    }
    fn read_interface(
        &self,
        app: &crate::interfaces::InterfaceBackup,
    ) -> Result<crate::interfaces::InterfaceState, String> {
        self.interface_state(app)
    }
    fn check_interface_write_access(
        &self,
        app: &crate::interfaces::InterfaceBackup,
    ) -> Result<(), String> {
        self.interface_write_access(app)
    }
    fn compare_exchange_interface(
        &self,
        app: &crate::interfaces::InterfaceBackup,
        expected: &crate::interfaces::InterfaceState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_interface(app, expected, replacement)
    }
    fn read_prog_id(
        &self,
        app: &crate::prog_ids::ProgIdBackup,
    ) -> Result<crate::prog_ids::ProgIdState, String> {
        self.prog_id_state(app)
    }
    fn check_prog_id_write_access(
        &self,
        app: &crate::prog_ids::ProgIdBackup,
    ) -> Result<(), String> {
        self.prog_id_write_access(app)
    }
    fn compare_exchange_prog_id(
        &self,
        app: &crate::prog_ids::ProgIdBackup,
        expected: &crate::prog_ids::ProgIdState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_prog_id(app, expected, replacement)
    }

    fn read_type_library(
        &self,
        app: &crate::type_libraries::TypeLibBackup,
    ) -> Result<crate::type_libraries::TypeLibState, String> {
        self.type_lib_state(app)
    }
    fn check_type_library_write_access(
        &self,
        app: &crate::type_libraries::TypeLibBackup,
    ) -> Result<(), String> {
        self.type_lib_write_access(app)
    }
    fn compare_exchange_type_library(
        &self,
        app: &crate::type_libraries::TypeLibBackup,
        expected: &crate::type_libraries::TypeLibState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_type_lib(app, expected, replacement)
    }

    fn read_registered_app(
        &self,
        name: &str,
        original: &StoredValue,
    ) -> Result<Option<StoredValue>, String> {
        self.registration_value(name, original)
    }
    fn check_registered_app_write_access(&self) -> Result<(), String> {
        self.registration_write_access()
    }
    fn compare_exchange_registered_app(
        &self,
        name: &str,
        original: &StoredValue,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_registration(name, original, expected, replacement)
    }

    fn read_shared_dll(&self, path: &str) -> Result<Option<StoredValue>, String> {
        self.shared_dll_value(path)
    }
    fn check_shared_dll_write_access(&self) -> Result<(), String> {
        self.shared_dll_write_access()
    }
    fn compare_exchange_shared_dll(
        &self,
        path: &str,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_shared_dll(path, expected, replacement)
    }
    fn read_application(
        &self,
        name: &str,
    ) -> Result<crate::applications::ApplicationSnapshot, String> {
        self.application_state(name)
    }
    fn set_application_hidden(
        &self,
        name: &str,
        original: &crate::applications::ApplicationSnapshot,
        hide: bool,
    ) -> Result<(), String> {
        self.change_application_hidden(name, original, hide)
    }
    fn read_service(&self, name: &str) -> Result<crate::services::ServiceState, String> {
        self.service_state(name)
    }
    fn set_service_disabled(
        &self,
        name: &str,
        original: &crate::services::ServiceSnapshot,
        disabled: bool,
    ) -> Result<(), String> {
        self.change_service_start(name, original, disabled)
    }

    fn read_com(&self, clsid: &str, server: &str) -> Result<crate::com::ComState, String> {
        self.com_state(clsid, server)
    }
    fn compare_exchange_com(
        &self,
        clsid: &str,
        server: &str,
        expected: &crate::com::ComState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_com(clsid, server, expected, replacement)
    }

    fn read_association(
        &self,
        extension: &str,
        progid: &str,
    ) -> Result<crate::associations::AssociationState, String> {
        self.association_state(extension, progid)
    }
    fn compare_exchange_association(
        &self,
        extension: &str,
        progid: &str,
        expected: &crate::associations::AssociationState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        self.exchange_association(extension, progid, expected, replacement)
    }

    fn read_uninstall(&self, key_name: &str) -> Result<UninstallSnapshot, String> {
        validate_uninstall_name(key_name)?;
        let path = format!("{}\\{}", self.uninstall_path, key_name);
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_options_flags(path, REG_OPTION_OPEN_LINK, KEY_READ).map_err(|error| format!("Cannot read the existing current-user uninstall entry (Windows error {}). Its key is never recreated automatically.", error.raw_os_error().unwrap_or(0)))?;
        read_uninstall_snapshot(&key)
    }
    fn set_uninstall_hidden(
        &self,
        key_name: &str,
        original: &UninstallSnapshot,
        hide: bool,
    ) -> Result<(), String> {
        validate_uninstall_name(key_name)?;
        original.validate_original()?;
        let hidden = original.hidden()?;
        let expected = if hide { original } else { &hidden };
        if self.read_uninstall(key_name)? != *expected {
            return Err("The uninstall entry changed. Its visibility was not changed.".into());
        }
        let transaction = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        let path = format!("{}\\{}", self.uninstall_path, key_name);
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_transacted_with_flags(path, &transaction, KEY_READ | KEY_SET_VALUE).map_err(|error| format!("Cannot open the existing uninstall entry for a protected change (Windows error {}).", error.raw_os_error().unwrap_or(0)))?;
        if read_uninstall_snapshot(&key)? != *expected {
            return Err(
                "The uninstall entry changed before its transaction. Nothing was overwritten."
                    .into(),
            );
        }
        let component_name = original
            .values
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case(COMPONENT))
            .map_or(COMPONENT, |item| item.name.as_str());
        let value = if hide {
            Some(StoredValue {
                kind: 4,
                bytes: vec![1, 0, 0, 0],
            })
        } else {
            original.get(COMPONENT).cloned()
        };
        match value {
            Some(value) => key.set_raw_value(
                component_name,
                &RegValue {
                    bytes: Cow::Borrowed(&value.bytes),
                    vtype: REG_DWORD,
                },
            ),
            None => key.delete_value(COMPONENT),
        }
        .map_err(|error| {
            format!(
                "The uninstall visibility change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        transaction.commit().map_err(|error| format!("Windows did not commit the uninstall change (Windows error {}). The backup is preserved.", error.raw_os_error().unwrap_or(0)))
    }
    fn read_app_path(&self, executable: &str) -> Result<AppPathState, String> {
        validate_app_path_name(executable)?;
        let path = format!("{}\\{}", self.app_paths_path, executable);
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_options_flags(path, REG_OPTION_OPEN_LINK, KEY_READ).map_err(|error| format!("Cannot read the existing current-user App Paths entry (Windows error {}). Its key is never recreated automatically.", error.raw_os_error().unwrap_or(0)))?;
        read_app_state(&key)
    }

    fn compare_exchange_app_path(
        &self,
        executable: &str,
        expected: &AppPathState,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        validate_app_path_name(executable)?;
        expected.guard.validate()?;
        if expected.value.is_none() && replacement.is_none() {
            return Err("No App Paths change was requested.".into());
        }
        for value in [expected.value.as_ref(), replacement].into_iter().flatten() {
            value.text()?;
        }
        if self.read_app_path(executable)? != *expected {
            return Err(
                "The App Paths entry changed before its transaction. Nothing was changed.".into(),
            );
        }
        let transaction = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        let path = format!("{}\\{}", self.app_paths_path, executable);
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_transacted_with_flags(path, &transaction, KEY_READ | KEY_SET_VALUE).map_err(|error| format!("Cannot open the existing App Paths entry for a protected change (Windows error {}).", error.raw_os_error().unwrap_or(0)))?;
        if read_app_state(&key)? != *expected {
            return Err(
                "The App Paths value or its metadata changed. Nothing was overwritten or removed."
                    .into(),
            );
        }
        match replacement {
            Some(value) => key.set_raw_value(
                "",
                &RegValue {
                    bytes: Cow::Borrowed(&value.bytes),
                    vtype: if value.kind == 1 {
                        REG_SZ
                    } else {
                        REG_EXPAND_SZ
                    },
                },
            ),
            None => key.delete_value(""),
        }
        .map_err(|error| {
            format!(
                "The App Paths change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        transaction.commit().map_err(|error| format!("Windows did not commit the App Paths change (Windows error {}). The backup is preserved.", error.raw_os_error().unwrap_or(0)))
    }
    fn read(&self, name: &str) -> Result<Option<StoredValue>, String> {
        validate_value_name(name)?;
        let hive = RegKey::predef(HKEY_CURRENT_USER);
        match hive.open_subkey_with_flags(&self.path, KEY_QUERY_VALUE) {
            Ok(key) => read_value(&key, name),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!(
                "Cannot read the current user's Run key (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )),
        }
    }
    fn compare_exchange(
        &self,
        name: &str,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        validate_value_name(name)?;
        if expected.is_none() && replacement.is_none() {
            return Err("No supported change was requested.".into());
        }
        for value in [expected, replacement].into_iter().flatten() {
            value.text()?;
        }
        let transaction = Transaction::new().map_err(|_| {
            "Windows registry transactions are unavailable. Nothing was changed.".to_string()
        })?;
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_transacted_with_flags(
                &self.path,
                &transaction,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
            )
            .map_err(|error| {
                format!(
                    "Cannot open the existing Run key for a protected change (Windows error {}).",
                    error.raw_os_error().unwrap_or(0)
                )
            })?;
        if read_value(&key, name)?.as_ref() != expected {
            return Err(
                "The startup value changed. No existing value was overwritten or removed.".into(),
            );
        }
        match replacement {
            Some(value) => key.set_raw_value(
                name,
                &RegValue {
                    bytes: Cow::Borrowed(&value.bytes),
                    vtype: if value.kind == 1 {
                        REG_SZ
                    } else {
                        REG_EXPAND_SZ
                    },
                },
            ),
            None => key.delete_value(name),
        }
        .map_err(|error| {
            format!(
                "The protected change failed (Windows error {}).",
                error.raw_os_error().unwrap_or(0)
            )
        })?;
        transaction.commit().map_err(|error| {
            format!(
                "Windows did not commit the change (Windows error {}). The backup is preserved.",
                error.raw_os_error().unwrap_or(0)
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        path: String,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.path);
        }
    }
    #[test]
    fn real_windows_transaction_round_trip_and_conflict_use_an_isolated_test_key() {
        let fixture = Fixture {
            path: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
        };
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&fixture.path)
            .unwrap();
        let original = StoredValue {
            kind: 2,
            bytes: "%LOCALAPPDATA%\\Missing\\app.exe\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        key.set_raw_value(
            "Fixture",
            &RegValue {
                bytes: Cow::Borrowed(&original.bytes),
                vtype: REG_EXPAND_SZ,
            },
        )
        .unwrap();
        drop(key);
        // The production constructor always uses STARTUP_KEY. Only this private
        // unit test substitutes its own disposable, non-startup registry key.
        let store = WindowsRegistryStore {
            path: fixture.path.clone(),
            app_paths_path: format!("{}\\App Paths", fixture.path),
            uninstall_path: format!("{}\\Uninstall", fixture.path),
            ..Default::default()
        };
        assert_eq!(store.read("Fixture").unwrap(), Some(original.clone()));
        store
            .compare_exchange("Fixture", Some(&original), None)
            .unwrap();
        assert!(store.read("Fixture").unwrap().is_none());
        store
            .compare_exchange("Fixture", None, Some(&original))
            .unwrap();
        assert_eq!(store.read("Fixture").unwrap(), Some(original.clone()));
        assert!(store
            .compare_exchange("Fixture", None, Some(&original))
            .is_err());
        let wrong = StoredValue {
            kind: 1,
            bytes: original.bytes.clone(),
        };
        assert!(store
            .compare_exchange("Fixture", Some(&wrong), None)
            .is_err());
        assert_eq!(store.read("Fixture").unwrap(), Some(original));
    }

    #[test]
    fn full_backup_disable_restart_and_restore_preserves_real_registry_bytes() {
        use crate::{
            changes::ChangeManager, Assessment, Category, EntryStatus, LocalPathProbe,
            RegistryEntry,
        };
        let fixture = Fixture {
            path: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
        };
        let directory = tempfile::tempdir().unwrap();
        let command = format!(
            "\"{}\"",
            directory.path().join("missing-application.exe").display()
        );
        let original = StoredValue {
            kind: 2,
            bytes: format!("{command}\0\0")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&fixture.path)
            .unwrap();
        key.set_raw_value(
            "Fixture",
            &RegValue {
                bytes: Cow::Borrowed(&original.bytes),
                vtype: REG_EXPAND_SZ,
            },
        )
        .unwrap();
        drop(key);
        let entry = RegistryEntry {
            id: "fixture".into(),
            name: "Fixture".into(),
            category: Category::Startup,
            hive: "HKCU".into(),
            key_path: STARTUP_KEY.into(),
            view: "shared".into(),
            value_name: "Fixture".into(),
            value_type: "REG_EXPAND_SZ".into(),
            raw_value: command,
            publisher: None,
            version: None,
            assessment: Assessment {
                status: EntryStatus::Review,
                code: "target_missing".into(),
                explanation: "Fixture target missing".into(),
                target: None,
            },
            snapshot: Some(original.clone()),
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
        };
        let mut manager = ChangeManager::new(
            WindowsRegistryStore {
                path: fixture.path.clone(),
                app_paths_path: format!("{}\\App Paths", fixture.path),
                uninstall_path: format!("{}\\Uninstall", fixture.path),
                ..Default::default()
            },
            directory.path().join("backups"),
            LocalPathProbe,
        );
        let preview = manager.prepare_quarantine(&entry).unwrap();
        let changed = manager.apply(&preview.token).unwrap();
        assert_eq!(
            manager.inventory().unwrap().backups[0].state,
            "restore_available"
        );
        drop(manager);
        let mut reopened = ChangeManager::new(
            WindowsRegistryStore {
                path: fixture.path.clone(),
                app_paths_path: format!("{}\\App Paths", fixture.path),
                uninstall_path: format!("{}\\Uninstall", fixture.path),
                ..Default::default()
            },
            directory.path().join("backups"),
            LocalPathProbe,
        );
        let restore = reopened.prepare_restore(&changed.backup_id).unwrap();
        reopened.apply(&restore.token).unwrap();
        let reader = WindowsRegistryStore {
            path: fixture.path.clone(),
            app_paths_path: format!("{}\\App Paths", fixture.path),
            uninstall_path: format!("{}\\Uninstall", fixture.path),
            ..Default::default()
        };
        assert_eq!(reader.read("Fixture").unwrap(), Some(original));
    }

    #[test]
    fn app_paths_transaction_repair_and_restart_restore_preserve_other_metadata() {
        use crate::{
            changes::ChangeManager, Assessment, Category, EntryStatus, LocalPathProbe,
            RegistryEntry,
        };
        let fixture = Fixture {
            path: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
        };
        let directory = tempfile::tempdir().unwrap();
        let app_paths = format!("{}\\App Paths", fixture.path);
        let child_path = format!("{app_paths}\\broken.exe");
        let original = StoredValue {
            kind: 1,
            bytes: format!("{}\0\0", directory.path().join("missing.exe").display())
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(&child_path)
            .unwrap();
        key.set_raw_value(
            "",
            &RegValue {
                bytes: Cow::Borrowed(&original.bytes),
                vtype: REG_SZ,
            },
        )
        .unwrap();
        key.set_value("Path", &"%LOCALAPPDATA%\\Example").unwrap();
        key.set_value("UseUrl", &1u32).unwrap();
        let guard = read_app_path_guard(&key).unwrap();
        drop(key);
        let store = || WindowsRegistryStore {
            path: format!("{}\\Run", fixture.path),
            app_paths_path: app_paths.clone(),
            uninstall_path: format!("{}\\Uninstall", fixture.path),
            ..Default::default()
        };
        let entry = RegistryEntry {
            id: "fixture".into(),
            name: "broken.exe".into(),
            category: Category::AppPaths,
            hive: "HKCU".into(),
            key_path: format!("{APP_PATHS_KEY}\\broken.exe"),
            view: "shared".into(),
            value_name: String::new(),
            value_type: "REG_SZ".into(),
            raw_value: original.text().unwrap(),
            publisher: None,
            version: None,
            assessment: Assessment {
                status: EntryStatus::Review,
                code: "target_missing".into(),
                explanation: "Missing fixture".into(),
                target: None,
            },
            snapshot: Some(original.clone()),
            app_path_guard: Some(guard.clone()),
            app_path_repairable: true,
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
        };
        let mut manager =
            ChangeManager::new(store(), directory.path().join("backups"), LocalPathProbe);
        let plan = manager.prepare_quarantine(&entry).unwrap();
        let result = manager.apply(&plan.token).unwrap();
        assert_eq!(
            store().read_app_path("broken.exe").unwrap(),
            AppPathState {
                value: None,
                guard: guard.clone()
            }
        );
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(&child_path, KEY_READ | KEY_SET_VALUE)
            .unwrap();
        key.set_value("UseUrl", &0u32).unwrap();
        assert!(manager.prepare_restore(&result.backup_id).is_err());
        key.set_value("UseUrl", &1u32).unwrap();
        drop(key);
        drop(manager);
        let mut reopened =
            ChangeManager::new(store(), directory.path().join("backups"), LocalPathProbe);
        let restore = reopened.prepare_restore(&result.backup_id).unwrap();
        reopened.apply(&restore.token).unwrap();
        let expected = store().read_app_path("broken.exe").unwrap();
        assert_eq!(expected.value, Some(original));
        assert_eq!(expected.guard, guard);
        // A concurrently changed default must not be overwritten by restore.
        assert!(store()
            .compare_exchange_app_path(
                "broken.exe",
                &AppPathState {
                    value: None,
                    guard: expected.guard.clone()
                },
                expected.value.as_ref()
            )
            .is_err());
        // Nested registration metadata is explicitly outside the mutation scope.
        let (nested, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!("{child_path}\\Nested"))
            .unwrap();
        drop(nested);
        assert!(store().read_app_path("broken.exe").is_err());
        assert!(store()
            .compare_exchange_app_path("broken.exe", &expected, None)
            .is_err());
    }

    #[test]
    fn uninstall_transaction_full_backup_restart_restore_preserves_raw_values() {
        use crate::{
            changes::ChangeManager, Assessment, Category, EntryStatus, LocalPathProbe,
            RegistryEntry,
        };
        for component in [None, Some(0)] {
            let fixture = Fixture {
                path: format!(r"Software\RustRegistryTests\{}", uuid::Uuid::new_v4()),
            };
            let directory = tempfile::tempdir().unwrap();
            let mut original = crate::uninstall::fixture_snapshot(component);
            for (field, text) in [
                (
                    "InstallLocation",
                    directory
                        .path()
                        .join("missing-installation")
                        .display()
                        .to_string(),
                ),
                (
                    "UninstallString",
                    format!(
                        "\"{}\" /remove",
                        directory.path().join("missing-uninstall.exe").display()
                    ),
                ),
                (
                    "QuietUninstallString",
                    format!(
                        "\"{}\" /quiet",
                        directory.path().join("missing-uninstall.exe").display()
                    ),
                ),
            ] {
                original
                    .values
                    .iter_mut()
                    .find(|item| item.name == field)
                    .unwrap()
                    .value = StoredValue {
                    kind: 1,
                    bytes: format!("{text}\0\0")
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect(),
                };
            }
            let uninstall_path = format!("{}\\Uninstall", fixture.path);
            let child_path = format!("{uninstall_path}\\ExampleUninstall");
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&child_path)
                .unwrap();
            for item in &original.values {
                let kind = match item.value.kind {
                    1 => REG_SZ,
                    3 => REG_BINARY,
                    4 => REG_DWORD,
                    _ => unreachable!(),
                };
                key.set_raw_value(
                    &item.name,
                    &RegValue {
                        bytes: Cow::Borrowed(&item.value.bytes),
                        vtype: kind,
                    },
                )
                .unwrap();
            }
            drop(key);
            let store = || WindowsRegistryStore {
                path: format!("{}\\Run", fixture.path),
                app_paths_path: format!("{}\\App Paths", fixture.path),
                uninstall_path: uninstall_path.clone(),
                ..Default::default()
            };
            assert_eq!(
                store().read_uninstall("ExampleUninstall").unwrap(),
                original
            );
            let entry = RegistryEntry {
                id: "fixture".into(),
                name: original.text("DisplayName").unwrap(),
                category: Category::Uninstall,
                hive: "HKCU".into(),
                key_path: format!("{UNINSTALL_KEY}\\ExampleUninstall"),
                view: "shared".into(),
                value_name: "InstallLocation".into(),
                value_type: "REG_SZ".into(),
                raw_value: original.text("InstallLocation").unwrap(),
                publisher: None,
                version: None,
                assessment: Assessment {
                    status: EntryStatus::Review,
                    code: "target_missing".into(),
                    explanation: "Missing fixture".into(),
                    target: None,
                },
                snapshot: None,
                app_path_guard: None,
                app_path_repairable: false,
                uninstall_snapshot: Some(original.clone()),
                uninstall_repairable: true,
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
            };
            let mut manager =
                ChangeManager::new(store(), directory.path().join("backups"), LocalPathProbe);
            let plan = manager.prepare_quarantine(&entry).unwrap();
            let result = manager.apply(&plan.token).unwrap();
            assert_eq!(
                store().read_uninstall("ExampleUninstall").unwrap(),
                original.hidden().unwrap()
            );
            let restore = manager.prepare_restore(&result.backup_id).unwrap();
            let key = RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(&child_path, KEY_READ | KEY_SET_VALUE)
                .unwrap();
            key.set_value("ExternalChange", &1u32).unwrap();
            assert!(manager.apply(&restore.token).is_err());
            assert!(store()
                .read_uninstall("ExampleUninstall")
                .unwrap()
                .is_hidden());
            key.delete_value("ExternalChange").unwrap();
            drop(key);
            drop(manager);
            let mut reopened =
                ChangeManager::new(store(), directory.path().join("backups"), LocalPathProbe);
            let restore = reopened.prepare_restore(&result.backup_id).unwrap();
            reopened.apply(&restore.token).unwrap();
            assert_eq!(
                store().read_uninstall("ExampleUninstall").unwrap(),
                original
            );
            assert!(store()
                .set_uninstall_hidden("ExampleUninstall", &original, false)
                .is_err());
            let (nested, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!("{child_path}\\Nested"))
                .unwrap();
            drop(nested);
            assert!(store().read_uninstall("ExampleUninstall").is_err());
            assert!(store()
                .set_uninstall_hidden("ExampleUninstall", &original, true)
                .is_err());
        }
    }
}
