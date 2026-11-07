use super::{read_value, WindowsRegistryStore};
use crate::{
    changes::{NamedValue, StoredValue},
    services::*,
};
use std::{
    mem::{align_of, size_of},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA},
    System::Services::*,
};
use winreg::{enums::*, RegKey};

const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
struct Handle(SC_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn failure(action: &str) -> String {
    format!("{action} (Windows error {}). No service is started, stopped, deleted, or elevated automatically.", unsafe {GetLastError()})
}
fn open_service(name: &str, change: bool) -> Result<Handle, String> {
    validate_service_name(name)?;
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(failure("Cannot open the local service manager"));
    }
    let manager = Handle(manager);
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let access = SERVICE_QUERY_CONFIG
        | SERVICE_QUERY_STATUS
        | SERVICE_ENUMERATE_DEPENDENTS
        | READ_CONTROL_ACCESS
        | if change { SERVICE_CHANGE_CONFIG } else { 0 };
    let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if handle.is_null() {
        return Err(failure(
            "Cannot open the existing service with the required configuration rights",
        ));
    }
    Ok(Handle(handle))
}

struct Buffer {
    words: Vec<u64>,
    bytes: usize,
}
impl Buffer {
    fn new(bytes: u32) -> Result<Self, String> {
        let bytes = bytes as usize;
        if bytes == 0 || bytes > 65_536 {
            return Err("Service configuration exceeds the supported read limit.".into());
        }
        Ok(Self {
            words: vec![0; bytes.div_ceil(8)],
            bytes,
        })
    }
    fn pointer(&mut self) -> *mut u8 {
        self.words.as_mut_ptr().cast()
    }
    fn structure<T: Copy>(&self) -> Result<T, String> {
        if self.bytes < size_of::<T>() || align_of::<T>() > align_of::<u64>() {
            return Err("Service configuration has an unsupported layout.".into());
        }
        // The API filled an aligned, bounded buffer containing its documented POD structure.
        Ok(unsafe { self.words.as_ptr().cast::<T>().read() })
    }
    fn text(&self, pointer: *const u16) -> Result<String, String> {
        if pointer.is_null() {
            return Ok(String::new());
        }
        let start = self.words.as_ptr() as usize;
        let address = pointer as usize;
        if address < start || address >= start + self.bytes || !(address - start).is_multiple_of(2)
        {
            return Err("Service configuration contains an invalid string pointer.".into());
        }
        // Restrict every pointer to the storage returned by SCM; never scan unbounded memory.
        let units =
            unsafe { std::slice::from_raw_parts(pointer, (start + self.bytes - address) / 2) };
        let length = units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or("Unterminated service configuration string.")?;
        String::from_utf16(&units[..length])
            .map_err(|_| "Service configuration contains invalid UTF-16.".into())
    }
}
fn extra(handle: &Handle, level: u32) -> Result<Buffer, String> {
    let mut needed = 0;
    let ok = unsafe { QueryServiceConfig2W(handle.0, level, null_mut(), 0, &mut needed) };
    if ok == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(failure("Cannot verify optional service configuration"));
    }
    let mut buffer = Buffer::new(needed)?;
    if unsafe {
        QueryServiceConfig2W(
            handle.0,
            level,
            buffer.pointer(),
            buffer.bytes as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(failure("Cannot read optional service configuration"));
    }
    Ok(buffer)
}
fn verify_optional(handle: &Handle) -> Result<(), String> {
    if extra(handle, SERVICE_CONFIG_LAUNCH_PROTECTED)?
        .structure::<SERVICE_LAUNCH_PROTECTED_INFO>()?
        .dwLaunchProtected
        != 0
        || extra(handle, SERVICE_CONFIG_TRIGGER_INFO)?
            .structure::<SERVICE_TRIGGER_INFO>()?
            .cTriggers
            != 0
        || extra(handle, SERVICE_CONFIG_DELAYED_AUTO_START_INFO)?
            .structure::<SERVICE_DELAYED_AUTO_START_INFO>()?
            .fDelayedAutostart
            != 0
        || extra(handle, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)?
            .structure::<SERVICE_FAILURE_ACTIONS_FLAG>()?
            .fFailureActionsOnNonCrashFailures
            != 0
    {
        return Err(
            "Protected, triggered, delayed-start, or recovery-managed services remain read-only."
                .into(),
        );
    }
    let actions = extra(handle, SERVICE_CONFIG_FAILURE_ACTIONS)?;
    let value = actions.structure::<SERVICE_FAILURE_ACTIONSW>()?;
    if value.cActions != 0
        || !actions.text(value.lpCommand)?.is_empty()
        || !actions.text(value.lpRebootMsg)?.is_empty()
    {
        return Err("Services with recovery actions remain read-only.".into());
    }
    Ok(())
}
fn config(handle: &Handle) -> Result<ServiceConfig, String> {
    let mut needed = 0;
    unsafe {
        QueryServiceConfigW(handle.0, null_mut(), 0, &mut needed);
    }
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(failure("Cannot size the service configuration"));
    }
    let mut buffer = Buffer::new(needed)?;
    if unsafe {
        QueryServiceConfigW(
            handle.0,
            buffer.pointer().cast(),
            buffer.bytes as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(failure("Cannot read the service configuration"));
    }
    let value = buffer.structure::<QUERY_SERVICE_CONFIGW>()?;
    if !buffer.text(value.lpDependencies)?.is_empty() {
        return Err("Services with dependencies remain read-only.".into());
    }
    let mut security_size = 0;
    unsafe {
        QueryServiceObjectSecurity(handle.0, 7, null_mut(), 0, &mut security_size);
    }
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(failure("Cannot verify the service security descriptor"));
    }
    let mut security = Buffer::new(security_size)?;
    if unsafe {
        QueryServiceObjectSecurity(
            handle.0,
            7,
            security.pointer().cast(),
            security.bytes as u32,
            &mut security_size,
        )
    } == 0
    {
        return Err(failure("Cannot read the service security descriptor"));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(security.words.as_ptr().cast::<u8>(), security.bytes) }
            .to_vec();
    Ok(ServiceConfig {
        service_type: value.dwServiceType,
        start_type: value.dwStartType,
        error_control: value.dwErrorControl,
        binary_path: buffer.text(value.lpBinaryPathName)?,
        load_order_group: buffer.text(value.lpLoadOrderGroup)?,
        tag_id: value.dwTagId,
        dependencies: vec![],
        account: buffer.text(value.lpServiceStartName)?,
        display_name: buffer.text(value.lpDisplayName)?,
        security: bytes,
    })
}
fn values(key: &RegKey) -> Result<Vec<NamedValue>, String> {
    let mut result = Vec::new();
    let mut bytes = 0;
    for item in key.enum_values() {
        let (name, value) = item
            .map_err(|_| "Service registry metadata could not be completely read.".to_string())?;
        bytes += value.bytes.len();
        if result.len() >= 64 || bytes > 32_768 {
            return Err("Service metadata exceeds backup limits.".into());
        }
        result.push(NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        });
    }
    result.sort_by_key(|item| item.name.to_ascii_lowercase());
    crate::associations::validate_values(&result)?;
    for item in &result {
        if read_value(key, &item.name)?.as_ref() != Some(&item.value) {
            return Err("Service registry values changed during reading.".into());
        }
    }
    Ok(result)
}
impl WindowsRegistryStore {
    fn service_state_with(
        &self,
        name: &str,
        handle: &Handle,
        change_allowed: bool,
    ) -> Result<ServiceState, String> {
        verify_optional(handle)?;
        let config = config(handle)?;
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        if unsafe {
            QueryServiceStatusEx(
                handle.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        } == 0
        {
            return Err(failure("Cannot verify whether the service is stopped"));
        }
        let mut count = 0;
        let mut bytes = 0;
        let ok = unsafe {
            EnumDependentServicesW(
                handle.0,
                SERVICE_STATE_ALL,
                null_mut(),
                0,
                &mut bytes,
                &mut count,
            )
        };
        let error = unsafe { GetLastError() };
        let has_dependents = if ok != 0 {
            count != 0
        } else if [ERROR_MORE_DATA, ERROR_INSUFFICIENT_BUFFER].contains(&error) {
            true
        } else {
            return Err(failure("Cannot verify dependent services"));
        };
        let root = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_options_flags(
                format!("{}\\{name}", self.services_path),
                REG_OPTION_OPEN_LINK,
                KEY_READ,
            )
            .map_err(|_| "Cannot read all service registry metadata.".to_string())?;
        let children: Vec<String> = root
            .enum_keys()
            .take(3)
            .collect::<Result<_, _>>()
            .map_err(|_| "Cannot read service child keys.".to_string())?;
        if children
            .iter()
            .any(|child| !child.eq_ignore_ascii_case("Security"))
        {
            return Err(
                "Nested, triggered, or custom service registration remains read-only.".into(),
            );
        }
        let security_values = if let Some(child) = children.first() {
            let key = root
                .open_subkey_with_options_flags(child, REG_OPTION_OPEN_LINK, KEY_READ)
                .map_err(|_| "Cannot read the existing service security metadata.".to_string())?;
            if key.enum_keys().next().is_some() {
                return Err("Nested service security metadata is unsupported.".into());
            }
            Some(values(&key)?)
        } else {
            None
        };
        let snapshot = ServiceSnapshot {
            values: values(&root)?,
            security_values,
            config,
        };
        snapshot.validate()?;
        Ok(ServiceState {
            snapshot,
            stopped: status.dwCurrentState == SERVICE_STOPPED && status.dwProcessId == 0,
            has_dependents,
            change_allowed,
        })
    }
    pub(crate) fn service_state(&self, name: &str) -> Result<ServiceState, String> {
        let handle = open_service(name, false)?;
        let change_allowed = open_service(name, true).is_ok();
        self.service_state_with(name, &handle, change_allowed)
    }
    pub(crate) fn change_service_start(
        &self,
        name: &str,
        original: &ServiceSnapshot,
        disable: bool,
    ) -> Result<(), String> {
        original.validate_original()?;
        let handle = open_service(name, true)?;
        let disabled = original.disabled()?;
        let expected = if disable { original } else { &disabled };
        let state = self.service_state_with(name, &handle, true)?;
        state.validate_change()?;
        if state.snapshot != *expected {
            return Err(
                "The service configuration or security changed. Nothing was changed.".into(),
            );
        }
        if disable {
            verify_missing_service(original, &crate::LocalPathProbe)?;
        }
        // SCM has no compare-and-swap operation. Recheck immediately before its supported
        // startup-only setter, then verify every guarded value afterward; never edit Services directly.
        let rechecked = self.service_state_with(name, &handle, true)?;
        rechecked.validate_change()?;
        if rechecked.snapshot != *expected {
            return Err("The service changed before the configuration update.".into());
        }
        let start = if disable { DISABLED } else { MANUAL };
        if unsafe {
            ChangeServiceConfigW(
                handle.0,
                SERVICE_NO_CHANGE,
                start,
                SERVICE_NO_CHANGE,
                null(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        } == 0
        {
            return Err(failure(
                "Windows refused the startup-type change; the backup is preserved",
            ));
        }
        let actual = self.service_state_with(name, &handle, true)?;
        actual.validate_change()?;
        if actual.snapshot != if disable { disabled } else { original.clone() } {
            return Err("The service changed during or after the SCM update. The verified backup is preserved; inspect before restoring.".into());
        }
        Ok(())
    }
}
