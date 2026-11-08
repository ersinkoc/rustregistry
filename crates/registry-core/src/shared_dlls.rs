use crate::{
    analyze_target, changes::StoredValue, EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};

pub const SHARED_DLLS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\SharedDLLs";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedDllBackup {
    pub path: String,
    pub view: String,
}

pub(crate) fn windows_directory() -> Result<String, String> {
    #[cfg(windows)]
    {
        let mut buffer = vec![0u16; 32_768];
        // Read the actual Windows directory, independently of process environment variables.
        let len = unsafe {
            windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        } as usize;
        if len == 0 || len >= buffer.len() {
            return Err("The Windows directory could not be verified.".into());
        }
        String::from_utf16(&buffer[..len])
            .map_err(|_| "Unsupported Windows directory encoding.".into())
    }
    #[cfg(not(windows))]
    {
        Ok(r"C:\Windows".into())
    }
}

pub fn validate_shared_dll_path(path: &str) -> Result<(), String> {
    let bytes = path.as_bytes();
    if !path.is_ascii()
        || path.len() < 8
        || path.len() > 2048
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || !path.to_ascii_lowercase().ends_with(".dll")
        || path[3..].contains(':')
        || path
            .chars()
            .any(|c| c.is_control() || "%/~\"*?<>|".contains(c))
        || path[3..].split('\\').any(|part| {
            part.is_empty() || part == "." || part == ".." || part.ends_with(['.', ' '])
        })
    {
        return Err("Only a bounded literal local DLL path without aliases, environment variables, or ambiguous segments supports shared DLL recovery.".into());
    }
    let windows = windows_directory()?
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    if path
        .to_ascii_lowercase()
        .starts_with(&format!("{windows}\\"))
    {
        return Err("Windows directory references remain outside shared DLL repair scope.".into());
    }
    Ok(())
}

pub fn validate_zero_count(value: &StoredValue) -> Result<(), String> {
    if value.kind != 4 || value.bytes != [0, 0, 0, 0] {
        return Err("Only an exact DWORD zero reference count supports repair. Positive or unsupported counts are preserved.".into());
    }
    Ok(())
}

pub fn verify_missing_shared_dll(
    path: &str,
    value: &StoredValue,
    probe: &impl PathProbe,
) -> Result<(), String> {
    validate_shared_dll_path(path)?;
    validate_zero_count(value)?;
    let assessment = analyze_target(path, TargetKind::File, &Environment::current(), probe);
    if assessment.status != EntryStatus::Review || assessment.code != "target_missing" {
        return Err(
            "The shared DLL target is not confirmed missing. Repair or restore is blocked.".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Probe(crate::ProbeResult);
    impl PathProbe for Probe {
        fn probe(&self, _: &str, _: TargetKind) -> crate::ProbeResult {
            self.0
        }
    }
    #[test]
    fn shared_dll_policy_accepts_only_zero_count_missing_literal_local_dlls() {
        let zero = StoredValue {
            kind: 4,
            bytes: vec![0; 4],
        };
        verify_missing_shared_dll(
            r"C:\RustRegistryMissing\zero.dll",
            &zero,
            &Probe(crate::ProbeResult::Missing),
        )
        .unwrap();
        for result in [
            crate::ProbeResult::Found,
            crate::ProbeResult::Inaccessible,
            crate::ProbeResult::Redirected,
            crate::ProbeResult::WrongKind,
        ] {
            assert!(verify_missing_shared_dll(
                r"C:\RustRegistryMissing\zero.dll",
                &zero,
                &Probe(result)
            )
            .is_err());
        }
        for value in [
            StoredValue {
                kind: 4,
                bytes: vec![1, 0, 0, 0],
            },
            StoredValue {
                kind: 4,
                bytes: vec![0; 8],
            },
            StoredValue {
                kind: 1,
                bytes: vec![0; 4],
            },
        ] {
            assert!(verify_missing_shared_dll(
                r"C:\RustRegistryMissing\zero.dll",
                &value,
                &Probe(crate::ProbeResult::Missing)
            )
            .is_err());
        }
        for path in [
            r"zero.dll",
            r"\\server\share\zero.dll",
            r"%TEMP%\zero.dll",
            r"C:\Apps\..\Windows\zero.dll",
            r"C:\Apps.\zero.dll",
            r"C:\Apps\\zero.dll",
            r"C:\PROGRA~1\zero.dll",
            r"C:/Apps/zero.dll",
            r"C:\Apps\zero.dll:stream",
            r"C:\Apps\zero.exe",
            r"C:\Apps\é.dll",
        ] {
            assert!(validate_shared_dll_path(path).is_err(), "{path}");
        }
        assert!(validate_shared_dll_path(&format!(
            "{}\\RustRegistryMissing.dll",
            windows_directory().unwrap()
        ))
        .is_err());
    }
}
