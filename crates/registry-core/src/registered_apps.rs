use crate::changes::StoredValue;
use serde::{Deserialize, Serialize};

pub const REGISTERED_APPS_KEY: &str = r"Software\RegisteredApplications";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisteredApplicationBackup {
    pub capabilities_path: String,
}

pub fn validate_registration_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 255
        || !name.is_ascii()
        || name.trim() != name
        || name
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    {
        return Err(
            "Only a bounded, unambiguous application registration name is supported.".into(),
        );
    }
    Ok(())
}

pub fn capabilities_path(value: &StoredValue) -> Result<String, String> {
    let path = value.text()?;
    let parts: Vec<_> = path.split('\\').collect();
    if value.kind != 1
        || path.len() > 512
        || !(3..=10).contains(&parts.len())
        || !parts[0].eq_ignore_ascii_case("Software")
        || !parts.last().unwrap().eq_ignore_ascii_case("Capabilities")
        || parts.iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.trim() != *part
                || part.ends_with('.')
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b" _.-".contains(&b))
        })
        || [
            "Microsoft",
            "Classes",
            "Policies",
            "RegisteredApplications",
            "Windows",
            "Wow6432Node",
        ]
        .iter()
        .any(|protected| parts[1].eq_ignore_ascii_case(protected))
    {
        return Err("Only a literal REG_SZ Software\\vendor\\…\\Capabilities registry path outside protected namespaces supports recovery.".into());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value(path: &str) -> StoredValue {
        StoredValue {
            kind: 1,
            bytes: path
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    #[test]
    fn capabilities_policy_rejects_indirection_protected_namespaces_and_unsupported_types() {
        assert_eq!(
            capabilities_path(&value(r"Software\Example Vendor\Player\Capabilities")).unwrap(),
            r"Software\Example Vendor\Player\Capabilities"
        );
        for path in [
            r"HKCU\Software\Example\Capabilities",
            r"Software\Microsoft\App\Capabilities",
            r"Software\Classes\App\Capabilities",
            r"Software\Policies\App\Capabilities",
            r"Software\Wow6432Node\App\Capabilities",
            r"Software\Example\..\Capabilities",
            r"Software\Example\\Capabilities",
            r"Software\Example.\Capabilities",
            r"Software\Example\%APP%\Capabilities",
            r"Software\Example\NotCapabilities",
            r"Software\Éxample\Capabilities",
        ] {
            assert!(capabilities_path(&value(path)).is_err(), "{path}");
        }
        let mut indirect = value(r"Software\Example\Capabilities");
        indirect.kind = 2;
        assert!(capabilities_path(&indirect).is_err());
        for name in ["", " bad", "bad\\name", "bad\0name"] {
            assert!(validate_registration_name(name).is_err());
        }
    }
}
