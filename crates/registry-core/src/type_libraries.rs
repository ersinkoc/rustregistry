use crate::{
    analyze_target,
    changes::{NamedValue, StoredValue},
    EntryStatus, Environment, PathProbe, TargetKind,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const TYPE_LIB_KEY: &str = r"Software\Classes\TypeLib";

pub fn validate_version(version: &str) -> Result<(), String> {
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 2
        || parts.iter().any(|p| {
            p.is_empty()
                || p.len() > 4
                || (p.len() > 1 && p.starts_with('0'))
                || !p.bytes().all(|b| b.is_ascii_hexdigit())
        })
    {
        return Err("A bounded hexadecimal major.minor type library version is required.".into());
    }
    Ok(())
}

pub fn validate_locale(locale: &str) -> Result<(), String> {
    if locale.is_empty()
        || locale.len() > 4
        || (locale.len() > 1 && locale.starts_with('0'))
        || !locale.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("A bounded hexadecimal type library locale is required.".into());
    }
    Ok(())
}

pub fn validate_library_path(path: &str) -> Result<(), String> {
    if !path.is_ascii()
        || path.len() < 4
        || ![".dll", ".tlb", ".olb"]
            .iter()
            .any(|extension| path.to_ascii_lowercase().ends_with(extension))
    {
        return Err(
            "Only literal local .dll, .tlb, or .olb mappings support type library recovery.".into(),
        );
    }
    // All three extensions have equal length. Reuse the strict local path and
    // actual Windows-directory exclusion policy, but probe the original path.
    crate::shared_dlls::validate_shared_dll_path(&format!("{}.dll",&path[..path.len()-4]))
        .map_err(|_|"Only bounded literal local type library files outside Windows, without aliases or indirection, support recovery.".into())
}

pub fn verify_missing_library(value: &StoredValue, probe: &impl PathProbe) -> Result<(), String> {
    let path = value.text()?;
    validate_library_path(&path)?;
    let assessment = analyze_target(&path, TargetKind::File, &Environment::current(), probe);
    if assessment.status != EntryStatus::Review || assessment.code != "target_missing" {
        return Err(
            "The type library target is not confirmed missing. Repair or restore is blocked."
                .into(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypeLibNode {
    pub path: String,
    pub values: Vec<NamedValue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypeLibGuard {
    pub nodes: Vec<TypeLibNode>,
}
impl TypeLibGuard {
    pub fn validate(&self, version: &str) -> Result<(), String> {
        validate_version(version)?;
        let required = [
            String::new(),
            version.into(),
            format!(r"{version}\0"),
            format!(r"{version}\0\win64"),
        ];
        let optional = [
            format!(r"{version}\0\win32"),
            format!(r"{version}\FLAGS"),
            format!(r"{version}\HELPDIR"),
        ];
        let mut seen = HashSet::new();
        if self.nodes.len() > 7
            || self
                .nodes
                .iter()
                .flat_map(|n| &n.values)
                .map(|v| v.value.bytes.len())
                .sum::<usize>()
                > 16384
        {
            return Err("Type library metadata exceeds the supported backup bounds.".into());
        }
        for node in &self.nodes {
            if (!required.contains(&node.path) && !optional.contains(&node.path))
                || !seen.insert(node.path.clone())
            {
                return Err("Unsupported or duplicated type library metadata scope.".into());
            }
            crate::associations::validate_values(&node.values)?;
            if node.values.len() > 1 || (node.path.ends_with(r"\win64") && !node.values.is_empty())
            {
                return Err("Named or alternate type library metadata remains read-only.".into());
            }
            for item in &node.values {
                if !item.name.is_empty()
                    || ![1, 2].contains(&item.value.kind)
                    || (item.value.text().is_err()
                        && !(item.value.bytes.len().is_multiple_of(2)
                            && item.value.bytes.iter().all(|b| *b == 0)))
                {
                    return Err(
                        "Only bounded default text metadata supports type library recovery.".into(),
                    );
                }
            }
        }
        if required.iter().any(|path| !seen.contains(path)) {
            return Err("Required type library metadata is missing.".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeLibState {
    pub value: Option<StoredValue>,
    pub guard: TypeLibGuard,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypeLibBackup {
    pub library_id: String,
    pub version: String,
    pub locale: String,
    pub platform: String,
    pub guard: TypeLibGuard,
}
impl TypeLibBackup {
    pub fn selector(library_id: &str, version: &str) -> Self {
        Self {
            library_id: library_id.into(),
            version: version.into(),
            locale: "0".into(),
            platform: "win64".into(),
            guard: TypeLibGuard {
                nodes: [
                    String::new(),
                    version.into(),
                    format!(r"{version}\0"),
                    format!(r"{version}\0\win64"),
                ]
                .map(|path| TypeLibNode {
                    path,
                    values: vec![],
                })
                .into(),
            },
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        crate::com::validate_clsid(&self.library_id)?;
        validate_version(&self.version)?;
        if self.locale != "0" || self.platform != "win64" {
            return Err("Only the neutral win64 type library mapping supports recovery.".into());
        }
        self.guard.validate(&self.version)
    }
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
    fn text(path: &str) -> StoredValue {
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
    fn type_library_policy_limits_selectors_paths_missing_evidence_and_guarded_metadata() {
        for version in ["1.0", "a.1", "ffff.ffff"] {
            validate_version(version).unwrap();
        }
        for version in ["1", "1.0.0", "01.0", "1.0000", "10000.0", r"1.0\0"] {
            assert!(validate_version(version).is_err());
        }
        for locale in ["0", "9", "409", "ffff"] {
            validate_locale(locale).unwrap();
        }
        for locale in ["", "00", "10000", "0x9", r"0\win64"] {
            assert!(validate_locale(locale).is_err());
        }
        for path in [
            r"C:\RustRegistryMissing\one.tlb",
            r"C:\RustRegistryMissing\one.olb",
            r"C:\RustRegistryMissing\one.dll",
        ] {
            verify_missing_library(&text(path), &Probe(crate::ProbeResult::Missing)).unwrap();
        }
        for path in [
            r"C:\Windows\one.tlb",
            r"C:\Apps\one.dll\1",
            r"C:\Apps\..\one.tlb",
            r"C:\Apps\one.exe",
            r"%TEMP%\one.tlb",
            r"\\server\one.tlb",
            r"C:\PROGRA~1\one.tlb",
        ] {
            assert!(validate_library_path(path).is_err(), "{path}");
        }
        for result in [
            crate::ProbeResult::Found,
            crate::ProbeResult::Inaccessible,
            crate::ProbeResult::Redirected,
            crate::ProbeResult::WrongKind,
        ] {
            assert!(verify_missing_library(
                &text(r"C:\RustRegistryMissing\one.tlb"),
                &Probe(result)
            )
            .is_err());
        }
        let guard = TypeLibGuard {
            nodes: ["", "1.0", r"1.0\0", r"1.0\0\win64"]
                .map(|p| TypeLibNode {
                    path: p.into(),
                    values: vec![],
                })
                .into(),
        };
        guard.validate("1.0").unwrap();
        let mut other = guard.clone();
        other.nodes.push(other.nodes[0].clone());
        assert!(other.validate("1.0").is_err());
        let mut other = guard.clone();
        other.nodes.push(TypeLibNode {
            path: r"1.0\409".into(),
            values: vec![],
        });
        assert!(other.validate("1.0").is_err());
        let mut other = guard;
        other.nodes[3].values.push(NamedValue {
            name: "Unknown".into(),
            value: text("preserve"),
        });
        assert!(other.validate("1.0").is_err());
    }
}
