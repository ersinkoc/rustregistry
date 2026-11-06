use crate::{Assessment, EntryStatus};
use std::{collections::HashMap, io, path::Path};

#[derive(Debug, Clone, Copy)]
pub enum TargetKind {
    Command,
    File,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    Found,
    Missing,
    Inaccessible,
    WrongKind,
    Redirected,
}

pub trait PathProbe {
    fn probe(&self, path: &str, kind: TargetKind) -> ProbeResult;
}

pub struct LocalPathProbe;

impl PathProbe for LocalPathProbe {
    fn probe(&self, path: &str, kind: TargetKind) -> ProbeResult {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
            let root: Vec<u16> = path[..3].encode_utf16().chain(Some(0)).collect();
            // SAFETY: root is a valid, NUL-terminated UTF-16 drive-root string.
            if unsafe { GetDriveTypeW(root.as_ptr()) } == 4 {
                return ProbeResult::Redirected;
            }
            // Do not follow junctions, symlinks, cloud placeholders or other reparse
            // points: a local-looking path can otherwise cause network access.
            for prefix in Path::new(path)
                .ancestors()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                match std::fs::symlink_metadata(prefix) {
                    Ok(metadata) if metadata.file_attributes() & 0x400 != 0 => {
                        return ProbeResult::Redirected;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return ProbeResult::Missing
                    }
                    Err(_) => return ProbeResult::Inaccessible,
                }
            }
        }
        match std::fs::metadata(Path::new(path)) {
            Ok(metadata) => {
                let correct = match kind {
                    TargetKind::Directory => metadata.is_dir(),
                    _ => metadata.is_file(),
                };
                if correct {
                    ProbeResult::Found
                } else {
                    ProbeResult::WrongKind
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => ProbeResult::Missing,
            Err(_) => ProbeResult::Inaccessible,
        }
    }
}

#[derive(Debug, Default)]
pub struct Environment(HashMap<String, String>);

impl Environment {
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(k, v)| (k.to_uppercase(), v))
                .collect(),
        )
    }

    pub fn current() -> Self {
        Self::from_pairs(
            std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))),
        )
    }

    fn expand(&self, value: &str) -> Result<String, ()> {
        let mut output = String::new();
        let mut remainder = value;
        while let Some(start) = remainder.find('%') {
            output.push_str(&remainder[..start]);
            let after = &remainder[start + 1..];
            let end = after.find('%').ok_or(())?;
            output.push_str(self.0.get(&after[..end].to_uppercase()).ok_or(())?);
            remainder = &after[end + 1..];
        }
        output.push_str(remainder);
        // Avoid guessing nested expansions or accidentally probing a different target.
        if output.contains('%') {
            Err(())
        } else {
            Ok(output)
        }
    }
}

fn assessment(
    status: EntryStatus,
    code: &str,
    explanation: &str,
    target: Option<String>,
) -> Assessment {
    Assessment {
        status,
        code: code.into(),
        explanation: explanation.into(),
        target,
    }
}

fn unknown(code: &str, explanation: &str, target: Option<String>) -> Assessment {
    assessment(EntryStatus::Unknown, code, explanation, target)
}

fn command_target(command: &str) -> Result<&str, &'static str> {
    if let Some(rest) = command.strip_prefix('"') {
        let end = rest.find('"').ok_or("unclosed_quote")?;
        if !rest[end + 1..].is_empty() && !rest[end + 1..].starts_with(char::is_whitespace) {
            return Err("ambiguous_command");
        }
        return Ok(&rest[..end]);
    }
    let first = command.split_whitespace().next().unwrap_or("");
    if first.to_ascii_lowercase().ends_with(".exe") {
        return Ok(first);
    }
    // An unquoted path with spaces has Windows-specific executable resolution rules.
    // Do not turn a guessed final .exe path into a missing-file diagnosis.
    Err("ambiguous_command")
}

pub fn analyze_target(
    raw: &str,
    kind: TargetKind,
    environment: &Environment,
    probe: &impl PathProbe,
) -> Assessment {
    let raw = raw.trim();
    if raw.is_empty() {
        return unknown("empty_target", "This record does not specify a target to verify. This alone does not indicate an error.", None);
    }
    if raw.contains('\0') {
        return unknown("embedded_null", "The value contains an embedded NUL character. Its target cannot be interpreted reliably.", None);
    }
    let expanded = match environment.expand(raw) {
        Ok(value) => value,
        Err(_) => return unknown("unresolved_environment", "Environment variables could not be resolved in the current user context. The record has not been marked as broken.", None),
    };
    let candidate = match kind {
        TargetKind::Command => match command_target(&expanded) {
            Ok(value) => value.to_string(),
            Err(code) => return unknown(code, "The executable target of this command is ambiguous. No file check was made to avoid a misleading diagnosis.", None),
        },
        _ => {
            if expanded.starts_with('"') || expanded.ends_with('"') {
                match expanded.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    Some(value) if !value.contains('"') => value.to_string(),
                    _ => return unknown("invalid_quote", "The path has ambiguous quoting. The target could not be verified.", None),
                }
            } else {
                expanded
            }
        }
    };
    let candidate = candidate.replace('/', "\\");
    if candidate.starts_with("\\\\") || candidate.starts_with("\\??\\") {
        return unknown("remote_or_device_path", "Network and device paths are not queried automatically. This may be an offline location or a special Windows path.", Some(candidate));
    }
    let bytes = candidate.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return unknown("relative_or_indirect", "No absolute local path was found. PATH lookup, app alias lookup, and indirect command resolution are outside this scan.", Some(candidate));
    }
    if candidate[3..].contains(':') || candidate.contains(['*', '?', '"']) {
        return unknown("unsupported_path", "The path contains special characters or an alternate data stream and is outside automatic path verification.", Some(candidate));
    }
    if matches!(kind, TargetKind::Command) {
        let executable = candidate
            .rsplit('\\')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if [
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "msiexec.exe",
            "wscript.exe",
            "cscript.exe",
        ]
        .contains(&executable.as_str())
        {
            return unknown("indirect_command", "This command uses a system launcher. The launcher existing does not establish that the underlying target is valid. The command was not executed.", Some(candidate));
        }
    }
    match probe.probe(&candidate, kind) {
        ProbeResult::Found => assessment(EntryStatus::Found, "target_found", "The specified local target existed at scan time. This does not establish that the application works or that the entire registry record is valid.", Some(candidate)),
        ProbeResult::Missing => assessment(EntryStatus::Review, "target_missing", "The specified local target was not found at scan time. A disconnected drive or an uninstalled application may explain this. Review the record before considering any changes.", Some(candidate)),
        ProbeResult::WrongKind => unknown("wrong_target_kind", "The path exists but does not match the expected file or folder type. Manual review is recommended.", Some(candidate)),
        ProbeResult::Inaccessible => unknown("path_inaccessible", "The target could not be accessed. An access error does not mean the target is missing.", Some(candidate)),
        ProbeResult::Redirected => unknown("redirected_path", "This path uses a network drive or a reparse point, such as a junction or cloud placeholder. It was not followed automatically.", Some(candidate)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Probe {
        result: ProbeResult,
        calls: Cell<usize>,
    }
    impl PathProbe for Probe {
        fn probe(&self, _: &str, _: TargetKind) -> ProbeResult {
            self.calls.set(self.calls.get() + 1);
            self.result
        }
    }
    fn probe(result: ProbeResult) -> Probe {
        Probe {
            result,
            calls: Cell::new(0),
        }
    }

    #[test]
    fn resolves_quoted_startup_command_and_case_insensitive_environment() {
        let env = Environment::from_pairs([(
            "LOCALAPPDATA".into(),
            "C:\\Users\\Test\\AppData\\Local".into(),
        )]);
        let result = analyze_target(
            r#""%localappdata%\My App\app.exe" --background"#,
            TargetKind::Command,
            &env,
            &probe(ProbeResult::Found),
        );
        assert_eq!(result.status, EntryStatus::Found);
        assert_eq!(
            result.target.as_deref(),
            Some(r"C:\Users\Test\AppData\Local\My App\app.exe")
        );
    }

    #[test]
    fn only_a_definite_missing_local_target_is_flagged_for_review() {
        let env = Environment::default();
        for (result, expected) in [
            (ProbeResult::Missing, EntryStatus::Review),
            (ProbeResult::Inaccessible, EntryStatus::Unknown),
            (ProbeResult::WrongKind, EntryStatus::Unknown),
            (ProbeResult::Redirected, EntryStatus::Unknown),
            (ProbeResult::Found, EntryStatus::Found),
        ] {
            let actual = analyze_target(r"C:\Apps\app.exe", TargetKind::File, &env, &probe(result));
            assert_eq!(actual.status, expected);
        }
    }

    #[test]
    fn never_probes_network_ambiguous_or_indirect_commands() {
        let probe = probe(ProbeResult::Missing);
        for raw in [
            r"\\server\share\app.exe",
            r"C:\Program Files\App\app.exe --start",
            r"app.exe --start",
            r"%UNKNOWN%\app.exe",
            r#""C:\app.exe"suffix"#,
            r"C:\Windows\System32\rundll32.exe anything.dll,Entry",
            r"C:\Windows\System32\cmd.exe /c something",
            r#""C:\app.exe"#,
            "",
        ] {
            let result = analyze_target(raw, TargetKind::Command, &Environment::default(), &probe);
            assert_eq!(result.status, EntryStatus::Unknown, "{raw}");
        }
        assert_eq!(probe.calls.get(), 0);
    }

    #[test]
    fn validates_directory_without_treating_spaces_as_arguments() {
        let result = analyze_target(
            r"C:\Program Files\Example",
            TargetKind::Directory,
            &Environment::default(),
            &probe(ProbeResult::Found),
        );
        assert_eq!(result.status, EntryStatus::Found);
    }

    #[test]
    fn rejects_malformed_and_special_paths_without_io() {
        let probe = probe(ProbeResult::Missing);
        for raw in [
            "C:\\file\0.exe",
            r"C:\file.exe:stream",
            r"C:\*.exe",
            r"C:relative.exe",
            r#""C:\app.exe" junk"#,
        ] {
            let result = analyze_target(raw, TargetKind::File, &Environment::default(), &probe);
            assert_eq!(result.status, EntryStatus::Unknown, "{raw}");
        }
        assert_eq!(probe.calls.get(), 0);
    }
}
