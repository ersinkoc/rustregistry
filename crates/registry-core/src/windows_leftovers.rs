use super::{read_uninstall_snapshot, read_value, WindowsRegistryStore};
use crate::{
    app_leftovers::*,
    changes::{NamedValue, StoredValue},
    uninstall::{UninstallSnapshot, UNINSTALL_KEY},
};
use std::{borrow::Cow, collections::HashMap};
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue, HKEY};
pub(crate) type AnchorIndex = HashMap<String, Vec<(String, Result<UninstallSnapshot, String>)>>;
pub(crate) struct LeftoverAppState {
    pub name: String,
    pub value: Option<StoredValue>,
    pub other: Vec<NamedValue>,
}
fn open_leftover_child(
    root: &RegKey,
    name: &str,
    flag: u32,
    tx: Option<&Transaction>,
    write: bool,
) -> Result<Option<RegKey>, String> {
    let access = KEY_READ | flag | if write { KEY_SET_VALUE } else { 0 };
    let child = if let Some(tx) = tx {
        root.open_subkey_transacted_with_options_flags(name, tx, REG_OPTION_OPEN_LINK, access)
    } else {
        root.open_subkey_with_options_flags(name, REG_OPTION_OPEN_LINK, access)
    };
    let child = match child {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "Application ownership evidence is inaccessible (Windows error {}).",
                e.raw_os_error().unwrap_or(0)
            ))
        }
    };
    if read_value(&child, "SymbolicLinkValue")?.is_some_and(|v| v.kind == 6) {
        return Err(
            "Application-owned registry links remain outside leftover cleanup scope.".into(),
        );
    }
    Ok(Some(child))
}
fn ownership_directory(value: &StoredValue) -> Option<String> {
    if value.kind == 1 {
        return literal_directory(value).ok();
    }
    if value.kind != 2 {
        return None;
    }
    // Expanded paths can disqualify ownership as duplicates, never grant cleanup.
    let path = crate::Environment::current()
        .expand(&value.text().ok()?)
        .ok()?;
    let literal = StoredValue {
        kind: 1,
        bytes: path
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect(),
    };
    literal_directory(&literal).ok()
}
#[cfg(test)]
#[path = "windows_leftover_tests.rs"]
mod tests;
#[path = "windows_leftover_types.rs"]
mod types;
impl WindowsRegistryStore {
    fn leftover_path(&self, part: &str, machine: Option<u32>) -> (HKEY, String) {
        #[cfg(test)]
        if let Some(base) = &self.leftover_test_root {
            return (
                HKEY_CURRENT_USER,
                format!(
                    r"{base}\{}\{part}",
                    machine.map_or("User".into(), |v| format!("Machine{v}"))
                ),
            );
        }
        (
            if machine.is_some() {
                HKEY_LOCAL_MACHINE
            } else {
                HKEY_CURRENT_USER
            },
            match part {
                "AppPaths" => crate::changes::APP_PATHS_KEY,
                "Uninstall" => UNINSTALL_KEY,
                _ => r"Software\Classes\Applications",
            }
            .into(),
        )
    }
    fn leftover_key(
        &self,
        part: &str,
        name: Option<&str>,
        machine: Option<u32>,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<Option<RegKey>, String> {
        // These are fixed Windows-managed roots, including the Classes hive
        // alias and WOW64 aliases. Follow only that root; inspect the individual
        // application child with OPEN_LINK so application-created links fail closed.
        let (hive, mut root_path) = self.leftover_path(part, machine);
        if part == "Applications" {
            root_path = root_path
                .strip_suffix(r"\Applications")
                .ok_or("Invalid fixed application root.")?
                .into();
        }
        let flag = if machine == Some(32) {
            KEY_WOW64_32KEY
        } else {
            KEY_WOW64_64KEY
        };
        let root = if let Some(tx) = tx {
            RegKey::predef(hive).open_subkey_transacted_with_flags(&root_path, tx, KEY_READ | flag)
        } else {
            RegKey::predef(hive).open_subkey_with_flags(&root_path, KEY_READ | flag)
        };
        let mut root = match root {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(format!(
                    "The fixed application registry root is inaccessible (Windows error {}).",
                    e.raw_os_error().unwrap_or(0)
                ))
            }
        };
        if part == "Applications" {
            let Some(child) = open_leftover_child(&root, "Applications", flag, tx, false)? else {
                return Ok(None);
            };
            root = child;
        }
        let Some(name) = name else {
            return Ok(Some(root));
        };
        open_leftover_child(&root, name, flag, tx, write)
    }
    pub(crate) fn leftover_anchors(&self, tx: Option<&Transaction>) -> Result<AnchorIndex, String> {
        let Some(root) = self.leftover_key("Uninstall", None, None, tx, false)? else {
            return Ok(HashMap::new());
        };
        let mut index: AnchorIndex = HashMap::new();
        for (i, item) in root.enum_keys().enumerate() {
            if i >= 10000 {
                return Err("Uninstall correlation reached its verification limit.".into());
            }
            let name = item.map_err(|_| "Uninstall correlation identifiers are unreadable.")?;
            let Some(key) = self.leftover_key("Uninstall", Some(&name), None, tx, false)? else {
                continue;
            };
            let Some(value) = read_value(&key, "InstallLocation")? else {
                continue;
            };
            let Some(directory) = ownership_directory(&value) else {
                continue;
            };
            index
                .entry(directory.to_ascii_lowercase())
                .or_default()
                .push((name, read_uninstall_snapshot(&key)));
        }
        Ok(index)
    }
    pub(crate) fn leftover_application(
        &self,
        name: &str,
        tx: Option<&Transaction>,
    ) -> Result<LeftoverAppState, String> {
        crate::changes::validate_app_path_name(name)?;
        let key = self
            .leftover_key("AppPaths", Some(name), None, tx, false)?
            .ok_or("The existing application registration is missing. No key will be recreated.")?;
        if key.enum_keys().next().is_some() {
            return Err(
                "Application registrations with child keys remain outside leftover cleanup scope."
                    .into(),
            );
        }
        let mut other = vec![];
        let mut value = None;
        let mut value_name = "Path".to_string();
        let mut bytes = 0;
        for (i, item) in key.enum_values().enumerate() {
            let (name, raw) = item.map_err(|_| "Application metadata is unreadable.")?;
            bytes += raw.bytes.len() + name.len();
            if i >= 32 || bytes > 16384 {
                return Err("Application metadata exceeds leftover verification limits.".into());
            }
            let stored = StoredValue {
                kind: raw.vtype as u32,
                bytes: raw.bytes.into_owned(),
            };
            if name.eq_ignore_ascii_case("Path") {
                value_name = name;
                value = Some(stored)
            } else {
                other.push(NamedValue {
                    name,
                    value: stored,
                })
            }
        }
        other.sort_by_key(|v| v.name.to_lowercase());
        Ok(LeftoverAppState {
            name: value_name,
            value,
            other,
        })
    }
    fn guarded_leftover(
        &self,
        app: &LeftoverBackup,
        tx: Option<&Transaction>,
    ) -> Result<Option<StoredValue>, String> {
        app.validate()?;
        if app.supported_type.is_some() {
            return self.guarded_supported_type(app, tx);
        }
        for view in [64, 32] {
            for (part, name) in [
                ("AppPaths", app.executable_name.as_str()),
                ("Uninstall", app.uninstall_key.as_str()),
                ("Applications", app.executable_name.as_str()),
            ] {
                if self
                    .leftover_key(part, Some(name), Some(view), tx, false)?
                    .is_some()
                {
                    return Err("A machine application counterpart exists. Leftover cleanup and restore are blocked.".into());
                }
            }
        }
        if self
            .leftover_key("Applications", Some(&app.executable_name), None, tx, false)?
            .is_some()
        {
            return Err("Another current-user application registration exists. Investigate its ownership before leftover cleanup.".into());
        }
        let anchors = self.leftover_anchors(tx)?;
        let matches = anchors
            .get(&app.directory.to_ascii_lowercase())
            .ok_or("The uninstall correlation anchor is missing.")?;
        if matches.len() != 1 || matches[0].0 != app.uninstall_key {
            return Err(
                "The application ownership evidence is now ambiguous. Nothing was overwritten."
                    .into(),
            );
        }
        if normalized_anchor(matches[0].1.as_ref().map_err(Clone::clone)?)? != app.anchor {
            return Err("The correlated uninstall metadata changed. Leftover cleanup or restore is blocked.".into());
        }
        if let Some(original) = &app.path_list {
            if search_directories(original)?
                .iter()
                .filter(|d| anchors.contains_key(&d.to_ascii_lowercase()))
                .count()
                != 1
            {
                return Err("More than one search directory now has uninstall ownership evidence. Path-list cleanup and restore are blocked.".into());
            }
        }
        let state = self.leftover_application(&app.executable_name, tx)?;
        if state.other != app.application_values
            || (state.value.is_some() && state.name != app.value_name)
        {
            return Err(
                "The application metadata or executable mapping changed. Nothing was overwritten."
                    .into(),
            );
        }
        Ok(state.value)
    }
    pub(crate) fn leftover_value(
        &self,
        app: &LeftoverBackup,
    ) -> Result<Option<StoredValue>, String> {
        let value = self.guarded_leftover(app, None)?;
        if app.path_list.is_some() && app.cleared_value()?.is_some() && value.is_none() {
            return Err("The retained search-path list is missing. Restore must not overwrite a different state.".into());
        }
        if app.path_list.is_some() && value == app.cleared_value()? {
            Ok(None)
        } else {
            Ok(value)
        }
    }
    pub(crate) fn leftover_access(&self, app: &LeftoverBackup) -> Result<(), String> {
        if app.supported_type.is_some() {
            return self.supported_type_access(app);
        }
        self.guarded_leftover(app, None)?;
        self.leftover_key("AppPaths", Some(&app.executable_name), None, None, true)?
            .ok_or("The existing application key is missing.")?;
        Ok(())
    }
    pub(crate) fn exchange_leftover_value(
        &self,
        app: &LeftoverBackup,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        if app.supported_type.is_some() {
            return self.exchange_supported_type(app, expected, replacement);
        }
        if expected.is_some() == replacement.is_some() {
            return Err("Only exact removal or restoration of the correlated search-path value is supported.".into());
        }
        let original = expected
            .or(replacement)
            .ok_or("Original leftover value is absent.")?;
        app.verify_original(original, &crate::LocalPathProbe)?;
        let cleared = app.cleared_value()?;
        let actual_expected = expected.or(cleared.as_ref());
        let actual_replacement = replacement.or(cleared.as_ref());
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.guarded_leftover(app, Some(&tx))?.as_ref() != actual_expected {
            return Err("The leftover value changed. No current value was overwritten.".into());
        }
        app.verify_original(original, &crate::LocalPathProbe)?;
        let key = self
            .leftover_key(
                "AppPaths",
                Some(&app.executable_name),
                None,
                Some(&tx),
                true,
            )?
            .ok_or("The existing application key is missing.")?;
        match actual_replacement {
            Some(value) => key.set_raw_value(
                &app.value_name,
                &RegValue {
                    vtype: REG_SZ,
                    bytes: Cow::Borrowed(&value.bytes),
                },
            ),
            None => key.delete_value(&app.value_name),
        }
        .map_err(|e| format!("Leftover value update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Leftover transaction did not commit: {e}"))
    }
}
