use super::*;
use crate::{
    leftover_types::SupportedTypeBackup,
    windows_changes::applications::{only_child, values},
};

pub(crate) struct SupportedTypeState {
    pub application_values: Vec<NamedValue>,
    pub guard: SupportedTypeBackup,
    pub hints: Vec<NamedValue>,
}
fn required_child(
    parent: &RegKey,
    name: &str,
    tx: Option<&Transaction>,
    write: bool,
) -> Result<RegKey, String> {
    open_leftover_child(parent, name, KEY_WOW64_64KEY, tx, write)?
        .ok_or_else(|| "An application suggestion key is missing. Keys are never recreated.".into())
}
impl WindowsRegistryStore {
    pub(crate) fn leftover_type_names(&self) -> Result<Vec<String>, String> {
        let Some(root) = self.leftover_key("Applications", None, None, None, false)? else {
            return Ok(vec![]);
        };
        let names = root
            .enum_keys()
            .take(10001)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Application suggestion inventory could not be completely read.")?;
        if names.len() > 10000 {
            return Err("Application suggestion inventory reached its limit.".into());
        }
        Ok(names)
    }
    pub(crate) fn leftover_type_state(
        &self,
        name: &str,
        tx: Option<&Transaction>,
    ) -> Result<SupportedTypeState, String> {
        crate::applications::validate_application_name(name)?;
        let root = self
            .leftover_key("Applications", Some(name), None, tx, false)?
            .ok_or("The application registration is missing. No key will be recreated.")?;
        let children = root
            .enum_keys()
            .take(4)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "Application children cannot be verified.")?;
        if !children.iter().any(|s| s.eq_ignore_ascii_case("shell"))
            || !children
                .iter()
                .any(|s| s.eq_ignore_ascii_case("SupportedTypes"))
            || children.iter().any(|s| {
                !["shell", "SupportedTypes", "DefaultIcon"]
                    .iter()
                    .any(|allowed| s.eq_ignore_ascii_case(allowed))
            })
        {
            return Err(
                "Alternative, delegated or unknown application activation keys remain protected."
                    .into(),
            );
        }
        let shell = required_child(&root, "shell", tx, false)?;
        only_child(&shell, Some("open"))?;
        let verb = required_child(&shell, "open", tx, false)?;
        only_child(&verb, Some("command"))?;
        let command = required_child(&verb, "command", tx, false)?;
        only_child(&command, None)?;
        let hints = required_child(&root, "SupportedTypes", tx, false)?;
        only_child(&hints, None)?;
        let icon = if children
            .iter()
            .any(|s| s.eq_ignore_ascii_case("DefaultIcon"))
        {
            let key = required_child(&root, "DefaultIcon", tx, false)?;
            only_child(&key, None)?;
            Some(values(&key)?)
        } else {
            None
        };
        let guard = SupportedTypeBackup {
            shell_values: values(&shell)?,
            verb_values: values(&verb)?,
            command_values: values(&command)?,
            icon_values: icon,
        };
        guard.validate()?;
        Ok(SupportedTypeState {
            application_values: values(&root)?,
            guard,
            hints: values(&hints)?,
        })
    }
    pub(super) fn guarded_supported_type(
        &self,
        app: &LeftoverBackup,
        tx: Option<&Transaction>,
    ) -> Result<Option<StoredValue>, String> {
        app.validate()?;
        for view in [64, 32] {
            for (part, name) in [
                ("Applications", app.executable_name.as_str()),
                ("AppPaths", app.executable_name.as_str()),
                ("Uninstall", app.uninstall_key.as_str()),
            ] {
                if self
                    .leftover_key(part, Some(name), Some(view), tx, false)?
                    .is_some()
                {
                    return Err("A machine application counterpart exists. Suggestion cleanup and restore are blocked.".into());
                }
            }
        }
        if self
            .leftover_key("AppPaths", Some(&app.executable_name), None, tx, false)?
            .is_some()
        {
            return Err("A current-user App Paths counterpart exists. Investigate its ownership before suggestion cleanup.".into());
        }
        let anchors = self.leftover_anchors(tx)?;
        let owners = anchors
            .get(&app.directory.to_ascii_lowercase())
            .ok_or("The uninstall correlation anchor is missing.")?;
        if owners.len() != 1 || owners[0].0 != app.uninstall_key {
            return Err(
                "The application ownership evidence is now ambiguous. Nothing was overwritten."
                    .into(),
            );
        }
        if normalized_anchor(owners[0].1.as_ref().map_err(Clone::clone)?)? != app.anchor {
            return Err("The correlated uninstall metadata changed. Suggestion cleanup and restore are blocked.".into());
        }
        let state = self.leftover_type_state(&app.executable_name, tx)?;
        if state.application_values != app.application_values
            || Some(&state.guard) != app.supported_type.as_deref()
        {
            return Err(
                "The application command or metadata changed. Nothing was overwritten.".into(),
            );
        }
        match state
            .hints
            .into_iter()
            .find(|v| v.name.eq_ignore_ascii_case(&app.value_name))
        {
            Some(v) if v.name != app.value_name => {
                Err("The suggestion value spelling changed. Nothing was overwritten.".into())
            }
            Some(v) => Ok(Some(v.value)),
            None => Ok(None),
        }
    }
    pub(super) fn supported_type_access(&self, app: &LeftoverBackup) -> Result<(), String> {
        self.guarded_supported_type(app, None)?;
        let root = self
            .leftover_key(
                "Applications",
                Some(&app.executable_name),
                None,
                None,
                false,
            )?
            .ok_or("The application registration is missing.")?;
        required_child(&root, "SupportedTypes", None, true)?;
        Ok(())
    }
    pub(super) fn exchange_supported_type(
        &self,
        app: &LeftoverBackup,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        if expected.is_some() == replacement.is_some() {
            return Err(
                "Only exact removal or restoration of one file-type suggestion is supported."
                    .into(),
            );
        }
        let original = expected
            .or(replacement)
            .ok_or("The suggestion original value is absent.")?;
        app.verify_original(original, &crate::LocalPathProbe)?;
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.guarded_supported_type(app, Some(&tx))?.as_ref() != expected {
            return Err("The suggestion value changed. Nothing was overwritten.".into());
        }
        app.verify_original(original, &crate::LocalPathProbe)?;
        let root = self
            .leftover_key(
                "Applications",
                Some(&app.executable_name),
                None,
                Some(&tx),
                false,
            )?
            .ok_or("The application registration is missing.")?;
        let key = required_child(&root, "SupportedTypes", Some(&tx), true)?;
        match replacement {
            Some(value) => key.set_raw_value(
                &app.value_name,
                &RegValue {
                    vtype: REG_SZ,
                    bytes: Cow::Borrowed(&value.bytes),
                },
            ),
            None => key.delete_value(&app.value_name),
        }
        .map_err(|e| format!("The file-type suggestion update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("The suggestion transaction did not commit: {e}"))
    }
}
