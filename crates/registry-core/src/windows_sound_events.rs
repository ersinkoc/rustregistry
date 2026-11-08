use super::{open_registration_path, read_value, WindowsRegistryStore};
use crate::{
    changes::{NamedValue, StoredValue},
    sound_events::*,
};
use std::borrow::Cow;
use winreg::{enums::*, transaction::Transaction, RegKey, RegValue};

#[cfg(test)]
#[path = "windows_sound_tests.rs"]
mod tests;

fn values(key: &RegKey) -> Result<Vec<NamedValue>, String> {
    let mut out = vec![];
    let mut size = 0;
    for item in key.enum_values() {
        let (name, value) = item.map_err(|_| "Sound metadata is unreadable.")?;
        size += name.len() + value.bytes.len();
        if out.len() >= 32 || size > 32768 {
            return Err("Sound metadata exceeds verification limits.".into());
        }
        out.push(NamedValue {
            name,
            value: StoredValue {
                kind: value.vtype as u32,
                bytes: value.bytes.into_owned(),
            },
        })
    }
    out.sort_by_key(|v| v.name.to_lowercase());
    Ok(out)
}
impl WindowsRegistryStore {
    fn sound_path(&self) -> &str {
        #[cfg(test)]
        if let Some(path) = &self.sound_test_root {
            return path;
        }
        SOUND_SCHEMES
    }
    fn sound_key(
        &self,
        suffix: &str,
        tx: Option<&Transaction>,
        write: bool,
    ) -> Result<RegKey, String> {
        let path = if suffix.is_empty() {
            self.sound_path().into()
        } else {
            format!(r"{}\{suffix}", self.sound_path())
        };
        open_registration_path(HKEY_CURRENT_USER, &path, KEY_WOW64_64KEY, tx, write)?
            .ok_or("An existing sound key is missing. No key will be recreated.".into())
    }
    fn no_machine_sound(
        &self,
        application: &str,
        event: &str,
        tx: Option<&Transaction>,
    ) -> Result<(), String> {
        #[cfg(test)]
        let (hive, path) = if let Some(base) = &self.sound_test_machine {
            (HKEY_CURRENT_USER, format!(r"{base}\{application}\{event}"))
        } else {
            (
                HKEY_LOCAL_MACHINE,
                format!(r"{SOUND_APPS}\{application}\{event}"),
            )
        };
        #[cfg(not(test))]
        let (hive, path) = (
            HKEY_LOCAL_MACHINE,
            format!(r"{SOUND_APPS}\{application}\{event}"),
        );
        if open_registration_path(hive, &path, KEY_WOW64_64KEY, tx, false)?.is_some() {
            return Err("A machine sound-event counterpart exists. Fallback changes remain outside repair scope.".into());
        }
        Ok(())
    }
    pub(crate) fn sound_snapshot(
        &self,
        application: &str,
        event: &str,
        tx: Option<&Transaction>,
    ) -> Result<SoundState, String> {
        component(application)?;
        component(event)?;
        self.no_machine_sound(application, event, tx)?;
        let selection = read_value(&self.sound_key("", tx, false)?, "")?;
        let app = self.sound_key(&format!(r"Apps\{application}"), tx, false)?;
        let event_key = self.sound_key(&format!(r"Apps\{application}\{event}"), tx, false)?;
        let mut variants = vec![];
        let mut current = None;
        let mut has_current = false;
        for item in event_key.enum_keys() {
            let name = item.map_err(|_| "Sound scheme names are unreadable.")?;
            component(&name)?;
            if variants.len() >= 32 {
                return Err("Sound scheme verification limit reached.".into());
            }
            let key = self.sound_key(&format!(r"Apps\{application}\{event}\{name}"), tx, false)?;
            if key.enum_keys().next().is_some() {
                return Err("Sound scheme keys with children remain read-only.".into());
            }
            let mut data = values(&key)?;
            if name.eq_ignore_ascii_case(CURRENT) {
                has_current = true;
                current = read_value(&key, "")?;
                data.retain(|v| !v.name.is_empty());
            }
            variants.push(SoundVariant { name, values: data });
        }
        if !has_current {
            return Err(
                "The existing current sound key is missing. No key will be recreated.".into(),
            );
        }
        variants.sort_by_key(|v| v.name.to_lowercase());
        Ok(SoundState {
            value: current,
            guard: SoundGuard {
                selected: selection,
                application_values: values(&app)?,
                event_values: values(&event_key)?,
                variants,
            },
        })
    }
    fn guarded_sound(
        &self,
        app: &SoundBackup,
        tx: Option<&Transaction>,
    ) -> Result<Option<StoredValue>, String> {
        app.validate()?;
        let state = self.sound_snapshot(&app.application, &app.event, tx)?;
        if state.guard != app.guard {
            return Err("The sound scheme selection or event metadata changed. Review again; nothing was overwritten.".into());
        }
        Ok(if state.value.as_ref() == Some(&empty_assignment()) {
            None
        } else {
            state.value
        })
    }
    pub(crate) fn read_sound_event(
        &self,
        app: &SoundBackup,
    ) -> Result<Option<StoredValue>, String> {
        self.guarded_sound(app, None)
    }
    pub(crate) fn sound_access(&self, app: &SoundBackup) -> Result<(), String> {
        self.guarded_sound(app, None)?;
        self.sound_key(
            &format!(r"Apps\{}\{}\{CURRENT}", app.application, app.event),
            None,
            true,
        )
        .map(|_| ())
    }
    pub(crate) fn exchange_sound_event(
        &self,
        app: &SoundBackup,
        expected: Option<&StoredValue>,
        replacement: Option<&StoredValue>,
    ) -> Result<(), String> {
        app.validate()?;
        if expected.is_some() == replacement.is_some() {
            return Err(
                "Only exact clearing or restoration of one sound assignment is supported.".into(),
            );
        }
        let original = expected
            .or(replacement)
            .ok_or("Original sound assignment is absent.")?;
        if original.kind != 1 || original.text()? != app.target {
            return Err("Sound assignment does not match original backup evidence.".into());
        }
        let tx = Transaction::new()
            .map_err(|_| "Registry transactions are unavailable. Nothing was changed.")?;
        if self.guarded_sound(app, Some(&tx))?.as_ref() != expected {
            return Err("The current sound assignment changed. No value was overwritten.".into());
        }
        let key = self.sound_key(
            &format!(r"Apps\{}\{}\{CURRENT}", app.application, app.event),
            Some(&tx),
            true,
        )?;
        let cleared = empty_assignment();
        let value = replacement.unwrap_or(&cleared);
        key.set_raw_value(
            "",
            &RegValue {
                vtype: REG_SZ,
                bytes: Cow::Borrowed(&value.bytes),
            },
        )
        .map_err(|e| format!("Sound assignment update failed: {e}"))?;
        tx.commit()
            .map_err(|e| format!("Sound transaction did not commit: {e}"))
    }
}
