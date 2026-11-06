# Changelog

Each published version has a matching Git tag and GitHub release. During `0.x`, development proceeds in small patch releases (`0.1.0`, `0.1.1`, `0.1.2`). Minor versions are reserved for larger planned milestones; major versions are reserved for an explicitly planned stable release.

## 0.1.2 — 2026-11-07

- Add backed-up repair and exact-value restore for confirmed missing executable mappings in the current user's `App Paths` entries.
- Repair removes only the `(Default)` mapping. The key, `Path`, and other metadata stay in place and must still match before repair or restore.
- Restrict repairs to flat, bounded `.exe` registrations with explicit missing local `.exe` targets; nested registrations, extensionless fallback targets, HKLM, and uncertain paths remain excluded.
- Introduce integrity-protected App Paths backups while retaining unchanged support for `0.1.1` startup backups.
- Add English App Paths review/restore dialogs and scope-aware backup listings.
- Add isolated native transaction, metadata-conflict, legacy-backup, and packaged desktop repair/restore checks using an owned temporary registration.

## 0.1.1 — 2026-11-06

- Add separately reviewed disable/restore actions for confirmed missing-target values in the current user's `Run` key.
- Require a flushed, read-back-verified backup of the original registry type and bytes before disabling a value.
- Add backup integrity checks, persistent local backup discovery, and conflict-safe restore without overwrites.
- Use Windows registry transactions for conditional changes; reject stale scans, expired plans, uncertain paths, and unsupported scopes.
- Add English confirmation dialogs and a Backups & restore page. Scans remain read-only; no automatic cleanup or administrator elevation is introduced.
- Add isolated Windows registry round-trip tests and policy/error-path tests.
- Keep version labels synchronized with the application manifest.

## 0.1.0 — 2026-11-06

- First public release under the MIT license.
- Read-only registry scanning across 12 Windows x64 locations.
- Startup, App Paths, and uninstall record diagnostics with conservative path checks.
- English desktop UI with search, filters, record details, coverage, session history, and light/dark themes.
- Background scanning with cancellation. No registry modifications.
- Unit tests and desktop verification against the packaged application.
