# RustRegistry

A Windows registry health explorer with read-only scanning and separately reviewed, reversible startup, application path, orphaned uninstall-listing, and Open with suggestion changes. Built with Rust, Tauri 2, React, and TypeScript. English is the primary application language.

Open source under the [MIT license](LICENSE). See the [changelog](CHANGELOG.md) and [GitHub releases](https://github.com/ersinkoc/rustregistry/releases) for version history and Windows downloads.

## Run the desktop app

Requirements: Windows x64, Rust 1.93 or newer with the MSVC toolchain, Visual Studio C++ Build Tools with a Windows SDK, Node.js 26 or newer, and Microsoft Edge WebView2 Runtime.

```powershell
npm ci
npm run desktop
```

Build a standalone application with embedded frontend assets:

```powershell
npm run desktop:build
.\target\release\rustregistry.exe
```

The executable requires WebView2 on the target computer. This first release does not create an installer or request administrator access.

`npm run dev` starts a **browser preview only**. It cannot access the registry and explicitly shows that the desktop connection is unavailable. No sample records are substituted for live data.

## What it reads

The scanner has a fixed scope of 14 registry locations:

| Category          | Location under `Software\Microsoft\Windows\CurrentVersion` | Check                                    |
| ----------------- | ---------------------------------------------------------- | ---------------------------------------- |
| Startup entries   | `Run`, `RunOnce`                                           | Clearly resolved local executable target |
| Application paths | `App Paths`                                                | Default executable path                  |
| Uninstall records | `Uninstall`                                                | `InstallLocation` folder, when provided  |

The four locations above are each read once under HKCU (shared view) and twice under HKLM (32-bit and 64-bit views), giving 12 scopes. Two additional scopes read `Software\Classes\.extension\OpenWithProgids` under HKCU and HKLM once each: these extension/ProgID keys are shared on supported Windows. See [Microsoft’s registry view table](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys). Uninstall records also show their reported display name, publisher, and version when available.

- **Found:** the expected local file, directory, or suggested file-type registration existed at scan time.
- **Review:** an unambiguously resolved local target was not found. A disconnected drive or uninstalled application may explain this; this is not a recommendation to delete the record.
- **Unverified:** the target is absent, ambiguous, inaccessible, unsupported, or could not be resolved reliably.

The app includes search, category/status filters, pagination, a record detail panel, location-level coverage notes, light/dark themes, cancellation, and an in-memory history of the last eight scans.

## Protected changes in 0.1.1

Scanning still opens registry handles with `KEY_READ`. A scan never changes registry values.

For a named `REG_SZ` or `REG_EXPAND_SZ` value in **HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run**, a confirmed missing local executable target makes **Review disable** available in the detail panel. HKLM, RunOnce, uncertain targets, and existing targets are not eligible for startup changes. App Paths and uninstall scopes are described below. This release does not offer bulk cleanup, general registry editing, administrator elevation, or command execution.

1. Complete a scan, open an eligible entry, and choose **Review disable**.
2. Review the exact original command, path, and value name. Confirm the checkbox, then choose **Back up & disable**.
3. The backend rechecks the live value and missing target, saves and flushes a new backup, reads it back, and verifies its integrity checksum.
4. A Windows registry transaction compares the expected bytes and type, removes only that one value, and commits. A conflict or unavailable transaction fails closed.
5. Use **Backups & restore** to review restoring the exact original type and bytes. Restore requires the value name to be absent and never overwrites an existing value. Restoring a startup command may cause it to run at a later sign-in.

Backups are stored under the application's local data folder in `backups-v1`; the exact folder is displayed in the app. Backups survive restarts. Keep them private and intact: they contain original command lines and local paths. Integrity checks detect corruption, not a malicious program acting with your own account's full permissions. There is no backup import feature. If an external tool deletes the entire Run key, this release does not recreate it.

Review tokens expire after five minutes, are single-use, and are kept in backend memory. The frontend supplies only a scanned entry ID or backup ID, never an arbitrary registry path or replacement command. Preparing or cancelling a review does not change registry values or create a backup. Backup state is derived from the live registry, so a saved backup from an interrupted attempt remains discoverable.

## App Paths repair in 0.1.2

For **HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\name.exe**, a missing explicit local `.exe` target can offer **Review repair**. The review shows the exact `(Default)` executable mapping and how many other values will be preserved. **Back up & repair** saves a verified backup, then removes only that broken default mapping inside a conditional Windows transaction. It does not guess a replacement executable, remove the registration key, or change `Path` and other helper values.

Use **Backups & restore → Review restore** to put the exact original type and bytes back. Restore requires the key to still exist, its default value to be absent, and all helper metadata to still match the backup. A new default value, changed helper metadata, added child key, or unreadable registration blocks the action. The existing key's permissions are preserved because the key is never deleted or recreated.

Only single `.exe` registration names, flat non-link entries, at most 32 other values with a combined 16 KiB of data, and supported bounded text mappings are eligible. Extensionless targets are excluded because Windows can apply executable-extension fallback. See [Microsoft's App Paths documentation](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration). Machine-wide HKLM registrations remain read-only.

App Paths backups use a new integrity-protected record format in the same local backup folder. Existing `0.1.1` startup backups retain their original checksum and format and remain restorable without migration. The backup list identifies each record's scope and full registry path.

Scanning runs in a blocking worker outside the UI thread. Commands found in registry values are never executed. Direct network/device paths, mapped network drives, and detected reparse points are not followed for target verification. Registry access failures and partial/cancelled scans are reported explicitly.

Scan results remain in memory. Confirmed changes save their backups locally, and the theme is saved in WebView local storage. No telemetry or remote content is used by the production frontend. Developer package installation and the development server naturally require their normal build-time connections.

The engine checks up to 5,000 entries per location (and at most 20,000 direct Classes child keys while discovering file extensions) and interprets string values up to 32 KiB. Limits are reported in coverage. The scan is a point-in-time inventory rather than an atomic registry snapshot. It does not inspect all registry hives, COM registrations, default application handlers, application functionality, malware, or overall Windows performance.

## Uninstall listing repair in 0.1.3

For flat entries under **HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall**, repair requires a nonempty display name, a confirmed missing local `InstallLocation` directory, and confirmed missing explicit local `.exe` targets for `UninstallString` and any `QuietUninstallString`. A missing directory alone is insufficient. Existing or ambiguous uninstallers, MSI/`WindowsInstaller` records, nonzero or malformed `SystemComponent`/`NoRemove` flags, update/group markers, child keys, registry links, and oversized metadata remain outside repair scope. HKLM remains read-only.

**Review repair → Back up & hide entry** saves every original registry value, type, and raw byte before setting only the `SystemComponent` DWORD to `1`. This is a reversible quarantine of the orphaned installed-program listing. It does **not** uninstall software, run the uninstall command, fix missing application files, delete the registration key, or change its permissions. The key stays in RustRegistry's inventory as a hidden/system-component record. Visibility behavior in other inventory tools may differ; see [Microsoft's Add/Remove Programs documentation](https://learn.microsoft.com/en-us/windows/win32/msi/configuring-add-remove-programs-with-windows-installer).

**Backups & restore → Review restore** restores the original absent or DWORD-zero visibility flag only when the entire live value snapshot matches the backed-up hidden state. Changed names, paths, commands, versions, custom values, added child keys, or a missing key block restoration. Existing keys are never recreated. Windows-managed key write timestamps naturally change; the backup covers original value contents, while key permissions stay untouched throughout.

Uninstall snapshots are limited to 64 values and 32 KiB of raw data; the complete backup must also fit the existing backup-file limit. The new integrity-protected backup format coexists with unchanged startup and App Paths formats in the local backup folder. Older backups are not migrated or rewritten.

## File association repair in 0.1.4

This patch inventories **Open with suggestions**, not every file association or default handler. An empty `REG_NONE` or `REG_SZ` value under `HKCU\Software\Classes\.extension\OpenWithProgids` names a suggested file-type registration (ProgID). A registration absent from both HKCU and HKLM Classes roots is marked for review. An existing registration only proves the key exists; its handler or application is not executed or tested. See [Microsoft’s Open with registration documentation](https://learn.microsoft.com/en-us/windows/win32/shell/how-to-include-an-application-on-the-open-with-dialog-box).

**Review repair → Back up & remove suggestion** saves the exact original value type and bytes plus guarded metadata, then conditionally removes only that named optional suggestion. It does not guess another application, fix missing executables, delete keys, change permissions, or modify an extension’s default value or protected `UserChoice` selection. Suggestions selected by either user/machine extension defaults or `UserChoice` are excluded. A same-named HKLM suggestion is also excluded because it would remain effective after removing the user value. Machine registrations remain read-only.

**Backups & restore → Review restore** puts the exact original suggestion back only when its value is absent, both application registrations are still absent, and all guarded metadata matches. The guard includes every other suggestion, user/machine extension values, and any read-only `UserChoice` value snapshot. A new registration, changed selection or metadata, nested suggestion key, unreadable location, malformed value, or missing existing key blocks the action. No key is recreated. All reads are repeated before the conditional transaction; scans are point-in-time inventories, not atomic snapshots of the whole registry.

The initial repair scope accepts ASCII extensions of 2–64 bytes (letters, digits, `_`, `-`, `+` after the dot) and single ASCII ProgIDs of at most 128 bytes with a leading letter and at least one dot. Unsupported names remain unverified or appear in coverage notes. Each guarded value collection is limited to 64 values/32 KiB and excludes registry links and ambiguous metadata. The complete backup must fit the existing 256 KiB limit. New association backups retain unchanged support for all three earlier backup formats; older files are never rewritten.

## Verify

```powershell
npm run format:check
npm run typecheck
npm test
cargo fmt --all --check
npm run test:rust
npm run check:rust
npm run desktop:build
npm run test:desktop
```

`test:desktop` launches the **built release app** with a temporary local WebView2 debugging connection and verifies real native IPC scanning, filters, search, pagination, details, coverage, history, themes, the minimum desktop layout, cancellation, backup discovery, and review/cancel controls. It never confirms changes to the user's actual startup entries. For App Paths it creates one uniquely named, owned `RustRegistry-E2E-<uuid>.exe` test registration, runs repair and restore through the real UI, independently reads the resulting registry state, then removes only its own registration and test backup. Existing user registrations and backups are not edited. The helper requires an existing current-user App Paths root and does not change PowerShell execution policy. The debugging connection is enabled only for that test process. Results and screenshots are written to the ignored `.temp_files/` directory; an interactive Windows desktop is required.

Rust tests cover backup failure, stale evidence, changed targets, metadata conflicts, expiry, invalid tokens, corrupted backups, and fixed `0.1.1`/`0.1.2`/`0.1.3` backup fixtures. Seven Windows integration tests create uniquely named **non-startup** keys under `HKCU\\Software\\RustRegistryTests`, exercise transactions and backup/repair/restart/restore round trips, and remove their own test keys afterward. Uninstall tests cover both an originally absent flag and an originally zero flag, including exact raw metadata preservation. They never modify the user's real startup list.

The desktop suite also creates one uniquely named `RustRegistry-E2E-Uninstall-<uuid>` registration in the existing current-user Uninstall root. It verifies review/cancel, full-backup hide, hidden-state diagnostics, reload and restore through the packaged UI. A separate PowerShell reader checks all fixture values, types, and owner/group/DACL permissions before and after. The suite cleans only its own registration and matching backup; existing entries and user backups are not edited. No Windows Settings/Control Panel list UI assertion is made.

The desktop suite additionally creates a uniquely named `.rr<uuid>` extension with two owned Open with suggestions and an owned default metadata value. It tests review/cancel, one-suggestion repair, exclusion of the default-selected suggestion, UI reload, and exact restore. An independent registry reader checks the original value types, other suggestions, extension defaults, permissions, and absence of UserChoice throughout. Only its owned extension and matching backup are removed afterward. The suite never creates or changes a protected UserChoice selection and does not assert Explorer’s cached Open with menu presentation.

For a real read-only scan without the GUI:

```powershell
npm run scan
```

For machine-readable JSON without npm log output, run `cargo run -p registry-core --bin registry-scan --quiet` directly. The report contains local application names and paths; keep it private.

## Project layout

- `crates/registry-core`: fixed registry inventory, conservative path analysis, backup/change engine, transactional Windows adapter, and read-only JSON CLI.
- `src-tauri`: desktop host, background scan coordination, cancellation, and restricted application configuration.
- `src`: English desktop UI, design tokens, result filtering, and frontend unit tests.
- `scripts/desktop-smoke.mjs`: verification against the packaged app and the real Windows registry.

The repository includes dependency lockfiles and checks version consistency before the main verification suite. Development proceeds through small patch releases; minor versions are reserved for larger milestones.

## Upstream dependency notice

The cross-platform Tauri dependency lockfile includes Linux-only `glib` 0.18.5, which has upstream advisory [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html). It is absent from this application's Windows x64 dependency graph. Linux builds are not supported by this project; revisit the upstream dependency before adding Linux support. This notice does not represent a full security audit.
