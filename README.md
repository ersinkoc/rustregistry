# RustRegistry

A Windows registry health explorer with read-only scanning and separately reviewed, reversible startup changes. Built with Rust, Tauri 2, React, and TypeScript. English is the primary application language.

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

The scanner has a fixed scope of 12 registry locations:

| Category          | Location under `Software\Microsoft\Windows\CurrentVersion` | Check                                    |
| ----------------- | ---------------------------------------------------------- | ---------------------------------------- |
| Startup entries   | `Run`, `RunOnce`                                           | Clearly resolved local executable target |
| Application paths | `App Paths`                                                | Default executable path                  |
| Uninstall records | `Uninstall`                                                | `InstallLocation` folder, when provided  |

Each location is read once under HKCU (shared view) and twice under HKLM (32-bit and 64-bit views). Uninstall records also show their reported display name, publisher, and version when available.

- **Found:** the expected local file or directory existed at scan time.
- **Review:** an unambiguously resolved local target was not found. A disconnected drive or uninstalled application may explain this; this is not a recommendation to delete the record.
- **Unverified:** the target is absent, ambiguous, inaccessible, unsupported, or could not be resolved reliably.

The app includes search, category/status filters, pagination, a record detail panel, location-level coverage notes, light/dark themes, cancellation, and an in-memory history of the last eight scans.

## Protected changes in 0.1.1

Scanning still opens registry handles with `KEY_READ`. A scan never changes registry values.

For a named `REG_SZ` or `REG_EXPAND_SZ` value in **HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run**, a confirmed missing local executable target makes **Review disable** available in the detail panel. HKLM, RunOnce, App Paths, uninstall entries, uncertain targets, and existing targets are not eligible. This release does not offer bulk cleanup, general registry editing, administrator elevation, or command execution.

1. Complete a scan, open an eligible entry, and choose **Review disable**.
2. Review the exact original command, path, and value name. Confirm the checkbox, then choose **Back up & disable**.
3. The backend rechecks the live value and missing target, saves and flushes a new backup, reads it back, and verifies its integrity checksum.
4. A Windows registry transaction compares the expected bytes and type, removes only that one value, and commits. A conflict or unavailable transaction fails closed.
5. Use **Backups & restore** to review restoring the exact original type and bytes. Restore requires the value name to be absent and never overwrites an existing value. Restoring a startup command may cause it to run at a later sign-in.

Backups are stored under the application's local data folder in `backups-v1`; the exact folder is displayed in the app. Backups survive restarts. Keep them private and intact: they contain original command lines and local paths. Integrity checks detect corruption, not a malicious program acting with your own account's full permissions. There is no backup import feature. If an external tool deletes the entire Run key, this release does not recreate it.

Review tokens expire after five minutes, are single-use, and are kept in backend memory. The frontend supplies only a scanned entry ID or backup ID, never an arbitrary registry path or replacement command. Preparing or cancelling a review does not change registry values or create a backup. Backup state is derived from the live registry, so a saved backup from an interrupted attempt remains discoverable.

Scanning runs in a blocking worker outside the UI thread. Commands found in registry values are never executed. Direct network/device paths, mapped network drives, and detected reparse points are not followed for target verification. Registry access failures and partial/cancelled scans are reported explicitly.

Scan results remain in memory. Confirmed changes save their backups locally, and the theme is saved in WebView local storage. No telemetry or remote content is used by the production frontend. Developer package installation and the development server naturally require their normal build-time connections.

The engine checks up to 5,000 entries per location and interprets string values up to 32 KiB. Limits are reported in coverage. The scan is a point-in-time inventory rather than an atomic registry snapshot. It does not inspect all registry hives, COM registrations, file associations, application functionality, malware, or overall Windows performance.

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

`test:desktop` launches the **built release app** with a temporary local WebView2 debugging connection and verifies real native IPC scanning, filters, search, pagination, details, coverage, history, themes, the minimum desktop layout, cancellation, backup discovery, and review/cancel controls. It never confirms changes to the user's actual startup entries. The connection is enabled only for that test process. Results and screenshots are written to the ignored `.temp_files/` directory; an interactive Windows desktop is required.

Rust tests cover backup failure, stale evidence, changed targets, conflicts, expiry, invalid tokens, and corrupted backups. Two Windows integration tests create uniquely named **non-startup** keys under `HKCU\\Software\\RustRegistryTests`, exercise transactions and a backup/disable/restart/restore round trip, and remove their own test keys afterward. They never modify the user's real startup list.

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
