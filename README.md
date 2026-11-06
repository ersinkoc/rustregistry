# RustRegistry

A read-only Windows registry health explorer, built with Rust, Tauri 2, React, and TypeScript. English is the primary application language.

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

## Read-only boundary

All registry handles are opened explicitly with `KEY_READ` and the appropriate view flag. The application contains no registry write, delete, repair, import, elevation, shell execution, or installation commands. Only two frontend commands are exposed: `scan_registry` and `cancel_scan`. They operate on fixed registry locations; the frontend cannot supply an arbitrary registry path.

Scanning runs in a blocking worker outside the UI thread. Commands found in registry values are never executed. Direct network/device paths, mapped network drives, and detected reparse points are not followed for target verification. Registry access failures and partial/cancelled scans are reported explicitly.

Scan results remain in memory. The only saved UI preference is the theme in WebView local storage. No telemetry or remote content is used by the production frontend. Developer package installation and the development server naturally require their normal build-time connections.

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

`test:desktop` launches the **built release app** with a temporary local WebView2 debugging connection and verifies real native IPC scanning, filters, search, pagination, details, coverage, history, themes, the minimum desktop layout, and cancellation. The connection is only enabled for that test process; the production app configuration does not enable remote debugging. Results and screenshots are written to the ignored `.temp_files/` directory. The test requires an interactive Windows desktop. It does not create or modify registry fixtures.

For a real read-only scan without the GUI:

```powershell
npm run scan
```

For machine-readable JSON without npm log output, run `cargo run -p registry-core --bin registry-scan --quiet` directly. The report contains local application names and paths; keep it private.

## Project layout

- `crates/registry-core`: fixed registry inventory, conservative path analysis, and JSON CLI.
- `src-tauri`: desktop host, background scan coordination, cancellation, and restricted application configuration.
- `src`: English desktop UI, design tokens, result filtering, and frontend unit tests.
- `scripts/desktop-smoke.mjs`: verification against the packaged app and the real Windows registry.

The repository includes dependency lockfiles. No registry cleanup functionality is implemented in this release.
