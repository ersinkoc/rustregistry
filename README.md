# RustRegistry

<img src="src-tauri/icons/128x128.png" alt="RustRegistry icon" width="64" height="64">

A native Windows utility for inspecting registry references, reviewing supported repairs, and undoing changes from verified backups. Built with Rust and GPUI.

[![Latest release](https://img.shields.io/github/v/release/ersinkoc/rustregistry)](https://github.com/ersinkoc/rustregistry/releases/latest)
[![Windows checks](https://github.com/ersinkoc/rustregistry/actions/workflows/windows.yml/badge.svg?branch=main)](https://github.com/ersinkoc/rustregistry/actions/workflows/windows.yml)
[![MIT license](https://img.shields.io/github/license/ersinkoc/rustregistry)](LICENSE)

## Download

Get the Windows x64 ZIP from [GitHub Releases](https://github.com/ersinkoc/rustregistry/releases/latest), extract it, and run `rustregistry.exe`. The portable app uses DirectX 11 and needs neither Node.js nor WebView2.

For verification, download `SHA256SUMS.txt` alongside the ZIP and compare its ZIP entry with the result of `Get-FileHash -Algorithm SHA256 <path-to-zip>`. Release notes also link to the build and its GitHub provenance.

## Use RustRegistry

1. **Run scan** to inspect 68 logical registry sections without writing to the registry.
2. **Explore the results** by name, category, or status. The inspector shows the registry key, view, value data, target and assessment.
3. **Review a change** from an eligible record or from **Clean registry**. Quick Clean uses the chosen category. Full Clean spans eligible categories. Personal history requires explicit selection.
4. **Recover an original** through **Backups & restore** or review **Undo** in **Recovery Center**. Interrupted operations can be reviewed after reopening the app.

A **Review** result means a resolved target was missing at scan time. Disconnected drives and removed applications can produce the same result. Review the evidence before choosing a change.

| Shortcut  | Action                       |
| --------- | ---------------------------- |
| `Ctrl+R`  | Run a live scan              |
| `Ctrl+F`  | Focus search                 |
| `Ctrl+I`  | Toggle the inspector         |
| `↑` / `↓` | Move through focused results |

Saved scans can be reopened read-only. The explorer supports filtered JSON export from a live scan. Settings offer system, light and dark appearance and three text sizes.

## Backups and local data

RustRegistry saves and verifies an original before applying a supported change, then rechecks the live registry. Restoration skips conflicts and preserves values that already match their backups. The operation journal records intent and outcome so interrupted work can be reviewed without automatically resuming it.

Upgrading from an earlier release keeps the same local-data folder at `%LOCALAPPDATA%\dev.rustregistry.desktop`. Keep `backups-v1` and `operations-v1` together. Saved scans and JSON exports are stored separately. These files can contain local paths, commands and registry data. Review them before sharing.

Read-only scanning works without elevation. Some supported repairs require existing Windows write permissions. See the [registry reference](docs/registry-reference.md) for scan coverage, eligibility and recovery rules.

## Build from source

Use Windows x64, Rust 1.93 or later with the MSVC toolchain, and Visual Studio C++ Build Tools with a Windows SDK that includes `fxc.exe`.

```powershell
cargo run --locked -p registry-desktop
cargo build --locked --release -p registry-desktop
```

The release binary is `target\release\rustregistry.exe` for a native x64 build. See [contributing](CONTRIBUTING.md) for tests and the legacy WebView regression harness.

## Project links

- [Changelog](CHANGELOG.md)
- [Registry reference](docs/registry-reference.md)
- [Release runbook](docs/releasing.md)
- [Security reporting](SECURITY.md)
- [MIT license](LICENSE)
