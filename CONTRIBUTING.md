# Contributing to RustRegistry

## Set up the Windows workspace

Use Windows x64 with the Rust MSVC toolchain, Visual Studio C++ Build Tools and a Windows SDK that includes `fxc.exe`. Node.js 26 and npm are used for the repository's checks and the legacy WebView harness.

```powershell
npm ci
cargo run --locked -p registry-desktop
npm run check
```

The native UI is in `crates/registry-desktop`. Scanning, registry transactions, backups, and recovery are in `crates/registry-core`. The legacy WebView harness is in `src` and `src-tauri`. For changes to registry behavior, include an owned fixture that proves the original type and bytes can be recovered.

## Run focused checks

| Area                            | Command                                                           |
| ------------------------------- | ----------------------------------------------------------------- |
| GPUI layout and review flow     | `cargo test --locked -p registry-desktop`                         |
| Registry inventory and recovery | `cargo test --locked -p registry-core`                            |
| Read-only CLI scan              | `cargo run --locked -p registry-core --bin registry-scan --quiet` |
| Legacy WebView harness          | `npm run desktop:legacy:build`, then `npm run test:desktop`       |

Use disposable keys and temporary storage for tests that apply changes. Capture exact registry values with an independent reader before and after a mutation. Scrub local paths, commands, account names, and value data from anything attached to a public issue.

See the [registry reference](docs/registry-reference.md) for existing protections and the [release runbook](docs/releasing.md) for publishing.
