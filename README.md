# RustRegistry

A Windows registry health explorer with read-only scanning and separately reviewed, reversible application suggestion, startup, application path, orphaned uninstall-listing, Open with suggestion, guarded COM DLL/handler/local-server mapping, and supported service startup changes. Built with Rust, Tauri 2, React, and TypeScript. English is the primary application language.

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

The executable requires WebView2 on the target computer. This release does not create an installer or automatically request administrator access. Service repair requires existing SCM configuration rights; read-only scanning does not require elevation.

`npm run dev` starts a **browser preview only**. It cannot access the registry and explicitly shows that the desktop connection is unavailable. No sample records are substituted for live data.

## What it reads

The scanner has a fixed scope of 23 registry locations:

| Category          | Location under `Software\Microsoft\Windows\CurrentVersion` | Check                                    |
| ----------------- | ---------------------------------------------------------- | ---------------------------------------- |
| Startup entries   | `Run`, `RunOnce`                                           | Clearly resolved local executable target |
| Application paths | `App Paths`                                                | Default executable path                  |
| Uninstall records | `Uninstall`                                                | `InstallLocation` folder, when provided  |

The four locations above are each read once under HKCU (shared view) and twice under HKLM (32-bit and 64-bit views), giving 12 scopes. Two additional scopes read `Software\Classes\.extension\OpenWithProgids` under HKCU and HKLM once each: these extension/ProgID keys are shared on supported Windows. See [Microsoft’s registry view table](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys). Four more scopes inventory `Software\Classes\CLSID\{GUID}\InprocServer32` under HKCU and HKLM in separate 32-bit and 64-bit views. COM inventory also includes LocalServer32 and InprocHandler32 mappings. Two more scopes inventory registered application open commands under shared HKCU/HKLM `Software\Classes\Applications` roots. Three more scopes cover shared-system Services ImagePath values and 32/64-bit SharedDLLs reference counts. Shared-file registrations remain read-only. Service repair in 0.1.6 is limited to the guarded policy described below. COM and shared-file target probing is limited to 64-bit mappings; 32-bit targets remain unverified because their filesystem/environment resolution requires a 32-bit context. Uninstall records also show their reported display name, publisher, and version when available.

- **Found:** the expected local file, directory, or suggested file-type registration existed at scan time.
- **Review:** an unambiguously resolved local target was not found. A disconnected drive or uninstalled application may explain this; this is not a recommendation to delete the record.
- **Unverified:** the target is absent, ambiguous, inaccessible, unsupported, or could not be resolved reliably.

The app includes search, category/status filters, pagination, a record detail panel, location-level coverage notes, light/dark themes, cancellation, and an in-memory history of the last eight scans.

## Protected changes in 0.1.1

Scanning still opens registry handles with `KEY_READ`. A scan never changes registry values.

For a named `REG_SZ` or `REG_EXPAND_SZ` value in **HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run**, a confirmed missing local executable target makes **Review disable** available in the detail panel. HKLM, RunOnce, uncertain targets, and existing targets are not eligible for startup changes. App Paths and uninstall scopes are described below. This startup scope does not include RunOnce. Quick Clean is described below; arbitrary registry editing and command execution are not supported.

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

The engine checks up to 10,000 entries per location (and at most 20,000 direct Classes child keys while discovering file extensions) and interprets string values up to 32 KiB. Limits are reported in coverage. The scan is a point-in-time inventory rather than an atomic registry snapshot. Exact duplicate found targets reuse their first positive observation only within that scan; missing/uncertain targets and every repair verification remain uncached. It does not inspect all registry hives, COM activation functionality, default application handlers, application functionality, malware, or overall Windows performance.

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

## COM DLL mapping repair in 0.1.5

This patch inventories `InprocServer32`, `InprocHandler32`, and `LocalServer32` default mappings for braced, nonzero CLSIDs in both hives and both architecture views. The initial 0.1.5 repair scope supports simple InprocServer32 mappings; 0.1.7 adds the two guarded forms described below. It does not enumerate all COM registration types or activate any COM object. The 32-bit mappings are shown as **Unverified** without probing DLL paths; 64-bit targets use the existing conservative local file checks. See Microsoft’s [InprocServer32 documentation](https://learn.microsoft.com/en-us/windows/win32/com/inprocserver32) and [registry architecture view table](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys).

**Review repair → Back up & disable mapping** is available only for a simple **current-user 64-bit** registration with a confirmed missing explicit local `.dll` target. The class must have exactly one child, `InprocServer32`, with no nested server keys. Its only supported class value is an optional REG_SZ default description; server metadata may contain only an optional REG_SZ `ThreadingModel` with an empty or documented threading model. Unknown metadata, managed-server fields, AppID/services, TreatAs/other activation children, inaccessible data, registry links, and a same-view HKLM class block the action. Machine and 32-bit mappings remain read-only. See Microsoft’s [CLSID registration options](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm).

A verified backup saves the exact original DLL path type and bytes, class values, threading metadata, CLSID, and architecture view before a conditional registry transaction removes only the default path value. The class and server keys, their permissions, other metadata, and application files remain intact. The app does not load or register DLLs, run `regsvr32`, guess replacement files, or change machine registrations. This is reversible disabling of a missing-target mapping, not repair of missing application files.

**Backups & restore → Review restore** restores the exact original path only when the existing key is still present, its default value is absent, class/server metadata matches the backup, and no machine counterpart or alternate activation has appeared. A conflict is never overwritten and deleted keys are never recreated. Restore can permit later COM loading if the DLL exists again; the app itself never activates it. Original key write timestamps naturally change; permissions are preserved without deleting keys.

COM backups use a new integrity-protected format alongside all four earlier formats in the same local backup folder. Fixed legacy fixtures verify their unchanged checksums and restore behavior. Existing backup limits and single-use, expiring confirmation tokens still apply.

## Quick Clean and selected cleaning in 0.1.5

Use **Clean registry** to review supported registry/service repair candidates after a completed scan. **Quick Clean** proposes up to 100 candidates from the latest backend-cached report. **Clean selected** lets you search and choose exact entries, up to the same limit. A review shows every entry, action, original value, registry path, architecture, and any skipped entry before an explicit confirmation. Scanning and preparing/cancelling a cleaning review never modify registry values or create backups.

Each change uses the same scope-specific rechecks, verified backup, and conditional registry transaction as an individual repair. Cleaning is sequential and stops at the first failed entry; it is not atomic across the batch. Earlier successes remain individually restorable from **Backups & restore**, and unattempted entries are reported. Sibling values in one guarded registration are deferred to a later scan to avoid invalidating one another’s metadata guards. Expired reviews, duplicate IDs, unknown IDs, stale scans, and unsupported scopes are rejected or explicitly skipped. Quick Clean never treats every review finding as eligible.

Additional read-only inventory includes service/driver `ImagePath` values under `HKLM\SYSTEM\CurrentControlSet\Services` and both views of `HKLM\Software\Microsoft\Windows\CurrentVersion\SharedDLLs`. It does not start/stop services, change driver configuration, alter reference counts, or delete files. Relative kernel paths, ambiguous commands, and 32-bit shared-file targets remain unverified. See Microsoft’s [Services registry documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree) and [shared-file usage count documentation](https://learn.microsoft.com/en-us/sql/odbc/reference/install/usage-counting?view=sql-server-ver17).

## Service startup repair in 0.1.6

A service is eligible only when its executable is a confirmed missing **literal absolute local `.exe` outside Windows**, it is stopped, has no dependent services or dependencies, uses its own process and the built-in LocalService account, and its startup type is Manual. Existing `SERVICE_CHANGE_CONFIG` and read/security permissions must be granted to the process. The app never changes permissions or requests elevation automatically. Drivers, Auto/Boot/System startup, LocalSystem/custom accounts, shared processes, critical error handling, protected services, triggers, recovery actions, load groups, custom/nested parameters, unknown metadata, environment-dependent commands, and uncertain paths remain read-only.

**Review repair → Back up & disable service** stores the original Start DWORD, full supported registry/security value snapshot, SCM configuration, and service security descriptor in an integrity-checked local backup. It then uses **ChangeServiceConfigW** to change only startup from Manual (`3`) to Disabled (`4`), preserving every other configuration field. It does not remove a service, change its executable/account, or start/stop it. **Review restore → Restore Manual startup** requires the stopped service and all guarded metadata to still match the disabled state; it restores startup only and never starts the service. Deleted services are not recreated. A later explicit start may run the configured executable.

Service changes use the supported SCM API rather than direct registry edits. The configuration, status, dependents, access, security, and metadata are checked before and after. SCM provides no atomic compare-and-swap; do not run another service configuration tool concurrently. A detected conflict blocks or reports the operation and preserves the backup. See Microsoft’s [service configuration guidance](https://learn.microsoft.com/en-us/windows/win32/services/service-configuration-programs), [startup-only configuration API](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfigw), and [database-lock limitation](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-lockservicedatabase).

Quick Clean and selected Clean include only eligible services with existing configuration rights. All other machine-wide areas retain their earlier restrictions. New service backups retain unchanged support for all five earlier formats, verified using fixed legacy fixtures.

## Readable interface on 4K

The top toolbar’s **Interface size** selector scales text and controls together from **100% to 200%** using the native WebView zoom. Your choice is saved locally and survives app restarts. The first launch on a 4K display at near-100% Windows scaling uses **150%**; existing Windows DPI scaling is not automatically boosted again. A saved preference always takes precedence. Browser preview uses CSS zoom and has no registry access.

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

Rust tests cover backup failure, stale evidence, changed targets, metadata conflicts, expiry, invalid tokens, corrupted backups, and fixed `0.1.1`/`0.1.2`/`0.1.3`/`0.1.4`/`0.1.5`/`0.1.7` backup fixtures. Windows integration tests create uniquely named **non-startup** keys under `HKCU\\Software\\RustRegistryTests`, exercise transactions and backup/repair/restart/restore round trips, and remove their own test keys afterward. Uninstall tests cover both an originally absent flag and an originally zero flag, including exact raw metadata preservation. They never modify the user's real startup list.

The desktop suite also creates one uniquely named `RustRegistry-E2E-Uninstall-<uuid>` registration in the existing current-user Uninstall root. It verifies review/cancel, full-backup hide, hidden-state diagnostics, reload and restore through the packaged UI. A separate PowerShell reader checks all fixture values, types, and owner/group/DACL permissions before and after. The suite cleans only its own registration and matching backup; existing entries and user backups are not edited. No Windows Settings/Control Panel list UI assertion is made.

The desktop suite additionally creates a uniquely named `.rr<uuid>` extension with two owned Open with suggestions and an owned default metadata value. It tests review/cancel, one-suggestion repair, exclusion of the default-selected suggestion, UI reload, and exact restore. An independent registry reader checks the original value types, other suggestions, extension defaults, permissions, and absence of UserChoice throughout. Only its owned extension and matching backup are removed afterward. The suite never creates or changes a protected UserChoice selection and does not assert Explorer’s cached Open with menu presentation.

The desktop suite also creates an owned random CLSID in both current-user architecture views. It verifies the 32-bit entry stays unverified/read-only, 64-bit review/cancel, backup/disable, inventory after disabling, UI reload, and exact restore. An independent reader compares both views, registry value types, raw unexpanded paths, threading metadata, and owner/group/DACL permissions. Only the owned classes and matching backup are removed. Neither production COM activation nor DLL loading is tested. The cleaning suite separately reviews/cancels Quick Clean without applying real user changes, then cleans exactly two owned App Paths fixtures and restores each from its independent backup after a UI reload.

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

## Expanded scanning and COM recovery in 0.1.7

Coverage increases to **23 fixed locations** with two shared application-command scopes: `HKCU` and `HKLM\Software\Classes\Applications\name\shell\open\command`. The scanner checks only an unambiguously resolved local executable expression; shell argument placeholders such as `"%1"` and `%*` are not treated as environment variables. Delegated execution, DDE, DropTarget, unknown command metadata, nested commands, registry links, and unreadable activation settings remain unverified without probing the default command. The initial 0.1.7 application command scope was read-only. Version 0.1.8 adds the guarded suggestion quarantine described below; all other application commands remain read-only. This does not test application behavior, all shell verbs, or default handlers. See [Microsoft's application registration documentation](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration).

Quick Clean and selected Clean now also accept simple **current-user 64-bit InprocHandler32 and LocalServer32 mappings** with confirmed missing explicit local DLL/executable targets. As with InprocServer32, the class must have exactly one server child, no nested children, an optional REG_SZ default class description, and no machine counterpart in the same view. Handler and local-server keys must have no named values. ServerExecutable overrides, ThreadingModel on these new forms, AppID, services, managed/alternate activation, unknown metadata, and 32-bit/machine changes remain excluded. LocalServer32 commands must contain a literal absolute local `.exe` path with unambiguous quoting; environment-dependent commands and indirect system launchers remain read-only. Arguments are saved exactly and never executed. See Microsoft's [InprocHandler32](https://learn.microsoft.com/en-us/windows/win32/com/inprochandler32) and [LocalServer32](https://learn.microsoft.com/en-us/windows/win32/com/localserver32) documentation.

Each confirmed repair flushes and verifies a separate backup before conditionally removing **only the default value** in a Windows registry transaction. Keys, permissions, class metadata, other registrations, and files stay in place. Restore requires the original keys, unchanged supported metadata/structure, no machine counterpart, and an absent default value. A changed command, new executable before repair, new activation key, corrupted backup, or occupied restore location blocks the action. No COM activation, executable launch, DLL loading, or file replacement takes place.

To run only the new application-command and COM handler/local-server UI checks against the built executable, use `npm run test:desktop -- --expanded-only`. This mode does not create service fixtures.

To run only the application suggestion repair UI checks, use `npm run test:desktop -- --application-only`.

The new mapping backups use schema 7 with a checksum-covered server-kind selector. Existing schemas 1–6 keep their original representation and remain restorable without migration; legacy InprocServer32 backups still use schema 5. The desktop suite independently compares both architecture views and permissions, checks Quick Clean inclusion and cancellation, applies only selected owned mappings, reloads the UI, restores exact originals, and removes only its fixtures and matching backups. Owned application-command controls verify missing/found/delegated/already-hidden diagnostics and exact registry values/permissions before and after recovery.

## Application suggestion repair in 0.1.8

For a simple **HKCU\Software\Classes\Applications\name.exe\shell\open\command** registration with a confirmed missing literal local executable, **Review repair → Back up & hide suggestion** saves the exact original command type/bytes and supported values at all four application/shell/open/command keys. It then conditionally adds only an empty REG_SZ **NoOpenWith** value on the existing application key in a Windows registry transaction. The command itself stays intact, including shell placeholders such as `"%1"` and `%*`. Quick Clean and selected Clean include the same supported candidates and create an independent verified backup per change. No command is executed, no executable is replaced, and default application selections and protected UserChoice values are not changed.

This is a quarantine of an optional application suggestion. NoOpenWith is Windows' documented application visibility/tracking flag: explicit OpenWithList/OpenWithProgIDs registrations may still display the application, and recent-file Jump List tracking for unregistered file types is also limited. Windows Shell caching and the appearance of Explorer menus are not tested or promised. It does not repair missing application files or disable the preserved open command. See Microsoft's [application registration](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration) and [NoOpenWith behavior](<https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh127438(v=vs.85)>) documentation.

Eligibility requires a single ASCII executable registration name, no same-named HKLM application, exactly the `shell → open → command` key chain, no child below command, and only its default command value. Application-root metadata may contain only an optional REG_SZ default description and FriendlyAppName; shell and open keys must have no values. Any existing NoOpenWith flag, machine counterpart, SupportedTypes/other children, alternate verb, delegated execution, DDE, unknown/protected metadata, registry link, unreadable state, ambiguous quoting, network/device/reparse target, environment-dependent executable expression, indirect system launcher, or unsupported value is excluded. Command arguments are never expanded or run. Supported snapshots are bounded to 64 values/32 KiB, and each complete backup must fit the existing 256 KiB limit.

**Backups & restore → Review restore → Restore suggestion visibility** removes only the added flag when the full current snapshot matches the backed-up hidden state and the original keys still exist. A changed command/flag/metadata, extra key, missing key, new machine counterpart, or corrupted backup blocks recovery. Keys and permissions are never deleted or recreated. Already-hidden applications are marked in the inventory and excluded from further cleaning; restore can make an optional suggestion available again. Scans remain read-only and all repair checks use fresh registry/filesystem observations.

Schema 8 stores the full supported snapshot and original absence of NoOpenWith under an integrity checksum. Formats 1–7 are not rewritten or migrated. Native Windows tests verify exact raw command bytes across backup/restart/restore, stale-target and metadata/flag conflicts, backup failure, scope tampering, and batch stop/individual recovery. Desktop verification creates four unique owned current-user applications (eligible missing, found, delegated, already hidden), cancels reviews without mutation, tests individual and selected repair plus Quick Clean inclusion, reloads and restores, independently compares command types/values and key permissions, and removes only its own registrations and matching backups.

## Upstream dependency notice

The cross-platform Tauri dependency lockfile includes Linux-only `glib` 0.18.5, which has upstream advisory [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html). It is absent from this application's Windows x64 dependency graph. Linux builds are not supported by this project; revisit the upstream dependency before adding Linux support. This notice does not represent a full security audit.

## Explicit owned-service test setup

Live SCM mutation tests require an administrator to create two uniquely named, never-started fixtures: one Manual service and an already-Disabled control. The setup delegates query/configure/delete rights only for those fixtures to the invoking user, plus read-only access to their registry metadata. It does not change any existing service or global SCM permissions. The main app and smoke suite do not launch administrator prompts.

After reviewing `scripts/service-fixture.ps1`, an explicitly approved Windows administrator can prepare the fixture from a normal Windows PowerShell session (this one setup action displays UAC):

```powershell
$fixtureToken = [Guid]::NewGuid().ToString('D')
powershell.exe -NoProfile -File scripts/service-fixture.ps1 -Action prepare -Token $fixtureToken
$env:RUSTREGISTRY_SERVICE_FIXTURE_TOKEN = $fixtureToken
npm run test:desktop
```

The service UI suite verifies control exclusion, review/cancel, SCM-backed disable, independent ServiceController/registry/security observations, restart/restore, Quick Clean inclusion, and selected cleaning. It deletes only the owned fixtures and their matching backups afterward. It never starts either fixture or writes an executable. Without an approved token, this live service mutation check is explicitly skipped; pure policy/recovery tests and existing native tests still run. If a test is interrupted before cleanup, use `powershell.exe -NoProfile -File scripts/service-fixture.ps1 -Action cleanup -Token <the-owned-token>`; identity/state checks guard cleanup.
