# Changelog

Each published version has a matching Git tag and GitHub release. During `0.x`, development proceeds in small patch releases (`0.1.0`, `0.1.1`, `0.1.2`). Minor versions are reserved for larger planned milestones; major versions are reserved for an explicitly planned stable release.

## 0.1.13 — 2026-11-07

- Expand coverage from 29 to 33 logical scan sections with COM Interface-to-TypeLib references under both hives and both architecture views. Check library GUID key existence in shared user and machine TypeLib roots without loading libraries, activating COM, or probing files. Any existing library prevents repair; this deliberately does not diagnose version-specific library failures.
- Add backed-up, reversible removal of simple orphaned current-user 64-bit interface TypeLib defaults to individual repair, Quick Clean, and selected Clean. Require exact live evidence, no machine interface counterpart in either view, a library absent from both hives, and existing write access before review.
- Preserve description, optional Version and flat ProxyStubClsid32 metadata, the entire 32-bit interface view, keys, permissions, files, and other registrations. Machine changes, complex/nested metadata, unknown children, links, malformed GUIDs, and uncertain evidence remain outside repair scope.
- Flush and verify an individual checksum-protected schema 13 backup before each conditional registry transaction. Restore exact original REG_SZ/REG_EXPAND_SZ bytes only while the value remains absent and every orphan, metadata, structure, and counterpart guard still matches. Keep formats 1–12 unchanged with a fixed v0.1.12 ProgID restoration fixture.
- Add policy, read-only inventory, write-access, conflict, batch-stop, exact-byte restart/restore, and tampered-backup tests. Add packaged UI verification of native/32-bit controls, shared user and read-only machine libraries, new-library conflicts after review, review/cancel, single and selected repair, reload/restore, raw metadata/permission preservation, and owned-fixture cleanup.

## 0.1.12 — 2026-11-07

- Expand coverage from 27 to 29 logical scan sections with shared HKCU/HKLM COM ProgID-to-CLSID reference inventory. These checks share Classes roots with file-association inventory but inspect different children and use distinct scope IDs. Resolve class-key existence through both hives and both architecture views without COM activation, resolution APIs, or filesystem probes.
- Add backed-up, reversible disabling of simple orphaned current-user ProgID CLSID defaults, including Quick Clean and selected Clean. Require a literal CLSID absent from every checked view, no same-named machine ProgID, unchanged bounded description metadata, and existing write access.
- Preserve all keys, descriptions, class registrations, default selections, UserChoice, file-association metadata, permissions, and files. Machine changes, existing targets in any view, CurVer/shell/complex registrations, links, malformed GUIDs, and unsupported ProgID names/types remain excluded.
- Flush and verify a separate schema 12 backup before each conditional registry transaction. Restore exact original REG_SZ/REG_EXPAND_SZ bytes only while the value is absent and all orphan/metadata/fallback guards still hold. Keep formats 1–11 unchanged, including a fixed v0.1.11 type library backup restoration test.
- Add policy, read-only inventory, unique-scope-ID regression, write-access, conflict, batch-stop, exact-byte restart/restore, and corruption tests. Add packaged UI controls for real 32-bit-only, 64-bit-only, and machine-only class targets, a newly appearing 32-bit class after review, Quick Clean review/cancel, individual and two-entry selected repair, independent raw/permission comparisons, and owned-fixture cleanup.

## 0.1.11 — 2026-11-07

- Expand read-only coverage from 25 to 27 locations with shared HKCU/HKLM TypeLib inventory. Read explicit win32/win64 platform mappings, versions, and locales without loading or registering libraries. Keep win32 file targets unverified in the 64-bit process and bound both mapping counts and hierarchy traversal.
- Add backed-up, reversible repair of missing literal local .dll/.tlb/.olb win64 defaults for simple one-version, neutral-locale current-user type libraries. Include guarded mappings in individual repair, Quick Clean, and selected Clean; require existing write access and no machine counterpart for the library ID.
- Preserve all supported library/version/locale/help/flags metadata, win32 mappings, keys, permissions, other libraries, and all files. Exclude Windows paths, ambiguous/environment/resource-index paths, multiple versions/locales, unknown/nested metadata, links, machine changes, and uncertain evidence.
- Save and verify a separate checksum-protected schema 11 backup before a conditional registry transaction removes only the reviewed default mapping. Restore exact original type/bytes only while the value remains absent, the file remains missing, and all metadata/fallback guards match. Never load, register, unregister, replace, or delete a library file.
- Preserve backup formats 1–10 without migration, including a fixed v0.1.10 registration backup restoration test. Add policy, read-only platform inventory, write-access, conflict, batch-stop, restart/restore, and corruption tests plus packaged UI recovery checks with independently read raw metadata and permissions in both architecture views.

## 0.1.10 — 2026-11-07

- Expand read-only coverage from 23 to 25 registry locations with shared HKCU/HKLM RegisteredApplications inventory. Check literal supported Capabilities registry references without probing files or running application commands; distinguish existing, missing, and unverified targets.
- Add separately reviewed, backed-up removal of orphaned current-user RegisteredApplications values, including Quick Clean and selected Clean. Require a missing user target, no same-named machine registration, no matching machine target in either view, exact live value evidence, and existing write access.
- Preserve default application selections, UserChoice, ProgIDs, Capabilities keys, existing child trees including PackagedApps, unrelated registrations, raw control values, permissions, and all files. Machine registrations, protected namespaces, links, environment expressions, unsupported types, and uncertain evidence remain read-only.
- Flush and verify a separate schema 10 backup before conditionally removing one named value in a Windows registry transaction. Restore its exact REG_SZ bytes only if still absent and all orphan/counterpart guards continue to hold. New targets or registrations, missing roots, or corrupted/mismatched backups block changes.
- Permit multiple independent registration values in one batch with individual backups, stop on the first conflict, and keep earlier completed changes independently restorable. Preserve formats 1–9 without migration, with a fixed legacy 0.1.9 backup restoration test.
- Add native policy, inventory, write-access, transactional conflict, batch, restart/restore, and compatibility tests plus owned-fixture packaged UI checks for Quick Clean review, single and two-entry selected repair, exact reload/restore, control data, root permissions, and cleanup.

## 0.1.9 — 2026-11-07

- Add backed-up, reversible removal of confirmed missing literal local DLL references with exact DWORD zero counts in HKLM's 64-bit SharedDLLs key. Include eligible references in individual repair, Quick Clean, and selected Clean.
- Preserve positive/malformed counters, 32-bit references, Windows-directory paths, aliases, environment-dependent or ambiguous paths, network/reparse targets, keys, permissions, and all files. Never decrement counters or load, unregister, replace, or delete DLLs.
- Require existing key write access at review, before any backup or mutation. Scanning still opens registry handles only for reading; the production app and normal smoke command never request elevation or alter permissions automatically.
- Use conditional Windows registry transactions to remove one expected zero value or restore its exact DWORD type/bytes only while its name remains absent and the DLL is still missing. Block new counters, reappearing files, changed structure, and corrupted or mismatched backups.
- Save checksum-protected schema 9 backups without rewriting formats 1–8. Add a fixed legacy 0.1.8 application backup fixture and restore test. Allow independent zero-count references from one shared key in a cleaning batch.
- Add native policy/access/conflict/batch/restart/restore tests, a read-only raw-registry fixture ABI check, and explicit same-account elevated desktop test tooling. Verify only owned 32/64-bit controls, inert files, positive counts, unrelated raw values, and key permissions; remove only owned fixtures and matching test backups.

## 0.1.8 — 2026-11-07

- Add backed-up, reversible application suggestion quarantine for simple current-user application open commands with confirmed missing literal local executables. Include eligible entries in individual repair, Quick Clean, and selected Clean; already-hidden registrations remain inventoried without another repair.
- Add only an empty REG_SZ NoOpenWith flag after flushing and verifying a complete supported value snapshot. Preserve the exact command type/bytes, shell arguments, keys, permissions, files, and default application selections. Never run commands or guess replacement executables.
- Block machine counterparts, delegated/DDE/alternative activation, extra verbs or nested keys, unknown/protected metadata, environment-dependent executable paths, indirect launchers, and uncertain targets.
- Restore only the original absent visibility flag when every guarded value and existing key still matches the backup. Save the new scope in integrity-protected schema 8 while retaining unchanged formats 1–7, including a fixed legacy 0.1.7 handler backup fixture.
- Explain NoOpenWith behavior in review screens: explicit Open with registrations may still display the application, and recent-file Jump List tracking for unregistered file types is also limited. This quarantines an optional suggestion; it does not fix missing files or disable the preserved command.
- Add Windows transaction/backup/restart/conflict/batch tests and packaged UI verification of individual repair, Quick Clean review, selected cleaning, reload/restore, exclusion controls, permissions, and owned-fixture cleanup.

## 0.1.7 — 2026-11-07

- Expand scanning from 21 to 23 fixed locations with shared HKCU/HKLM application open-command inventory. Preserve shell argument placeholders, diagnose only explicit local executable expressions, and keep these application commands read-only.
- Include guarded current-user 64-bit InprocHandler32 DLL and LocalServer32 executable mappings in individual repair, Quick Clean, and selected Clean. Keep machine counterparts, alternate activation, ServerExecutable overrides, unknown/nested metadata, indirect launchers, environment-dependent local servers, and 32-bit changes excluded.
- Back up and verify exact original values and supported metadata before removing only the broken default mapping in a conditional Windows transaction. Preserve keys and permissions; never activate COM, load DLLs, run commands, or change files.
- Restore the exact original type and bytes only when existing keys, metadata, and fallback guards still match. Use scope-checked schema 7 backups for the new mappings while retaining unchanged schemas 1–6.
- Add native Windows tests for both new repair types, Quick Clean/restart/restore, stale targets, override/metadata conflicts, backup failures, scope tampering, and read-only application command inventory. Extend packaged desktop verification with both COM views, independent permission checks, Quick Clean review, selected repair, and exact restore.

## 0.1.6 — 2026-11-07

- Avoid repeated filesystem queries for duplicate found targets within a read-only scan. Missing/uncertain targets and all repair checks remain uncached.

- Add backed-up service startup repair through Windows Service Control Manager for verified stopped, independent, Manual, own-process LocalService registrations with missing literal local executables outside Windows.
- Change only Manual startup to Disabled and restore only the original Manual type. Never start, stop, delete, recreate, elevate, or change a service's executable, account, permissions, or files automatically.
- Include eligible, configuration-authorized services in Quick Clean and selected Clean; drivers, Windows/shared/protected/privileged services, dependencies, triggers, recovery, unknown metadata, environment-dependent paths, and uncertain targets remain excluded.
- Save full guarded registry/security metadata and SCM configuration before the supported startup-only API update. Recheck before and after, block changed evidence, and retain all five earlier backup formats without rewriting them. SCM changes are not registry transactions or an atomic compare-and-swap.
- Add persistent 100–200% interface sizing and a 150% default on 4K displays at 100% Windows scaling, without adding another automatic boost over Windows DPI scaling.
- Add service eligibility, backup/restart/restore, access/status/conflict tests, a fixed v0.1.5 COM backup fixture, and owned-service UI verification tooling with explicit administrator setup.

## 0.1.5 — 2026-11-07

- Add Quick Clean and selected Clean with a full review, up to 100 protected candidates, separate verified backups, and individual restore. Stop at the first failed change and report completed, failed, skipped, and unattempted entries.
- Add read-only service/driver ImagePath inventory and shared DLL usage references. Increase the reported per-scope inventory cap to 10,000; machine/service/reference-count changes stay excluded from cleaning.

- Add read-only InprocServer32, InprocHandler32, and LocalServer32 COM inventory in separate HKCU/HKLM 32-bit and 64-bit views, bringing coverage to 21 scopes. Keep 32-bit DLL targets unverified without probing them in the wrong filesystem context.
- Add backed-up, reversible disabling of confirmed missing explicit local DLL paths in simple current-user 64-bit COM classes.
- Remove only the default DLL path after a verified backup; preserve the CLSID and server keys, threading metadata, permissions, and application files. No COM object is activated and no DLL is loaded or registered.
- Exclude machine counterparts, alternate activation, services/AppID, managed-server or unknown metadata, nested keys, and uncertain targets. Recheck class structure and all supported metadata inside conditional Windows transactions.
- Restore the exact original path type and bytes only when the live keys and guarded metadata still match and no replacement value exists. Preserve all four earlier backup formats without migration.
- Add English COM review/restore screens, native Windows conflict/restart tests, and a packaged UI round trip that independently verifies both architecture views and permissions.

## 0.1.4 — 2026-11-07

- Add read-only Open with suggestion inventory under shared current-user and machine Classes roots, bringing coverage to 14 scopes.
- Add backed-up, reversible removal of a current-user suggestion only when its referenced file-type registration is absent from both user and machine roots.
- Preserve extension defaults, protected UserChoice selections, other suggestions, keys, permissions, and application files. Default-selected or machine-duplicated suggestions remain read-only.
- Recheck guarded metadata and registrations before conditional Windows transactions; block stale scans, new registrations, changed selections, conflicts, and missing keys.
- Restore the exact original empty REG_NONE/REG_SZ type and bytes from persistent integrity-checked backups. Preserve all earlier backup formats, including a fixed v0.1.3 fixture.
- Add English association review/restore screens, native Windows conflict and restart tests, and a packaged desktop round trip with an independently inspected owned fixture.

## 0.1.3 — 2026-11-07

- Add backed-up, reversible visibility repair for verified orphaned current-user uninstall entries.
- Require both a missing installation folder and missing explicit local uninstall executables; existing/uncertain uninstallers, MSI, system components, protected entries, updates, grouped entries, and nested keys remain read-only.
- Back up every original value and byte type before setting only `SystemComponent=1`. Keep the key, permissions, application files, and all other metadata intact. No uninstall command is executed.
- Restore the exact original absent/zero visibility flag only when the full live record matches its backed-up hidden state.
- Preserve `0.1.1` startup and `0.1.2` App Paths backup compatibility, verified using fixed legacy-format fixtures.
- Add English full-backup confirmation and restore screens, hidden-entry diagnostics, native Windows transaction tests, and an owned-fixture desktop round trip.

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
