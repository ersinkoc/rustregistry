# Registry Doctor: scope and next milestones

RustRegistry should help users understand a finding, choose a supported action, and return to the original state. Increasing the number of scanned roots alone does not achieve that. This document records the research and decisions through 0.1.23; future milestones below are plans, not implemented features.

## Research and current behavior

[CCleaner's published registry rules](https://support.ccleaner.com/s/article/registry-cleaning-rules?change=true&language=es) distinguish missing libraries, COM/classes, extensions, application paths, uninstall remnants, fonts, help files, startup, MUI cache, sounds and services. Its list is a useful coverage inventory, not proof that every matching record can be removed safely. RustRegistry uses its own implementation and policy; no utility code or rule templates are copied.

[NirSoft's MUICacheView description](https://www.nirsoft.net/utils/muicache_view.html) identifies the current-user display cache and explains that Windows can recreate deleted entries when applications run. This supports treating MUI cleanup as cache maintenance, separate from application uninstall or structural registry repair. The two recognized per-executable fields and their exact raw-byte behavior are also checked against owned fixtures on the running Windows machine.

[Microsoft's WOW64 registry table](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys) distinguishes shared keys from redirected COM registrations. A logical check is not necessarily a separate physical root. The fixed Windows-managed user Classes alias is opened using the existing application-registration approach; subsequent cache components reject links.

History is different from a missing reference. A stored Run command or typed network path can be perfectly valid and still be something a user wants to clear. Version 0.1.20 therefore adds explicitly selected registry-history maintenance without classifying history as a fault or putting it into Quick Clean. The exact supported shapes are validated against isolated registry fixtures. Explorer can cache suggestions and other history databases can contribute to its interface; this version promises only the selected registry-store change.

## Delivered in 0.1.20

- A maintenance diagnosis on Overview, with routes to supported cleaning candidates, optional history and unverified evidence.
- Category and text filters for manual cleaning; category-scoped Quick Clean, with native exclusion of personal history.
- Real MUI cache inventory and reviewed cleanup of known display fields for confirmed missing local executables, individually or in selected batches.
- Optional RunMRU and TypedPaths snapshot clearing with exact backups, complete RunMRU ordering checks, preserved default metadata and strict new-data conflicts.
- Schema 20 records with flush/read-back/integrity verification before transactions and exact-value restart/restore. Formats 1–19 retain their original layouts and checksums.
- Native mutation tests on isolated owned roots, and a packaged MUI UI flow using independent raw readers. Live user history is scanned and review-cancelled, not cleared by the UI test.

The engine removes supported values or applies documented visibility/startup changes. It does not remove whole application trees based on a vendor name, delete application files, run stored commands or promise a speed increase from a registry count.

## Delivered in 0.1.21

Persisted font registration and HTML Help/WinHelp directory-mapping diagnostics add six logical sections. Supported missing current-user `.ttf`/`.otf` references and literal machine help mappings have separate individual review, selected/category-scoped cleaning, schema 21 verified backups and exact-value restart restoration. System fonts, matching machine font names, ambiguous/expanded paths, multi-file resources and unsupported metadata remain read-only. Package children, runtime font resources, help search/security settings and files are preserved.

Microsoft's [font installation model](https://learn.microsoft.com/en-us/windows/win32/gdi/font-installation-and-deletion) distinguishes persisted registration from the active system font table; [AddFontResourceEx](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-addfontresourceexa) documents collections and multi-file resources. The implementation checks file presence without invoking these APIs. Microsoft's [WinHelp rules](<https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/bb776786(v=vs.85)>) and a help producer's [HTML Help deployment instructions](https://www.innovasys.com/help/dx/deployment.html) explain filename-to-directory registration. Missing candidates do not prove the absence of every possible fallback or working viewer.

Native tests use isolated roots; the packaged UI flow uses only owned registration values, inert help files and independent raw/permission readers. The setup has explicit test elevation for machine controls; the production app still uses existing rights. Test-created global help roots are removed only while a transaction verifies that they remain empty. Existing registrations and data are preserved.

## Delivered in 0.1.22

Sound-event inventory adds two shared user/machine logical sections, bringing coverage to 66. Explicit empty assignments are separated from absent values and missing files. Supported missing current-user `.Current` wave assignments can be reviewed individually or in selected/category-scoped cleaning. A verified schema 22 backup precedes a conditional write of an explicit empty assignment; exact restart restoration requires the same current value, selected scheme, saved variants, metadata and missing-file evidence.

Microsoft's [theme format](https://learn.microsoft.com/en-us/windows/win32/controls/themesfileformat-overview) describes event sound files and empty entries. [PlaySound](<https://learn.microsoft.com/en-us/previous-versions/dd743680(v=vs.85)>) documents alias/search/default behavior. The implementation keeps the current value/key, preserves saved/default/No Sounds schemes and protects default fallback events and machine counterparts. This is a configuration change with explicit review; cached sounds and each application's fallback are not inferred. No audio is played, decoded or deleted, and no device, volume or notification policy changes.

Native tests use isolated roots for selected-scheme, saved metadata, machine-counterpart, current-value and real-file conflicts during apply/restore. The packaged fixture uses only a GUID-owned current-user sound application and inert controls, preserves the real selected scheme and unrelated applications, and checks original bytes and permissions independently. Owned registry-tree cleanup compares the snapshot inside a transaction before deletion.

## Delivered in 0.1.23

The Application leftovers workspace correlates an exact current-user installation directory across application search paths and one non-MSI uninstall owner. Missing installation/application/uninstaller targets are shown with their provenance and related supported actions. Names alone do not establish ownership, and missing targets do not prove every setting is disposable. One logical correlation section brings coverage to 67 while reusing existing roots.

Supported group actions retain their existing per-item backups. The new action removes only an unused literal App Paths Path value after a verified schema 23 backup, with missing-target, ownership, metadata and counterpart guards before apply/restore. New mappings, reinstall directories, changed anchors, expanded duplicate owners, missing keys and corrupt backups block changes. Existing executable mappings must be reviewed first; after another scan, a remaining search path can be reviewed separately. Restore that newer search-path backup before an older executable-mapping backup. Supported uninstall visibility changes remain independently reversible. No key, application setting, license, installer database or file is removed by the new action.

Microsoft's [application registration documentation](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration) distinguishes executable lookup, optional search paths and custom metadata. [Uninstall registration](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key) and [Windows Installer ARP behavior](https://learn.microsoft.com/en-us/windows/win32/msi/configuring-add-remove-programs-with-windows-installer) support retaining installer/product-code data and separating visibility from actual installation state. This release does not infer a vendor-wide deletion rule from these sources.

Native tests use isolated roots. The packaged flow uses only owned controls, independently compares original bytes/settings/license markers/permissions, tests real reinstall and ownership conflicts, restores mixed schema 23/3/20 groups and staged schema 2/3/23 actions, and removes only its own fixtures through conditional transactions.

## Next concrete milestones

| Area                          | Next implementation work                                                                             | Evidence required before enabling repair                                                                               |
| ----------------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Further font/help coverage    | Research packaged fonts, collections, Unicode/expanded paths and loader-specific relative resolution | Verified lookup/fallback semantics, unchanged system/runtime resources and exact recovery before enabling more repairs |
| Further sound coverage        | Research expanded/relative paths, aliases, saved scheme editing and application-specific fallback    | Verified resolution and consumer behavior, default protections and exact recovery before enabling further repairs      |
| Further application leftovers | Research additional owner identities, package/installer presence and supported leftover stores       | Strong ownership evidence, live reinstall conflicts and exact recovery; no vendor-wide deletion of settings/licenses   |
| Review controls               | Per-category selections, explicit exclusions and remembered user decisions                           | Excluded IDs cannot enter native batches; changes in scan evidence must invalidate old decisions                       |
| Recovery workflow             | Group successful batch backups into a visible operation journal                                      | Partial-failure reporting, per-item outcomes, exact conflict handling and independently tested restart recovery        |
| Diagnostics                   | Show why a finding is repairable, protected, inaccessible or uncertain                               | Reason codes map to visible explanations and exports; no fake severity or inflated issue counts                        |

Each new category must bring an understandable user action and a complete recovery test, not merely a larger scan total. Future machine-wide changes must use existing rights and their own documented guards. UserChoice, installer databases, drivers, security configuration, application licenses and arbitrary empty keys are not disposable merely because they look old.
