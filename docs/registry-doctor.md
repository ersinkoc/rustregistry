# Registry Doctor: scope and next milestones

RustRegistry should help users understand a finding, choose a supported action, and return to the original state. Increasing the number of scanned roots alone does not achieve that. This document records the research and decisions through 0.1.21; future milestones below are plans, not implemented features.

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

## Next concrete milestones

| Area                            | Next implementation work                                                                              | Evidence required before enabling repair                                                                               |
| ------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Further font/help coverage      | Research packaged fonts, collections, Unicode/expanded paths and loader-specific relative resolution  | Verified lookup/fallback semantics, unchanged system/runtime resources and exact recovery before enabling more repairs |
| Sound events                    | Inventory custom per-user sound mappings and distinguish empty/no-sound settings from missing media   | Default-scheme exclusions, exact metadata preservation, no playback, and tested user/system fallback behavior          |
| Installed-application leftovers | Correlate application paths, uninstall records, suggestions and cached labels into explainable groups | Multiple independent signals; absent files alone must not imply that settings, licenses or user data are disposable    |
| Review controls                 | Per-category selections, explicit exclusions and remembered user decisions                            | Excluded IDs cannot enter native batches; changes in scan evidence must invalidate old decisions                       |
| Recovery workflow               | Group successful batch backups into a visible operation journal                                       | Partial-failure reporting, per-item outcomes, exact conflict handling and independently tested restart recovery        |
| Diagnostics                     | Show why a finding is repairable, protected, inaccessible or uncertain                                | Reason codes map to visible explanations and exports; no fake severity or inflated issue counts                        |

Each new category must bring an understandable user action and a complete recovery test, not merely a larger scan total. Future machine-wide changes must use existing rights and their own documented guards. UserChoice, installer databases, drivers, security configuration, application licenses and arbitrary empty keys are not disposable merely because they look old.
