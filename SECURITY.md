# Security policy

Report a suspected vulnerability through [GitHub private vulnerability reporting](https://github.com/ersinkoc/rustregistry/security/advisories/new). Include the RustRegistry version, Windows version and architecture, the affected operation, and reproduction steps using a disposable registry fixture where possible.

Backup files, saved scans, operation journals, and exported reports can contain personal paths, commands, and original registry data. Share a minimal redacted reproduction.

Security fixes target the latest stable release. Ordinary bugs can be filed in [GitHub Issues](https://github.com/ersinkoc/rustregistry/issues).

## Dependency advisories

The Windows dependency path for `grid 0.18.0` is `GPUI 0.2.2 → Taffy 0.9.0 → grid`. The advisory concerns `Grid::expand_rows`. Taffy's occupancy matrix creates and replaces its storage with `Grid::new` and `Grid::from_vec`, and its source has zero calls to the affected method. This alert is triaged as `not_used` for the current Windows app. [Grid advisory](https://github.com/advisories/GHSA-38c5-483c-4qqp), [pinned Taffy source](https://github.com/DioxusLabs/taffy/blob/v0.9.0/src/compute/grid/types/cell_occupancy.rs)

Release builds also enable arithmetic overflow checks, including when generic dependency code is compiled into a caller. The release-profile reproduction rejects the reported row-expansion overflow before it changes the backing storage.

The `glib 0.18.5` advisory belongs to the legacy WebView's Linux dependency graph. The complete native and legacy Windows x64 dependency graphs contain zero `glib` packages. This alert is also triaged as `not_used` for the supported Windows target. [GLib advisory](https://github.com/advisories/GHSA-wrw7-89jp-8q8g), [registry reference](docs/registry-reference.md#upstream-dependency-notice)

Reassess these decisions when changing GPUI, Taffy, the supported platforms, or the registry UI's dependency graph.
