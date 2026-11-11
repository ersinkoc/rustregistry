# Security policy

Report a suspected vulnerability through [GitHub private vulnerability reporting](https://github.com/ersinkoc/rustregistry/security/advisories/new). Include the RustRegistry version, Windows version and architecture, the affected operation, and reproduction steps using a disposable registry fixture where possible.

Backup files, saved scans, operation journals, and exported reports can contain personal paths, commands, and original registry data. Share a minimal redacted reproduction.

Security fixes target the latest stable release. Ordinary bugs can be filed in [GitHub Issues](https://github.com/ersinkoc/rustregistry/issues).

## Dependency advisories

Release builds enable arithmetic overflow checks, including when generic code from the `grid` dependency is compiled into a caller. The checks reject the reported row-expansion overflow before it changes the backing storage. Dependabot still tracks the upstream version. [Grid advisory](https://github.com/advisories/GHSA-38c5-483c-4qqp)

The legacy WebView dependency graph also records a Linux-only `glib` advisory. [Registry reference](docs/registry-reference.md#upstream-dependency-notice)
