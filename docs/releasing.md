# Release runbook

## Prepare the version

Update the workspace version, both lockfiles, the npm package, the Tauri configuration and the changelog. Run `npm ci` and `npm run check` on Windows. Commit the release and confirm Windows CI passes for that commit on `main`.

From that exact commit, create an annotated tag and push it. For example, for 0.3.0:

```powershell
node scripts/check-version.mjs v0.3.0
git tag -a v0.3.0 -m "RustRegistry 0.3.0"
git push origin refs/tags/v0.3.0
```

## Verify and publish

The tag run of [Windows CI](../.github/workflows/windows.yml) checks the workspace and produces an attested ZIP and checksum file. Wait for both jobs to pass. Use the run for the release tag and confirm that its commit matches the annotated tag.

```powershell
gh run download <tag-run-id> -n rustregistry-windows-x64 -D target/release-download
gh attestation verify target/release-download/RustRegistry-0.3.0-windows-x64.zip -R ersinkoc/rustregistry --source-ref refs/tags/v0.3.0
./scripts/verify-windows-release.ps1 -Version 0.3.0 -Archive target/release-download/RustRegistry-0.3.0-windows-x64.zip -Checksums target/release-download/SHA256SUMS.txt -Launch
```

Use PowerShell 7 for the package scripts. The startup check launches the extracted executable in the background on Windows, verifies that its window responds, and closes that process. The checksum file covers the ZIP and the executable inside it.

Create the release as a draft with both files and release notes. Use `gh release create --verify-tag` so GitHub uses the existing tag. Download the attached files and repeat package verification before publishing the draft as latest. Include a link to the successful tag run in the release notes.

## Recover a failed run

For a transient runner, network, or tool download failure, use `gh run rerun <run-id> --failed` and reverify the replacement artifact. For a source or workflow defect, fix it on `main` and use a new version and tag. Preserve published tags and release assets.

For a local packaging check, build with `cargo build --locked --release -p registry-desktop --target x86_64-pc-windows-msvc`, then run `./scripts/package-windows.ps1 -CargoAbout <path-to-cargo-about>` in a fresh output directory. GitHub Releases use the artifact from the tag workflow.
