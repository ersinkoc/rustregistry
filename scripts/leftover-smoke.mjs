import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifyLeftoverRecovery(page, output, checked, summary) {
  const token = randomUUID();
  const shell = resolve(
    process.env.SystemRoot || 'C:\\Windows',
    'System32/WindowsPowerShell/v1.0/powershell.exe',
  );
  const fixture = async (action) => {
    const { stdout } = await run(
      shell,
      [
        '-NoProfile',
        '-NonInteractive',
        '-File',
        resolve(import.meta.dirname, 'leftover-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
      ],
      { windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  let original,
    storagePath,
    failure,
    attempted = false;
  const cleanupErrors = [];
  const info = (kind) => original.fixtures.find((f) => f.kind === kind);
  const id = (kind) => `HKCU|shared|${info(kind).applicationPath}|pAth`;
  const preserved = (
    state,
    removedPaths = [],
    hidden = [],
    cacheCleared = false,
    removedDefaults = [],
  ) => {
    expect(state.environmentPreserved).toBe(true);
    const expected = structuredClone(original.current);
    for (const node of expected.applications) {
      if (removedPaths.includes(node.kind))
        node.snapshot.values = node.snapshot.values.filter((v) => v.name.toLowerCase() !== 'path');
      if (removedDefaults.includes(node.kind))
        node.snapshot.values = node.snapshot.values.filter((v) => v.name !== '');
    }
    for (const kind of hidden) {
      const node = expected.uninstall.find((n) => n.name === info(kind).anchorKey);
      node.snapshot.values.push({ name: 'SystemComponent', type: 4, data: 'AQAAAA==' });
      node.snapshot.values.sort((a, b) =>
        a.name.toLowerCase().localeCompare(b.name.toLowerCase(), 'en'),
      );
    }
    if (cacheCleared) expected.cache = [];
    expect(state.current).toEqual(expected);
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const groups = async () => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Application leftovers', exact: true })
      .click();
    await page.getByRole('textbox', { name: 'Search application leftovers' }).fill(original.search);
  };
  const card = (kind) =>
    page
      .locator('.leftover-group')
      .filter({ has: page.getByRole('heading', { name: info(kind).displayName, exact: true }) });
  const backups = async () => {
    expect(storagePath).toMatch(/^[a-z]:\\/i);
    const out = [];
    for (const file of await readdir(storagePath).catch((e) => {
      if (e.code === 'ENOENT') return [];
      throw e;
    })) {
      if (!/^[a-f0-9-]{36}\.json$/.test(file)) continue;
      const path = resolve(storagePath, file);
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) continue;
      let record;
      try {
        record = JSON.parse(await readFile(path, 'utf8'));
      } catch {
        continue;
      }
      if (
        original.fixtures.some(
          (f) =>
            record.leftover?.executableName === f.executableName ||
            record.appPath?.executable === f.executableName ||
            record.uninstall?.keyName === f.anchorKey ||
            record.maintenance?.item === f.executable,
        )
      )
        out.push({ path, record });
    }
    return out;
  };
  const blocked = async (plan, match) => {
    const outcome = await page.evaluate(
      async ({ token, match }) => {
        try {
          await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
          return { blocked: false, error: null };
        } catch (e) {
          return { blocked: String(e).includes(match), error: String(e) };
        }
      },
      { token: plan.token, match },
    );
    summary.leftoverLastBlockedOutcome = outcome;
    expect(outcome.blocked).toBe(true);
  };
  const prepare = async () =>
    page.evaluate(
      (entryId) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId }),
      id('One'),
    );
  const restore = async (b) => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    const row = page
      .locator('.backup-item')
      .filter({ has: page.getByText(b.record.id, { exact: true }) });
    await row.getByRole('button', { name: 'Review restore', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('checkbox').check();
    await dialog.getByRole('button', { name: /^Restore / }).click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const applyGroup = async (kind, count) => {
    await groups();
    await card(kind)
      .getByRole('button', { name: `Review cleanup for ${info(kind).displayName}`, exact: true })
      .click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(
      count,
    );
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page
      .getByRole('button', {
        name: `Back up & clean ${count} entries`,
        exact: true,
      })
      .click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.leftoverFixtureToken = token;
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(
      page.getByRole('heading', { name: 'Backups & restore', exact: true }),
    ).toBeVisible();
    await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
    storagePath = await page.locator('.backup-location .mono').innerText();
    await scan();
    await groups();
    await expect(page.locator('.leftover-group')).toHaveCount(3);
    for (const kind of ['One', 'Two', 'Deferred']) {
      await expect(card(kind)).toContainText(info(kind).directory);
      await expect(card(kind)).toContainText(info(kind).executable);
      await expect(card(kind)).toContainText('uninstall.exe');
      await expect(card(kind)).toContainText(info(kind).anchorKey);
    }
    await expect(
      card('One').getByRole('button', {
        name: `Review cleanup for ${info('One').displayName}`,
        exact: true,
      }),
    ).toContainText('(3)');
    await expect(
      card('Deferred').getByRole('button', { name: 'Review search-path cleanup', exact: true }),
    ).toHaveCount(0);
    await page.screenshot({
      path: resolve(output, 'desktop-application-leftovers.png'),
      fullPage: true,
    });
    preserved(await fixture('inspect'));
    checked(
      'Application leftovers groups combine exact installation-directory, executable and uninstaller evidence; name-only, shared/expanded duplicate, MSI, present-directory and expanded-path controls are excluded while existing metadata and license markers remain exact',
    );
    await card('One')
      .getByRole('button', { name: `Review cleanup for ${info('One').displayName}`, exact: true })
      .click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(3);
    await expect(page.getByRole('dialog')).toContainText(
      'Remove correlated unused application search path',
    );
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    checked(
      'Group review identifies separate search-path, uninstall-visibility and exact-file cache actions; cancellation makes no registry or backup change',
    );
    for (const [kind, match] of [
      ['directory', 'not confirmed missing'],
      ['metadata', 'uninstall metadata changed'],
      ['duplicate', 'ambiguous'],
      ['default', 'metadata or executable mapping changed'],
    ]) {
      let active = false;
      try {
        const p = await prepare();
        await fixture(`conflict-${kind}-create`);
        active = true;
        await blocked(p, match);
        expect(await backups()).toHaveLength(0);
      } finally {
        if (active) await fixture(`conflict-${kind}-remove`);
      }
      preserved(await fixture('inspect'));
    }
    summary.leftoverApplyReinstallBlocked = true;
    summary.leftoverApplyOwnershipBlocked = true;
    summary.leftoverApplyMetadataBlocked = true;
    summary.leftoverApplyMappingBlocked = true;
    checked(
      'A real reinstall directory, changed uninstall metadata, expanded duplicate owner and newly introduced executable mapping each block post-review leftover cleanup before backup or mutation',
    );
    await groups();
    await card('One')
      .getByRole('button', { name: 'Review search-path cleanup', exact: true })
      .click();
    await expect(
      page.getByRole('heading', { name: 'Remove unused application search path?', exact: true }),
    ).toBeVisible();
    const apply = page.getByRole('button', { name: 'Back up & remove search path', exact: true });
    await expect(apply).toBeDisabled();
    await expect(page.getByRole('dialog')).toContainText(info('One').directory);
    await expect(page.getByRole('dialog')).toContainText(info('One').anchorKey);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await expect(apply).toBeEnabled();
    await page.screenshot({
      path: resolve(output, 'desktop-leftover-cleanup-review.png'),
      fullPage: true,
    });
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    await card('One')
      .getByRole('button', { name: 'Review search-path cleanup', exact: true })
      .click();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & remove search path', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    preserved(await fixture('inspect'), ['One']);
    const one = (await backups())[0];
    expect((await backups()).length).toBe(1);
    expect(one.record.schemaVersion).toBe(23);
    expect(one.record.valueName).toBe('pAth');
    expect(one.record.leftover.directory).toBe(info('One').directory);
    const raw = original.current.applications
      .find((n) => n.kind === 'One')
      .snapshot.values.find((v) => v.name === 'pAth');
    expect(Buffer.from(one.record.original.bytes).toString('base64')).toBe(raw.data);
    checked(
      'Individual leftover review requires explicit consent, cancels without mutation and removes only the unused Path value after a disjoint schema-23 backup, preserving original spelling/bytes, settings, licenses, keys and permissions',
    );
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    const bytes = await readFile(one.path);
    for (const [kind, match] of [
      ['directory', 'not confirmed missing'],
      ['metadata', 'uninstall metadata changed'],
      ['duplicate', 'ambiguous'],
      ['default', 'metadata or executable mapping changed'],
    ]) {
      let active = false;
      try {
        const p = await page.evaluate(
          (backupId) => window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId }),
          one.record.id,
        );
        await fixture(`conflict-${kind}-create`);
        active = true;
        await blocked(p, match);
        expect(await readFile(one.path)).toEqual(bytes);
      } finally {
        if (active) await fixture(`conflict-${kind}-remove`);
      }
      preserved(await fixture('inspect'), ['One']);
    }
    summary.leftoverRestoreReinstallBlocked = true;
    summary.leftoverRestoreOwnershipBlocked = true;
    summary.leftoverRestoreMetadataBlocked = true;
    summary.leftoverRestoreMappingBlocked = true;
    checked(
      'Restart-safe leftover restoration blocks real reinstall, changed anchor, duplicate ownership and new default-mapping conflicts while preserving the absent search path and exact backup bytes',
    );
    await restore(one);
    preserved(await fixture('inspect'));
    checked(
      'UI restoration returns the exact original search-path name, type and UTF-16 bytes after reload without recreating keys or changing license/settings metadata',
    );
    const before = new Set((await backups()).map((b) => b.record.id));
    await applyGroup('One', 3);
    preserved(await fixture('inspect'), ['One'], ['One'], true);
    const mixed = (await backups()).filter((b) => !before.has(b.record.id));
    expect(mixed.map((b) => b.record.schemaVersion).sort((a, b) => a - b)).toEqual([3, 20, 23]);
    checked(
      'Reviewed group cleanup applies three distinct supported actions with independent verified schema-23/3/20 backups; only the search path, uninstall visibility and exact-file display cache change',
    );
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    for (const schema of [3, 20, 23])
      await restore(mixed.find((b) => b.record.schemaVersion === schema));
    preserved(await fixture('inspect'));
    checked(
      'Mixed group backups survive restart and restore independently, including legacy uninstall/cache records before the new search path, with all original registry bytes and permissions preserved',
    );
    const beforeDeferred = new Set((await backups()).map((b) => b.record.id));
    await applyGroup('Deferred', 2);
    preserved(await fixture('inspect'), [], ['Deferred'], false, ['Deferred']);
    const deferredOld = (await backups()).filter((b) => !beforeDeferred.has(b.record.id));
    expect(deferredOld.map((b) => b.record.schemaVersion).sort()).toEqual([2, 3]);
    await groups();
    await expect(
      card('Deferred').getByRole('button', { name: 'Review search-path cleanup', exact: true }),
    ).toBeEnabled();
    checked(
      'An existing executable mapping keeps direct search-path cleanup protected; after reviewed legacy mapping/visibility cleanup and a fresh scan, the remaining correlated search path becomes eligible',
    );
    const beforePath = new Set((await backups()).map((b) => b.record.id));
    await applyGroup('Deferred', 1);
    preserved(await fixture('inspect'), ['Deferred'], ['Deferred'], false, ['Deferred']);
    const deferredPath = (await backups()).filter((b) => !beforePath.has(b.record.id));
    expect(deferredPath).toHaveLength(1);
    expect(deferredPath[0].record.schemaVersion).toBe(23);
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await restore(deferredPath[0]);
    await restore(deferredOld.find((b) => b.record.schemaVersion === 2));
    await restore(deferredOld.find((b) => b.record.schemaVersion === 3));
    preserved(await fixture('inspect'));
    checked(
      'The staged remaining-path cleanup has its own restart-safe backup; restoring it before the older executable-mapping backup returns the complete original application group exactly',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (attempted)
      try {
        const after = await fixture('cleanup');
        expect(after.environmentPreserved).toBe(true);
        expect(
          [...after.current.applications, ...after.current.uninstall].every(
            (n) => n.snapshot === null,
          ),
        ).toBe(true);
        expect(after.current.cache).toHaveLength(0);
      } catch (e) {
        cleanupErrors.push(String(e));
      }
    if (storagePath && original)
      try {
        for (const b of await backups()) await unlink(b.path);
      } catch (e) {
        cleanupErrors.push(String(e));
      }
    summary.leftoverFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned leftover cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned application/uninstall controls, inert files, cache values and matching test backups are conditionally cleaned while pre-existing registrations, settings, licenses and unrelated cache remain preserved',
  );
}
