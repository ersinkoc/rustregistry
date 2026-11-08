import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, win32 } from 'node:path';
const run = promisify(execFile);

export async function verifyMaintenanceRecovery(page, output, checked, summary) {
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
        resolve(import.meta.dirname, 'maintenance-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
      ],
      { windowsHide: true, timeout: 60000, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  let original,
    storagePath,
    failure,
    attempted = false;
  const cleanupErrors = [];
  const info = (kind) => original.fixtures.find((f) => f.kind === kind);
  const names = (kind) => info(kind).suffixes.map((s) => info(kind).item + s);
  const preserved = (current, removedKinds = []) => {
    for (const before of original.views) {
      const after = current.views.find((v) => v.view === before.view);
      expect(after.acl).toBe(before.acl);
      expect(after.children).toEqual(before.children);
      const values = new Map(after.values.map((v) => [v.name.toLowerCase(), v]));
      const removed = new Set(removedKinds.flatMap(names).map((n) => n.toLowerCase()));
      for (const v of before.values) {
        if (removed.has(v.name.toLowerCase())) expect(values.has(v.name.toLowerCase())).toBe(false);
        else expect(values.get(v.name.toLowerCase())).toEqual(v);
      }
      const prior = new Set(before.values.map((v) => v.name.toLowerCase()));
      const added = after.values.filter((v) => !prior.has(v.name.toLowerCase())).length;
      summary.concurrentCacheAdditionsObserved = Math.max(
        summary.concurrentCacheAdditionsObserved || 0,
        added,
      );
    }
  };
  const results = async () => {
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('mui_cache');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(original.search);
  };
  const backups = async () => {
    expect(storagePath).toMatch(/^[a-z]:\\/i);
    const found = [];
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
        record.schemaVersion === 20 &&
        record.maintenance?.kind === 'mui_cache' &&
        ['One', 'Two'].some((k) => info(k).item === record.maintenance.item)
      )
        found.push({ path, record });
    }
    return found;
  };
  const restore = async (id) => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    const card = page.locator('.backup-item').filter({ has: page.getByText(id, { exact: true }) });
    await card.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Restore application cache?', exact: true }),
    ).toBeVisible();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore cache values', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    await page.getByRole('link', { name: 'RustRegistry overview', exact: true }).click();
    await expect(page.getByRole('region', { name: 'Maintenance diagnosis' })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Maintenance diagnosis' })).toContainText(
      'not counted as registry errors',
    );
    const historyBefore = await fixture('history-inspect');
    await page.getByRole('button', { name: 'Inspect optional history', exact: true }).click();
    await expect(page.getByRole('combobox', { name: 'Filter by category' })).toHaveValue(
      'usage_history',
    );
    let reviewed = false;
    for (const button of await page.locator('.entry-button').all()) {
      await button.click();
      const action = page.getByRole('button', { name: 'Review history cleanup', exact: true });
      if (await action.count()) {
        await action.click();
        await expect(
          page.getByRole('heading', { name: 'Clear optional registry history?', exact: true }),
        ).toBeVisible();
        await expect(page.getByRole('dialog')).toContainText('backup retains this history');
        const apply = page.getByRole('button', { name: 'Back up & clear history', exact: true });
        await expect(apply).toBeDisabled();
        await page.getByRole('dialog').getByRole('checkbox').check();
        await expect(apply).toBeEnabled();
        await page.screenshot({
          path: resolve(output, 'desktop-history-review.png'),
          fullPage: true,
        });
        await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
        reviewed = true;
        break;
      }
      await page.keyboard.press('Escape');
    }
    expect(await fixture('history-inspect')).toEqual(historyBefore);
    summary.historyReviewOnly = reviewed;
    summary.historyRegistryPreserved = true;
    if (!reviewed)
      summary.skipped.push(
        'No supported nonempty live RunMRU/TypedPaths snapshot exists; live history review was unavailable. Native isolated single/selected clear, restart, exact restore and conflict tests cover both stores.',
      );
    checked(
      reviewed
        ? 'Maintenance diagnosis and explicit personal-history review/cancel preserve exact live registry snapshots without applying cleanup'
        : 'Maintenance diagnosis separates optional history from registry errors; empty/unsupported live histories stay read-only and their exact snapshots are preserved',
    );

    attempted = true;
    original = await fixture('create');
    summary.maintenanceFixtureToken = token;
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
    storagePath = await page.locator('.backup-location .mono').innerText();
    summary.maintenanceBackupStorageVerified = true;
    await scan();
    await results();
    for (const [kind, status] of [
      ['One', 'Review'],
      ['Two', 'Review'],
      ['Existing', 'Found'],
      ['Windows', 'Review'],
      ['Complex', 'Unverified'],
      ['Malformed', 'Unverified'],
      ['Network', 'Unverified'],
      ['Relative', 'Unverified'],
    ]) {
      const button = page.getByRole('button', {
        name: `${win32.basename(info(kind).item)} details`,
        exact: true,
      });
      await expect(
        page.locator('tbody tr').filter({ has: button }).locator('.status-badge'),
      ).toHaveText(status);
      await button.click();
      const action = page.getByRole('button', { name: 'Review cache cleanup', exact: true });
      if (['One', 'Two'].includes(kind)) await expect(action).toBeEnabled();
      else await expect(action).toHaveCount(0);
      await page.keyboard.press('Escape');
    }
    checked(
      'MUI inventory groups paired display fields and distinguishes missing/found files, protected Windows paths, future metadata, wrong types, network and relative controls without executing a file',
    );

    const entryId = `HKCU|shared|Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache|${info('One').item}`;
    const plan = await page.evaluate(
      (id) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId: id }),
      entryId,
    );
    try {
      await fixture('conflict-create');
      const blocked = await page.evaluate(async (token) => {
        try {
          await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
          return false;
        } catch (e) {
          return String(e).includes('not confirmed missing');
        }
      }, plan.token);
      expect(blocked).toBe(true);
      expect(await backups()).toHaveLength(0);
    } finally {
      await fixture('conflict-remove');
    }
    preserved(await fixture('inspect'));
    summary.cacheApplyConflictBlocked = true;
    checked(
      'A real executable appearing after cache review blocks native apply before any backup or registry change; removal of only the owned inert conflict restores eligibility',
    );

    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await expect(
      page.getByRole('checkbox', { name: 'Include optional registry history in manual selection' }),
    ).not.toBeChecked();
    await page.getByRole('combobox', { name: 'Cleaning category' }).selectOption('mui_cache');
    await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(original.search);
    await expect(page.locator('.clean-candidate')).toHaveCount(2);
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    await expect(
      page.getByRole('dialog').locator('.clean-review-items details').first(),
    ).toBeVisible();
    for (const item of await page.getByRole('dialog').locator('.clean-review-items details').all())
      await expect(item.locator('summary')).toContainText('Clear stale application display cache');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    checked(
      'Cleaning category and search isolate owned stale cache; category-scoped Quick Clean proposes only display-cache changes, excludes personal history, and cancellation remains read-only',
    );

    for (const mode of ['single', 'selected']) {
      const priorBackupIds = new Set((await backups()).map((b) => b.record.id));
      if (mode === 'single') {
        await results();
        await page
          .getByRole('button', { name: `${win32.basename(info('One').item)} details`, exact: true })
          .click();
        await page.getByRole('button', { name: 'Review cache cleanup', exact: true }).click();
        await expect(
          page.getByRole('heading', { name: 'Clear stale application cache?', exact: true }),
        ).toBeVisible();
        const apply = page.getByRole('button', { name: 'Back up & clear cache', exact: true });
        await expect(apply).toBeDisabled();
        await page.getByRole('dialog').getByRole('checkbox').check();
        await expect(apply).toBeEnabled();
        await page.screenshot({
          path: resolve(output, 'desktop-cache-review.png'),
          fullPage: true,
        });
        await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
        preserved(await fixture('inspect'));
        expect(await backups()).toHaveLength(0);
        await page
          .getByRole('button', { name: `${win32.basename(info('One').item)} details`, exact: true })
          .click();
        await page.getByRole('button', { name: 'Review cache cleanup', exact: true }).click();
        await page.getByRole('dialog').getByRole('checkbox').check();
        await page.getByRole('button', { name: 'Back up & clear cache', exact: true }).click();
      } else {
        await page
          .locator('nav')
          .getByRole('button', { name: 'Clean registry', exact: true })
          .click();
        await page.getByRole('combobox', { name: 'Cleaning category' }).selectOption('mui_cache');
        await page
          .getByRole('textbox', { name: 'Search cleaning candidates' })
          .fill(original.search);
        for (const kind of ['One', 'Two'])
          await page
            .getByRole('checkbox', {
              name: `Select ${win32.basename(info(kind).item)}`,
              exact: true,
            })
            .check();
        await page.getByRole('button', { name: 'Review selected (2)', exact: true }).click();
        await expect(page.getByRole('dialog')).toContainText(info('Two').item);
        await page.getByRole('dialog').getByRole('checkbox').check();
        await page.getByRole('button', { name: 'Back up & clean 2 entries', exact: true }).click();
      }
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30000,
      });
      const kinds = mode === 'single' ? ['One'] : ['One', 'Two'];
      preserved(await fixture('inspect'), kinds);
      const records = (await backups()).filter(
        (b) =>
          !priorBackupIds.has(b.record.id) &&
          kinds.some((k) => info(k).item === b.record.maintenance.item),
      );
      expect(records).toHaveLength(kinds.length);
      for (const b of records) {
        expect(b.record.maintenance.snapshot.values).toHaveLength(2);
        expect(b.record.maintenance.snapshot.preserved).toEqual([]);
      }
      checked(
        `${mode}: only selected application's recognized cache fields are cleared after separate schema-20 backups; both registry-view reads, every pre-existing unrelated value, control registration and permission remain exact`,
      );
      await page.reload();
      await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
      if (mode === 'single') {
        const b = records[0];
        const restorePlan = await page.evaluate(
          (id) => window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId: id }),
          b.record.id,
        );
        const bytes = await readFile(b.path);
        try {
          await fixture('conflict-create');
          const blocked = await page.evaluate(async (token) => {
            try {
              await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
              return false;
            } catch (e) {
              return String(e).includes('not confirmed missing');
            }
          }, restorePlan.token);
          expect(blocked).toBe(true);
          expect(await readFile(b.path)).toEqual(bytes);
          preserved(await fixture('inspect'), ['One']);
        } finally {
          await fixture('conflict-remove');
        }
        summary.cacheRestoreConflictBlocked = true;
        checked(
          'An executable appearing after cache restore review blocks restoration without overwriting cache or backup; only the owned conflict file is removed',
        );
      }
      for (const b of records) await restore(b.record.id);
      preserved(await fixture('inspect'));
      checked(
        `${mode}: display-cache backups survive app reload and restore exact original REG_SZ bytes, including empty display labels, while both views, unrelated values and permissions remain intact`,
      );
    }
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        const after = await fixture('cleanup');
        if (original)
          preserved(
            after,
            original.fixtures.map((f) => f.kind),
          );
      } catch (e) {
        cleanupErrors.push(String(e));
      }
    }
    if (storagePath && original) {
      try {
        for (const b of await backups()) await unlink(b.path);
      } catch (e) {
        cleanupErrors.push(String(e));
      }
    }
    summary.maintenanceFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned maintenance fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned cache values, inert files and matching backups are cleaned; existing cache values and concurrent unrelated additions remain preserved, and personal history is untouched',
  );
}
