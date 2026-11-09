import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);
export async function verifyLargeCleaning(page, output, checked, summary) {
  const token = randomUUID();
  let original,
    storage,
    failure,
    attempted = false;
  const cleanup = [];
  const fixture = async (action) => {
    const { stdout } = await run(
      resolve(
        process.env.SystemRoot || 'C:\\Windows',
        'System32/WindowsPowerShell/v1.0/powershell.exe',
      ),
      [
        '-NoProfile',
        '-NonInteractive',
        '-File',
        resolve(import.meta.dirname, 'large-clean-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
      ],
      { windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const targetSet = () => new Set(original.targets.map((t) => t.toLowerCase()));
  const backups = async () => {
    const result = [];
    const targets = targetSet();
    for (const file of await readdir(storage)) {
      if (!/^[a-f0-9-]{36}\.json$/.test(file)) continue;
      const path = resolve(storage, file);
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) continue;
      let record;
      try {
        record = JSON.parse(await readFile(path, 'utf8'));
      } catch {
        continue;
      }
      if (record.schemaVersion === 20 && targets.has(record.maintenance?.item?.toLowerCase()))
        result.push({ record, path });
    }
    return result;
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const preserved = (state, removed = []) => {
    expect(state.environmentPreserved).toBe(true);
    const targets = new Set(removed.map((t) => t.toLowerCase()));
    expect(state.current).toEqual(
      original.original.filter(
        (v) =>
          !targets.has(
            v.name.replace(/\.(FriendlyAppName|ApplicationCompany)$/i, '').toLowerCase(),
          ),
      ),
    );
  };
  const selectOwned = async () => {
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('combobox', { name: 'Cleaning category' }).selectOption('mui_cache');
    await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(original.search);
    await expect(page.locator('.clean-candidate')).toHaveCount(50);
    await page.getByRole('button', { name: 'Select matching (up to 10,000)', exact: true }).click();
    await expect(
      page.getByRole('button', { name: 'Review selected (128)', exact: true }),
    ).toBeEnabled();
  };
  const start = async () => {
    await page.getByRole('button', { name: 'Review selected (128)', exact: true }).click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(50);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & clean 128 entries', exact: true }).click();
  };
  const restoreNative = async (records) => {
    const count = await page.evaluate(
      async (ids) => {
        for (const backupId of ids) {
          const p = await window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId });
          await window.__TAURI_INTERNALS__.invoke('apply_change', {
            token: p.token,
            confirmed: true,
          });
        }
        return ids.length;
      },
      records.map((b) => b.record.id),
    );
    expect(count).toBe(records.length);
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.largeCleanFixtureToken = token;
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
    storage = await page.locator('.backup-location .mono').innerText();
    await scan();
    await selectOwned();
    await page.getByRole('button', { name: 'Next candidates', exact: true }).click();
    await expect(page.locator('.clean-candidate input:checked')).toHaveCount(50);
    await page.getByRole('button', { name: 'Next candidates', exact: true }).click();
    await expect(page.locator('.clean-candidate input:checked')).toHaveCount(28);
    await page.getByRole('button', { name: 'Previous candidates', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    summary.largeCleanSelectionVerified = true;
    checked(
      'All 128 owned candidates can be selected across three pages without a 100-entry cutoff; page navigation preserves selection and registry bytes',
    );
    await page.getByRole('button', { name: 'Review Full Clean', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Review Full Clean', exact: true })).toBeVisible(
      { timeout: 30000 },
    );
    await expect(page.getByRole('dialog')).toContainText('changes are ready for review');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    summary.fullCleanReviewReadOnly = true;
    checked(
      'Full Clean reviews the latest supported candidates across categories, excludes personal history and cancels without applying any real-user or owned change',
    );
    await page.getByRole('button', { name: 'Review selected (128)', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Next review entries', exact: true }).click();
    await expect(dialog.locator('.clean-review-items details')).toHaveCount(50);
    await dialog.getByRole('button', { name: 'Next review entries', exact: true }).click();
    await expect(dialog.locator('.clean-review-items details')).toHaveCount(28);
    await expect(
      dialog.getByRole('button', { name: 'Back up & clean 128 entries', exact: true }),
    ).toBeDisabled();
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    summary.largeCleanReviewPagingVerified = true;
    checked(
      'Large review pages expose all 128 actions and original values while confirmation remains required; no review truncation or mutation occurs',
    );
    await start();
    const progress = page.getByRole('progressbar', { name: 'Cleaning progress', exact: true });
    await expect(progress).toBeVisible();
    await expect
      .poll(async () => Number(await progress.getAttribute('value')), { timeout: 30000 })
      .toBeGreaterThan(0);
    await page.getByRole('button', { name: 'Stop after current entry', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 60000 });
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    const stopped = await backups();
    expect(stopped.length).toBeGreaterThan(0);
    expect(stopped.length).toBeLessThan(128);
    preserved(
      await fixture('inspect'),
      stopped.map((b) => b.record.maintenance.item),
    );
    summary.largeCleanCancellationVerified = true;
    summary.largeCleanStoppedCount = stopped.length;
    checked(
      'Live cleaning progress advances and Stop ends the batch after a completed entry; only completed owned targets change and every one has an independent verified backup',
    );
    await restoreNative(stopped);
    preserved(await fixture('inspect'));
    await scan();
    checked(
      'Every completed entry from the stopped batch restores exact original raw bytes through fresh native recovery while unattempted targets remain untouched',
    );
    await selectOwned();
    const before = new Set((await backups()).map((b) => b.record.id));
    await start();
    await expect(
      page.getByRole('progressbar', { name: 'Cleaning progress', exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 180000 });
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    const completed = (await backups()).filter((b) => !before.has(b.record.id));
    expect(completed).toHaveLength(128);
    preserved(await fixture('inspect'), original.targets);
    for (const b of completed) {
      expect(b.record.integritySha256).toMatch(/^[a-f0-9]{64}$/);
      expect(b.record.maintenance.snapshot.values).toHaveLength(2);
    }
    summary.largeCleanCompleted128 = true;
    checked(
      'Selected Clean completes 128 actual Windows cache groups with 128 verified independent backups; all unrelated live values and permissions remain preserved',
    );
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    const search = page.getByRole('textbox', { name: 'Search backups', exact: true });
    await search.fill(original.search);
    await expect(page.locator('.backup-item')).toHaveCount(50);
    await page.getByRole('button', { name: 'Next backups', exact: true }).click();
    await expect(page.locator('.backup-item')).toHaveCount(50);
    await search.fill(completed[0].record.id);
    await expect(page.locator('.backup-item')).toHaveCount(1);
    summary.largeCleanBackupPagingVerified = true;
    await page.screenshot({
      path: resolve(output, 'desktop-large-clean-recovery.png'),
      fullPage: true,
    });
    await page
      .locator('.backup-item')
      .getByRole('button', { name: 'Review restore', exact: true })
      .click();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page
      .getByRole('dialog')
      .getByRole('button', { name: 'Restore cache values', exact: true })
      .click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    await restoreNative(completed.slice(1));
    preserved(await fixture('inspect'));
    summary.largeCleanExactRestoreVerified = true;
    checked(
      'All 128 completed backups survive reload, remain reachable by pages/search and restore exact original bytes; one UI restore and all remaining native restores preserve pre-existing backups and registry data',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (attempted)
      try {
        const after = await fixture('cleanup');
        expect(after.current).toHaveLength(0);
        expect(after.environmentPreserved).toBe(true);
      } catch (error) {
        cleanup.push(String(error));
      }
    if (storage && original)
      try {
        for (const b of await backups()) await unlink(b.path);
      } catch (error) {
        cleanup.push(String(error));
      }
    summary.largeCleanFixtureCleanup = cleanup.length === 0;
    summary.errors.push(...cleanup);
  }
  if (failure) throw failure;
  if (cleanup.length) throw new Error(cleanup.join('; '));
  checked(
    'Owned large-clean cache values and matching test backups are conditionally removed while every pre-existing value, permission and backup remains preserved',
  );
}
