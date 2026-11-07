import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifySharedDllRecovery(page, output, checked, summary) {
  const token = process.env.RUSTREGISTRY_SHARED_DLL_FIXTURE_TOKEN;
  if (!token) {
    summary.skipped.push(
      'Live SharedDLLs recovery requires an explicitly elevated owned-fixture test session.',
    );
    console.log(`SKIP ${summary.skipped.at(-1)}`);
    return;
  }
  if (!/^[a-f0-9-]{36}$/.test(token)) throw new Error('Invalid shared DLL fixture identifier.');
  const shell = resolve(
    process.env.SystemRoot || 'C:\\Windows',
    'System32/WindowsPowerShell/v1.0/powershell.exe',
  );
  const script = resolve(import.meta.dirname, 'shared-dll-fixture.ps1');
  const fixture = async (action) => {
    const { stdout } = await run(
      shell,
      ['-NoProfile', '-NonInteractive', '-File', script, '-Action', action, '-Token', token],
      { windowsHide: true, timeout: 15_000, encoding: 'utf8' },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
  };
  const results = async () => {
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('shared_dlls');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
  };
  const row = (name, view) =>
    page
      .locator('tbody tr')
      .filter({ has: page.getByRole('button', { name: `${name} details`, exact: true }) })
      .filter({
        has: page.locator('.view-label').filter({ hasText: new RegExp(`^${view} bit$`) }),
      });
  await page.locator('nav').getByRole('button', { name: 'Backups & restore', exact: true }).click();
  await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
  const storagePath = await page.locator('.backup-location .mono').innerText();
  let original;
  let attempted = false;
  let failure;
  const cleanupErrors = [];
  let zeroPath;
  const backups = async () => {
    const matches = [];
    for (const file of await readdir(storagePath).catch((e) => {
      if (e.code === 'ENOENT') return [];
      throw e;
    })) {
      if (!/^[a-f0-9-]{36}\.json$/.test(file)) continue;
      const path = resolve(storagePath, file);
      const info = await lstat(path);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 262_144) continue;
      let record;
      try {
        record = JSON.parse(await readFile(path, 'utf8'));
      } catch {
        continue;
      }
      if (
        zeroPath &&
        record.schemaVersion === 9 &&
        record.sharedDll?.path === zeroPath &&
        record.sharedDll?.view === '64' &&
        record.valueName === zeroPath
      )
        matches.push({ path, record });
    }
    return matches;
  };
  try {
    attempted = true;
    original = await fixture('create');
    zeroPath = original.zeroPath;
    const name = zeroPath.split('\\').at(-1);
    await scan();
    await results();
    await expect(page.locator('tbody tr')).toHaveCount(6);
    for (const state of original.views) {
      for (const value of state.owned) {
        const entryName = value.name.split('\\').at(-1);
        const eligible = state.view === '64' && value.name === zeroPath;
        const status =
          state.view === '32' || value.kind !== 4
            ? 'Unverified'
            : entryName.endsWith('-existing.dll')
              ? 'Found'
              : 'Review';
        const entry = row(entryName, state.view);
        await expect(entry.locator('.status-badge')).toHaveText(status);
        await entry.locator('.entry-button').click();
        if (eligible)
          await expect(
            page.getByRole('button', { name: 'Review repair', exact: true }),
          ).toBeEnabled();
        else
          await expect(
            page.getByRole('button', { name: 'Review repair', exact: true }),
          ).toHaveCount(0);
        await page.keyboard.press('Escape');
      }
    }
    checked(
      'Shared DLL inventory offers only the missing 64-bit zero-count fixture; positive, existing, malformed, Windows, and 32-bit controls stay read-only',
    );
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(name);
    for (const value of original.views
      .find((v) => v.view === '64')
      .owned.filter((v) => v.name !== zeroPath))
      await expect(page.getByRole('dialog')).not.toContainText(value.name);
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    expect(await backups()).toHaveLength(0);
    checked(
      'Quick Clean includes the zero-count DLL reference; review/cancel preserves all counters, both views, permissions, and the inert file without a backup',
    );
    for (const mode of ['single', 'selected']) {
      if (mode === 'single') {
        await results();
        await row(name, '64').locator('.entry-button').click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
        await expect(
          page.getByRole('heading', {
            name: 'Remove zero-count shared DLL reference?',
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.getByRole('dialog')).toContainText('64 bit · machine-wide');
        await expect(
          page.getByRole('button', { name: 'Back up & remove reference', exact: true }),
        ).toBeDisabled();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        expect(await fixture('inspect')).toEqual(original);
        expect(await backups()).toHaveLength(0);
        checked(
          'Shared DLL review displays the exact DWORD zero and machine-wide path, requires confirmation, and cancels without mutation',
        );
        await row(name, '64').locator('.entry-button').click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
      } else {
        await scan();
        await page
          .locator('nav')
          .getByRole('button', { name: 'Clean registry', exact: true })
          .click();
        await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(token);
        await expect(page.locator('.clean-candidate')).toHaveCount(1);
        await page.getByRole('checkbox', { name: `Select ${name}`, exact: true }).check();
        await page.getByRole('button', { name: 'Review selected (1)', exact: true }).click();
        await expect(page.locator('.clean-review-items details')).toHaveCount(1);
        await page.locator('.clean-review-items details summary').click();
      }
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page.screenshot({
        path: resolve(output, `desktop-shared-dll-${mode}-review.png`),
        fullPage: true,
      });
      await page
        .getByRole('button', {
          name: mode === 'single' ? 'Back up & remove reference' : 'Back up & clean 1 entries',
          exact: true,
        })
        .click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30_000,
      });
      expect(await fixture('inspect')).toEqual({
        ...original,
        views: original.views.map((v) =>
          v.view === '64'
            ? {
                ...v,
                owned: v.owned.map((value) =>
                  value.name === zeroPath
                    ? { ...value, present: false, kind: null, bytes: null }
                    : value,
                ),
              }
            : v,
        ),
      });
      const records = await backups();
      expect(records).toHaveLength(mode === 'single' ? 1 : 2);
      for (const { record } of records)
        expect(record.original).toEqual({ kind: 4, bytes: [0, 0, 0, 0] });
      checked(
        `${mode}: only the owned 64-bit zero-count value is removed after backup; all other raw counters, both root permissions, and files remain exact`,
      );
      await results();
      await expect(row(name, '64')).toHaveCount(0);
      await expect(row(name, '32')).toHaveCount(1);
      await page.reload();
      await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
      await page
        .locator('nav')
        .getByRole('button', { name: 'Backups & restore', exact: true })
        .click();
      const backup = page
        .locator('.backup-item')
        .filter({ has: page.getByRole('heading', { name, exact: true }) })
        .first();
      await expect(backup).toContainText('Shared DLL reference · 64 bit');
      await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
      await expect(
        page.getByRole('heading', { name: 'Restore shared DLL reference?', exact: true }),
      ).toBeVisible();
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page.getByRole('button', { name: 'Restore zero-count reference', exact: true }).click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30_000,
      });
      expect(await fixture('inspect')).toEqual(original);
      checked(
        `${mode}: shared DLL backup survives reload and restores the exact original zero DWORD with both views, all other values, permissions, and files intact`,
      );
    }
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        const cleaned = await fixture('cleanup');
        expect(cleaned.views.every((v) => v.owned.every((value) => !value.present))).toBe(true);
        expect(cleaned.existingFile).toBe(false);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
      try {
        for (const { path } of await backups()) await unlink(path);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.sharedDllFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned shared DLL fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned SharedDLLs values in both views, the inert file, and matching test backups are cleaned without changing unrelated counters or permissions',
  );
}
