import { expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
const script = resolve(import.meta.dirname, 'uninstall-fixture.ps1');
export async function verifyUninstallRecovery(page, output, checked, summary) {
  const token = randomUUID();
  const name = `RustRegistry-E2E-Uninstall-${token}`;
  await page.locator('nav').getByRole('button', { name: 'Backups & restore', exact: true }).click();
  await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
  const storagePath = await page.locator('.backup-location .mono').innerText();
  const shell = join(
    process.env.SystemRoot || 'C:\\Windows',
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );
  const fixture = async (action) => {
    const { stdout } = await run(
      shell,
      ['-NoProfile', '-NonInteractive', '-File', script, '-Action', action, '-Name', name],
      { windowsHide: true, encoding: 'utf8', timeout: 10_000 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  let attempted = false;
  let failure;
  const cleanupErrors = [];
  try {
    attempted = true;
    const original = await fixture('create');
    expect(original.marker).toBe(token);
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('uninstall');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('review');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.locator('.entry-button').click();
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(original.displayName);
    await expect(
      page.getByRole('heading', { name: 'Repair orphaned uninstall entry?', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Back up & hide entry', exact: true }),
    ).toBeDisabled();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    checked(
      'Uninstall repair review and cancellation preserve every owned fixture value and its permissions',
    );

    await page.locator('.entry-button').click();
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(original.displayName);
    await page.getByRole('checkbox').check();
    await page.screenshot({
      path: resolve(output, 'desktop-uninstall-review.png'),
      fullPage: true,
    });
    await page.getByRole('button', { name: 'Back up & hide entry', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    const backup = page
      .locator('.backup-item')
      .filter({ has: page.getByRole('heading', { name: original.displayName, exact: true }) });
    await expect(backup.getByRole('button', { name: 'Review restore', exact: true })).toBeEnabled();
    const expectedValues = [
      ...original.values,
      { name: 'SystemComponent', kind: 'DWord', value: 1 },
    ].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase(), 'en'));
    expect(await fixture('inspect')).toEqual({ ...original, hidden: true, values: expectedValues });
    checked(
      'Packaged uninstall repair changes only SystemComponent; full values and key permissions are preserved',
    );

    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await expect(
      page.getByRole('heading', { name: 'No entries match your filters' }),
    ).toBeVisible();
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('unknown');
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.locator('.entry-button').click();
    await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
    await expect(page.locator('.detail-fields')).toContainText('uninstall_hidden');
    await page.keyboard.press('Escape');
    checked('Hidden uninstall listings remain inventoried and no longer offer another repair');

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(backup.getByRole('button', { name: 'Review restore', exact: true })).toBeEnabled();
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(original.displayName);
    await expect(
      page.getByRole('heading', { name: 'Restore uninstall entry visibility?', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Restore original visibility', exact: true }),
    ).toBeDisabled();
    await page.getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore original visibility', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    expect(await fixture('inspect')).toEqual(original);
    await expect(
      backup.getByRole('button', { name: 'Original present', exact: true }),
    ).toBeDisabled();
    await page.screenshot({
      path: resolve(output, 'desktop-uninstall-restored.png'),
      fullPage: true,
    });
    checked(
      'Uninstall backup survives UI reload and restores all original values, flag absence, and permissions',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        await fixture('cleanup');
      } catch (error) {
        cleanupErrors.push(String(error));
      }
      try {
        for (const file of await readdir(storagePath).catch((error) => {
          if (error.code === 'ENOENT') return [];
          throw error;
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
          const marker = record.uninstall?.snapshot?.values?.find(
            (item) => item.name === 'RustRegistryFixture',
          );
          if (
            record.uninstall?.keyName === name &&
            marker &&
            Buffer.from(marker.value.bytes).toString('utf16le').replace(/\0+$/, '') === token
          )
            await unlink(path);
        }
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.uninstallFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned uninstall fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned uninstall fixture and its backup are cleaned without changing existing entries or backups',
  );
}
