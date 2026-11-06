import { expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
const fixtureScript = resolve(import.meta.dirname, 'app-path-fixture.ps1');

export async function verifyAppPathRecovery(page, output, checked, summary) {
  const token = randomUUID();
  const name = `RustRegistry-E2E-${token}.exe`;
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
      ['-NoProfile', '-NonInteractive', '-File', fixtureScript, '-Action', action, '-Name', name],
      { windowsHide: true, encoding: 'utf8', timeout: 10_000 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  let created = false;
  let failure;
  const cleanupErrors = [];
  try {
    created = true;
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
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('app_paths');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('review');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(name);
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.locator('.entry-button').click();
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Repair broken application path?', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Back up & repair', exact: true }),
    ).toBeDisabled();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    checked('App Paths repair review and cancellation preserve the owned fixture exactly');

    await page.locator('.entry-button').click();
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await page.getByRole('checkbox').check();
    await page.screenshot({ path: resolve(output, 'desktop-app-path-review.png'), fullPage: true });
    await page.getByRole('button', { name: 'Back up & repair', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    const backup = page
      .locator('.backup-item')
      .filter({ has: page.getByRole('heading', { name, exact: true }) });
    await expect(backup.getByRole('button', { name: 'Review restore', exact: true })).toBeEnabled();
    const disabled = await fixture('inspect');
    expect(disabled).toEqual({
      ...original,
      value: null,
      kind: null,
      valueCount: original.valueCount - 1,
    });
    checked(
      'Packaged app repairs only the owned App Paths default and preserves all helper metadata',
    );

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(backup.getByRole('button', { name: 'Review restore', exact: true })).toBeEnabled();
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Restore application path?', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Restore original value', exact: true }),
    ).toBeDisabled();
    await page.getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore original value', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    expect(await fixture('inspect')).toEqual(original);
    await expect(
      backup.getByRole('button', { name: 'Original present', exact: true }),
    ).toBeDisabled();
    await page.screenshot({
      path: resolve(output, 'desktop-app-path-restored.png'),
      fullPage: true,
    });
    checked(
      'App Paths backup survives UI reload and restores the owned fixture with metadata intact',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (created) {
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
          const marker = record.appPath?.guard?.values?.find(
            (value) => value.name === 'RustRegistryFixture',
          );
          if (
            record.name === name &&
            record.appPath?.executable === name &&
            marker &&
            Buffer.from(marker.value.bytes).toString('utf16le').replace(/\0+$/, '') === token
          )
            await unlink(path);
        }
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.appPathFixtureCleanup = cleanupErrors.length === 0;
    if (cleanupErrors.length) summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned App Paths fixture and its test backup are cleaned without touching existing registrations',
  );
}
