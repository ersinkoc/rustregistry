import { expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
const script = resolve(import.meta.dirname, 'association-fixture.ps1');
export async function verifyAssociationRecovery(page, output, checked, summary) {
  const token = randomUUID();
  const extension = `.rr${token.replaceAll('-', '')}`;
  const progid = `RustRegistry.E2E.Missing.${token}`;
  const name = `${extension} · ${progid}`;
  await page.locator('nav').getByRole('button', { name: 'Backups & restore', exact: true }).click();
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
      ['-NoProfile', '-NonInteractive', '-File', script, '-Action', action, '-Token', token],
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
    expect(original.userChoicePresent).toBe(false);
    const originalSuggestion = original.values.find((v) => v.name === progid);
    expect(originalSuggestion.kind).toBe('None');
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page
      .getByRole('combobox', { name: 'Filter by category' })
      .selectOption('file_associations');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('review');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(progid);
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.locator('.entry-button').click();
    await expect(page.locator('.detail-fields')).toContainText('progid_missing');
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(name);
    await expect(
      page.getByRole('heading', { name: 'Repair orphaned file association?', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Back up & remove suggestion', exact: true }),
    ).toBeDisabled();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    checked(
      'File association review/cancel preserves owned suggestions, defaults, permissions, and absent UserChoice',
    );

    await page.locator('.entry-button').click();
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(name);
    await page.getByRole('checkbox').check();
    await page.screenshot({
      path: resolve(output, 'desktop-association-review.png'),
      fullPage: true,
    });
    await page.getByRole('button', { name: 'Back up & remove suggestion', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    expect(await fixture('inspect')).toEqual({
      ...original,
      values: original.values.filter((v) => v.name !== progid),
    });
    const backup = page
      .locator('.backup-item')
      .filter({ has: page.getByRole('heading', { name, exact: true }) });
    await expect(backup.getByRole('button', { name: 'Review restore', exact: true })).toBeEnabled();
    checked(
      'Packaged association repair removes only one orphaned suggestion after backup and preserves defaults and permissions',
    );

    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await expect(
      page.getByRole('heading', { name: 'No entries match your filters', exact: true }),
    ).toBeVisible();
    await page
      .getByRole('textbox', { name: 'Search entries' })
      .fill(`RustRegistry.E2E.Keep.${token}`);
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.locator('.entry-button').click();
    await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
    await expect(page.getByRole('dialog')).toContainText('default application selection');
    await page.keyboard.press('Escape');
    checked('Default-selected association suggestions remain visible and cannot be repaired');

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(backup.getByRole('button', { name: 'Review restore', exact: true })).toBeEnabled();
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(name);
    await expect(
      page.getByRole('heading', { name: 'Restore Open with suggestion?', exact: true }),
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
      path: resolve(output, 'desktop-association-restored.png'),
      fullPage: true,
    });
    checked(
      'Association backup survives UI reload and restores the exact REG_NONE suggestion without changing default selections',
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
          const marker = record.association?.guard?.extensionValues?.find(
            (item) => item.name === 'RustRegistryFixture',
          );
          if (
            record.association?.extension === extension &&
            record.valueName === progid &&
            marker &&
            Buffer.from(marker.value.bytes).toString('utf16le').replace(/\0+$/, '') === token
          )
            await unlink(path);
        }
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.associationFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned association fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned file association fixture and its matching backup are cleaned; existing registrations and backups stay untouched',
  );
}
