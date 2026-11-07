import { expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { promisify } from 'node:util';
const run = promisify(execFile);
const script = resolve(import.meta.dirname, 'app-path-fixture.ps1');

export async function verifyCleaning(page, output, checked, summary) {
  const tokens = [randomUUID(), randomUUID()];
  const names = tokens.map((token) => `RustRegistry-E2E-${token}.exe`);
  const shell = join(
    process.env.SystemRoot || 'C:\\Windows',
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );
  const fixture = async (action, name) => {
    const { stdout } = await run(
      shell,
      ['-NoProfile', '-NonInteractive', '-File', script, '-Action', action, '-Name', name],
      { windowsHide: true, encoding: 'utf8', timeout: 10_000 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  await page.locator('nav').getByRole('button', { name: 'Backups & restore', exact: true }).click();
  await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
  const storagePath = await page.locator('.backup-location .mono').innerText();
  const attempted = [];
  const originals = [];
  let failure;
  const cleanupErrors = [];
  try {
    for (const name of names) {
      attempted.push(name);
      originals.push(await fixture('create', name));
    }
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(names[0]);
    await expect(page.getByRole('dialog')).toContainText(names[1]);
    await expect(
      page.getByRole('dialog').getByRole('button', { name: /Back up & clean/ }),
    ).toBeDisabled();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    for (let i = 0; i < names.length; i++)
      expect(await fixture('inspect', names[i])).toEqual(originals[i]);
    checked(
      'Quick Clean proposes live protected candidates; review/cancel changes no owned values',
    );

    await page
      .getByRole('textbox', { name: 'Search cleaning candidates' })
      .fill('RustRegistry-E2E-');
    for (const name of names)
      await page.getByRole('checkbox', { name: `Select ${name}`, exact: true }).check();
    await page.getByRole('button', { name: 'Review selected (2)', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Review selected cleaning', exact: true }),
    ).toBeVisible();
    await expect(page.locator('.clean-review-items details')).toHaveCount(2);
    for (const name of names) await expect(page.getByRole('dialog')).toContainText(name);
    await page.locator('.clean-review-items details').first().locator('summary').click();
    await page.screenshot({ path: resolve(output, 'desktop-clean-review.png'), fullPage: true });
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & clean 2 entries', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    for (let i = 0; i < names.length; i++) {
      const after = await fixture('inspect', names[i]);
      expect(after).toEqual({
        ...originals[i],
        value: null,
        kind: null,
        valueCount: originals[i].valueCount - 1,
      });
    }
    checked(
      'Selected Clean applies exactly two owned repairs with a separate verified backup for each',
    );

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    for (let i = 0; i < names.length; i++) {
      const backup = page
        .locator('.backup-item')
        .filter({ has: page.getByRole('heading', { name: names[i], exact: true }) });
      await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
      await expect(page.getByRole('dialog')).toContainText(names[i]);
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page.getByRole('button', { name: 'Restore original value', exact: true }).click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30_000,
      });
      expect(await fixture('inspect', names[i])).toEqual(originals[i]);
    }
    checked(
      'Both cleaning backups survive reload and restore each original registration independently',
    );
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.screenshot({ path: resolve(output, 'desktop-clean-panel.png'), fullPage: true });
  } catch (error) {
    failure = error;
  } finally {
    for (const name of attempted) {
      try {
        await fixture('cleanup', name);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
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
        const index = names.indexOf(record.appPath?.executable);
        const marker = record.appPath?.guard?.values?.find(
          (item) => item.name === 'RustRegistryFixture',
        );
        if (
          index >= 0 &&
          marker &&
          Buffer.from(marker.value.bytes).toString('utf16le').replace(/\0+$/, '') === tokens[index]
        )
          await unlink(path);
      }
    } catch (error) {
      cleanupErrors.push(String(error));
    }
    summary.cleanFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned cleaning fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Cleaning fixtures and their matching backups are cleaned without modifying existing user entries',
  );
}
