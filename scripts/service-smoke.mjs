import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { promisify } from 'node:util';
const run = promisify(execFile);
const script = resolve(import.meta.dirname, 'service-fixture.ps1');

export async function verifyServiceRecovery(page, output, checked, summary) {
  const token = process.env.RUSTREGISTRY_SERVICE_FIXTURE_TOKEN;
  if (!token) {
    summary.skipped.push(
      'Live service mutation UI: no explicitly approved owned service fixture is configured. No administrator prompt is launched by the suite.',
    );
    console.log(`SKIP ${summary.skipped.at(-1)}`);
    return;
  }
  if (!/^[a-f0-9-]{36}$/.test(token)) throw new Error('Invalid approved service fixture token.');
  const name = `RustRegistry-E2E-Service-${token}`;
  const displayName = `RustRegistry E2E service ${token}`;
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
      { windowsHide: true, encoding: 'utf8', timeout: 15_000 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  await page.locator('nav').getByRole('button', { name: 'Backups & restore', exact: true }).click();
  const storagePath = await page.locator('.backup-location .mono').innerText();
  let failure;
  const cleanupErrors = [];
  try {
    const original = await fixture('inspect');
    expect(original.services).toHaveLength(2);
    expect(original.services.find((service) => service.name === name).startMode).toBe('Manual');
    const disabled = {
      ...original,
      services: original.services.map((service) =>
        service.name === name
          ? {
              ...service,
              startMode: 'Disabled',
              values: service.values.map((item) =>
                item.name.toLowerCase() === 'start' ? { ...item, value: 4 } : item,
              ),
            }
          : service,
      ),
    };
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('services');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('review');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(`${token}-Control`);
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.locator('.entry-button').click();
    await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
    await page.keyboard.press('Escape');
    checked(
      'The already-disabled owned control service stays read-only and is excluded from repair',
    );

    await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
    await expect(page.locator('tbody tr')).toHaveCount(2);
    const openService = () =>
      page.getByRole('button', { name: `${displayName} details`, exact: true }).click();
    await openService();
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(displayName);
    await expect(
      page.getByRole('heading', { name: 'Disable this missing-target service?', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Back up & disable service', exact: true }),
    ).toBeDisabled();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    checked(
      'Service review/cancel preserves both SCM configurations, all registry values, status, and permissions',
    );

    await openService();
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(displayName);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.screenshot({ path: resolve(output, 'desktop-service-review.png'), fullPage: true });
    await page.getByRole('button', { name: 'Back up & disable service', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    expect(await fixture('inspect')).toEqual(disabled);
    checked(
      'The SCM-backed repair changes only the owned service startup type to Disabled; neither service is started or stopped',
    );
    const backup = page
      .locator('.backup-item')
      .filter({ has: page.getByRole('heading', { name: displayName, exact: true }) });
    await expect(backup.getByRole('button', { name: 'Review restore', exact: true })).toBeEnabled();
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(displayName);
    await expect(
      page.getByRole('heading', { name: 'Restore service startup?', exact: true }),
    ).toBeVisible();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore Manual startup', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    expect(await fixture('inspect')).toEqual(original);
    checked(
      'The service backup survives UI reload and restores Manual startup with exact configuration and permissions',
    );

    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(displayName);
    await expect(page.getByRole('dialog')).not.toContainText(`${displayName} control`);
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(token);
    await page.getByRole('checkbox', { name: `Select ${displayName}`, exact: true }).check();
    await page.getByRole('button', { name: 'Review selected (1)', exact: true }).click();
    await expect(page.locator('.clean-review-items details')).toHaveCount(1);
    await expect(page.getByRole('dialog')).toContainText(displayName);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & clean 1 entries', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    expect(await fixture('inspect')).toEqual(disabled);
    checked(
      'Quick Clean includes the eligible service and excludes the disabled control; selected Clean uses the same guarded SCM repair',
    );
    const readyBackup = page
      .locator('.backup-item')
      .filter({ has: page.getByRole('heading', { name: displayName, exact: true }) })
      .first();
    await readyBackup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(displayName);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore Manual startup', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    expect(await fixture('inspect')).toEqual(original);
  } catch (error) {
    failure = error;
  } finally {
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
        if (
          record.service?.serviceName === name &&
          record.service?.snapshot?.config?.displayName === displayName
        )
          await unlink(path);
      }
    } catch (error) {
      cleanupErrors.push(String(error));
    }
    summary.serviceFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned service fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Both owned services and their matching backups are removed; existing services and user backups remain untouched',
  );
}
