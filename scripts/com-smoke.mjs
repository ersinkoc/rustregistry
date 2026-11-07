import { expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { promisify } from 'node:util';
const run = promisify(execFile);
const script = resolve(import.meta.dirname, 'com-fixture.ps1');

export async function verifyComRecovery(page, output, checked, summary, server = 'InprocServer32') {
  const expanded = server !== 'InprocServer32';
  const label =
    server === 'LocalServer32'
      ? 'COM server command'
      : server === 'InprocHandler32'
        ? 'COM handler mapping'
        : 'COM DLL mapping';
  const token = randomUUID();
  const clsid = `{${token}}`;
  const name = `RustRegistry E2E COM ${token}${expanded ? ` ${server}` : ''}`;
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
      [
        '-NoProfile',
        '-NonInteractive',
        '-File',
        script,
        '-Action',
        action,
        '-Token',
        token,
        '-ServerKind',
        server,
      ],
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
    expect(original.views).toHaveLength(2);
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('com');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('unknown');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.locator('.entry-button').click();
    await expect(page.getByRole('dialog')).toContainText('com_32bit_unverified');
    await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
    await page.keyboard.press('Escape');
    checked('The owned 32-bit COM mapping is inventoried as unverified and remains read-only');

    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('review');
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await page.locator('.entry-button').click();
    await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(name);
    await expect(
      page.getByRole('heading', { name: `Repair broken ${label}?`, exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('dialog')).toContainText('64 bit · current user');
    await expect(
      page.getByRole('button', { name: 'Back up & disable mapping', exact: true }),
    ).toBeDisabled();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    checked(
      'COM review and cancellation preserve both registry views, all metadata, and permissions',
    );

    if (expanded) {
      await page
        .locator('nav')
        .getByRole('button', { name: 'Clean registry', exact: true })
        .click();
      await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
      await expect(page.getByRole('dialog')).toContainText(name);
      await page.getByRole('button', { name: 'Cancel', exact: true }).click();
      expect(await fixture('inspect')).toEqual(original);
      checked(
        `${server}: Quick Clean includes the guarded mapping; cancellation preserves all values`,
      );
      await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(token);
      await page.getByRole('checkbox', { name: `Select ${name}`, exact: true }).check();
      await page.getByRole('button', { name: 'Review selected (1)', exact: true }).click();
      await expect(page.locator('.clean-review-items details')).toHaveCount(1);
    } else {
      await page.locator('.entry-button').click();
      await page.getByRole('button', { name: 'Review repair', exact: true }).click();
    }
    await expect(page.getByRole('dialog')).toContainText(name);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.screenshot({
      path: resolve(output, `desktop-com-${server}-review.png`),
      fullPage: true,
    });
    await page
      .getByRole('button', {
        name: expanded ? 'Back up & clean 1 entries' : 'Back up & disable mapping',
        exact: true,
      })
      .click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
    const expected = {
      ...original,
      views: original.views.map((view) =>
        view.view === 'Registry64'
          ? { ...view, serverValues: view.serverValues.filter((item) => item.name !== '') }
          : view,
      ),
    };
    expect(await fixture('inspect')).toEqual(expected);
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    const backup = page
      .locator('.backup-item')
      .filter({ has: page.getByRole('heading', { name, exact: true }) });
    await expect(backup.getByRole('button', { name: 'Review restore', exact: true })).toBeEnabled();
    checked(
      `Packaged ${server} repair removes only the 64-bit default mapping; the 32-bit mapping, metadata, and permissions are preserved`,
    );

    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await expect(
      page.getByRole('heading', { name: 'No entries match your filters', exact: true }),
    ).toBeVisible();
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('unknown');
    await expect(page.locator('tbody tr')).toHaveCount(2);
    checked('Disabled COM mappings remain in the inventory without being offered another repair');

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(name);
    await expect(
      page.getByRole('heading', { name: `Restore ${label}?`, exact: true }),
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
      path: resolve(output, `desktop-com-${server}-restored.png`),
      fullPage: true,
    });
    checked(
      `${server} backup survives UI reload and restores the exact REG_EXPAND_SZ value with both views and permissions intact`,
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
          const description = record.com?.guard?.classValues?.find((item) => item.name === '');
          if (
            record.com?.clsid === clsid &&
            record.com?.view === '64' &&
            description &&
            Buffer.from(description.value.bytes).toString('utf16le').replace(/\0+$/, '') === name
          )
            await unlink(path);
        }
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary[`com${server}FixtureCleanup`] = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned COM fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned COM registrations in both views and their matching backup are cleaned without changing existing registrations or backups',
  );
}
