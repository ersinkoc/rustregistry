import { expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
const run = promisify(execFile);

export async function verifyApplicationRecovery(page, executable, checked, summary) {
  const token = randomUUID();
  const shell = resolve(
    process.env.SystemRoot || 'C:\\Windows',
    'System32/WindowsPowerShell/v1.0/powershell.exe',
  );
  const script = resolve(import.meta.dirname, 'application-fixture.ps1');
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
        '-FoundTarget',
        executable,
      ],
      { windowsHide: true, encoding: 'utf8', timeout: 10_000 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const name = `RustRegistry-E2E-App-${token}-Missing.exe`;
  await page.locator('nav').getByRole('button', { name: 'Backups & restore', exact: true }).click();
  await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
  const storagePath = await page.locator('.backup-location .mono').innerText();
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
        record.schemaVersion === 8 &&
        record.name === name &&
        record.application?.executable === name
      )
        matches.push({ path, record });
    }
    return matches;
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30_000,
    });
  };
  try {
    const original = await fixture('create');
    await scan();
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page
      .getByRole('combobox', { name: 'Filter by category' })
      .selectOption('application_commands');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
    await expect(page.locator('tbody tr')).toHaveCount(4);
    for (const [kind, status] of [
      ['Missing', 'Review'],
      ['Found', 'Found'],
      ['Delegated', 'Unverified'],
      ['Hidden', 'Unverified'],
    ]) {
      const name = `RustRegistry-E2E-App-${token}-${kind}.exe`;
      const row = page
        .locator('tbody tr')
        .filter({ has: page.getByRole('button', { name: `${name} details`, exact: true }) });
      await expect(row.locator('.status-badge')).toHaveText(status);
      await row.locator('.entry-button').click();
      await expect(page.getByRole('dialog')).toContainText('"%1"');
      if (kind === 'Missing')
        await expect(
          page.getByRole('button', { name: 'Review repair', exact: true }),
        ).toBeEnabled();
      else
        await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(
          0,
        );
      await expect(page.getByRole('button', { name: 'Review disable', exact: true })).toHaveCount(
        0,
      );
      await page.keyboard.press('Escape');
    }
    checked(
      'Application inventory distinguishes eligible missing, found, delegated, and already-hidden registrations while preserving shell arguments',
    );
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText(name);
    for (const kind of ['Found', 'Delegated', 'Hidden'])
      await expect(page.getByRole('dialog')).not.toContainText(
        `RustRegistry-E2E-App-${token}-${kind}.exe`,
      );
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    expect(await backups()).toHaveLength(0);
    checked(
      'Quick Clean includes only the eligible application; review/cancel preserves every command, flag, and permission without creating a backup',
    );

    for (const mode of ['single', 'selected']) {
      if (mode === 'single') {
        await page
          .locator('nav')
          .getByRole('button', { name: /Scan results/ })
          .click();
        await page.getByRole('button', { name: `${name} details`, exact: true }).click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
        await expect(
          page.getByRole('heading', { name: 'Hide broken application suggestion?', exact: true }),
        ).toBeVisible();
        await expect(page.getByRole('dialog')).toContainText('NoOpenWith');
        await expect(
          page.getByRole('button', { name: 'Back up & hide suggestion', exact: true }),
        ).toBeDisabled();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        expect(await fixture('inspect')).toEqual(original);
        expect(await backups()).toHaveLength(0);
        checked(
          'Application repair review identifies the exact preserved command and optional visibility flag; cancellation creates no backup or registry change',
        );
        await page.getByRole('button', { name: `${name} details`, exact: true }).click();
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
        path: resolve(import.meta.dirname, `../.temp_files/desktop-application-${mode}-review.png`),
        fullPage: true,
      });
      await page
        .getByRole('button', {
          name: mode === 'single' ? 'Back up & hide suggestion' : 'Back up & clean 1 entries',
          exact: true,
        })
        .click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30_000,
      });
      expect(await fixture('inspect')).toEqual({
        ...original,
        applications: original.applications.map((app) =>
          app.name === name ? { ...app, noOpenWith: true } : app,
        ),
      });
      const records = await backups();
      expect(records).toHaveLength(mode === 'single' ? 1 : 2);
      for (const { record } of records) {
        expect(Buffer.from(record.original.bytes).toString('utf16le').replace(/\0+$/, '')).toBe(
          original.applications.find((app) => app.name === name).command,
        );
        expect(record.original.kind).toBe(2);
        expect(record.application.snapshot.applicationValues).toEqual([]);
      }
      checked(
        `${mode}: application repair adds only NoOpenWith after an integrity-checked backup; all open commands, control entries, and permissions remain exact`,
      );

      await page
        .locator('nav')
        .getByRole('button', { name: /Scan results/ })
        .click();
      await page
        .getByRole('combobox', { name: 'Filter by category' })
        .selectOption('application_commands');
      await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
      await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('unknown');
      const row = page
        .locator('tbody tr')
        .filter({ has: page.getByRole('button', { name: `${name} details`, exact: true }) });
      await row.locator('.entry-button').click();
      await expect(page.getByRole('dialog')).toContainText('application_hidden');
      await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
      await page.keyboard.press('Escape');
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
      await expect(backup).toContainText('Application suggestion');
      await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
      await expect(
        page.getByRole('heading', { name: 'Restore application suggestion?', exact: true }),
      ).toBeVisible();
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page
        .getByRole('button', { name: 'Restore suggestion visibility', exact: true })
        .click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30_000,
      });
      expect(await fixture('inspect')).toEqual(original);
      checked(
        `${mode}: application backup survives reload and removes only the added flag, restoring exact commands, metadata, controls, and permissions`,
      );
    }
  } finally {
    const cleaned = await fixture('cleanup');
    expect(cleaned.applications.every((item) => !item.exists)).toBe(true);
    for (const { path } of await backups()) await unlink(path);
    summary.applicationFixtureCleanup = true;
  }
  checked('Owned application command fixtures are removed without touching existing registrations');
}
