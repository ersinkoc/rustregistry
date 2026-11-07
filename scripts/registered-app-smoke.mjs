import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifyRegisteredApplicationRecovery(page, output, checked, summary) {
  const token = randomUUID();
  const prefix = `RustRegistry-E2E-Registration-${token}-`;
  const capRoot = `Software\\RustRegistryE2E-${token}`;
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
        resolve(import.meta.dirname, 'registered-app-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
      ],
      { windowsHide: true, timeout: 15000, encoding: 'utf8' },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const results = async () => {
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page
      .getByRole('combobox', { name: 'Filter by category' })
      .selectOption('registered_applications');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
  };
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
      if (!info.isFile() || info.isSymbolicLink() || info.size > 262144) continue;
      let record;
      try {
        record = JSON.parse(await readFile(path, 'utf8'));
      } catch {
        continue;
      }
      if (
        record.schemaVersion === 10 &&
        record.valueName.startsWith(prefix) &&
        record.registeredApp?.capabilitiesPath.startsWith(`${capRoot}\\`)
      )
        matches.push({ path, record });
    }
    return matches;
  };
  let original,
    attempted = false,
    failure;
  const cleanupErrors = [];
  const restore = async (kind) => {
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    const backup = page
      .locator('.backup-item')
      .filter({ has: page.getByRole('heading', { name: prefix + kind, exact: true }) })
      .first();
    await expect(backup).toContainText('Application registration');
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Restore application registration?', exact: true }),
    ).toBeVisible();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore registration', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.registeredApplicationFixtureToken = token;
    await scan();
    await results();
    await expect(page.locator('tbody tr')).toHaveCount(4);
    for (const [kind, status] of [
      ['MissingOne', 'Review'],
      ['MissingTwo', 'Review'],
      ['Found', 'Found'],
      ['Malformed', 'Unverified'],
    ]) {
      const row = page.locator('tbody tr').filter({
        has: page.getByRole('button', { name: `${prefix + kind} details`, exact: true }),
      });
      await expect(row.locator('.status-badge')).toHaveText(status);
      await row.locator('.entry-button').click();
      if (kind.startsWith('Missing'))
        await expect(
          page.getByRole('button', { name: 'Review repair', exact: true }),
        ).toBeEnabled();
      else
        await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(
          0,
        );
      await page.keyboard.press('Escape');
    }
    checked(
      'RegisteredApplications inventory distinguishes missing Capabilities, existing targets, and malformed values; only verified current-user orphans offer repair',
    );
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    for (const kind of ['MissingOne', 'MissingTwo'])
      await expect(page.getByRole('dialog')).toContainText(prefix + kind);
    for (const kind of ['Found', 'Malformed'])
      await expect(page.getByRole('dialog')).not.toContainText(prefix + kind);
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    expect(await backups()).toHaveLength(0);
    checked(
      'Quick Clean includes both independent orphaned registrations; cancel preserves all raw values, unrelated registrations, child names, and permissions without backups',
    );
    for (const mode of ['single', 'selected']) {
      const targets = mode === 'single' ? ['MissingOne'] : ['MissingOne', 'MissingTwo'];
      if (mode === 'single') {
        await results();
        await page
          .getByRole('button', { name: `${prefix}MissingOne details`, exact: true })
          .click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
        await expect(
          page.getByRole('heading', {
            name: 'Remove orphaned application registration?',
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.getByRole('dialog')).toContainText(
          `${capRoot}\\MissingOne\\Capabilities`,
        );
        await expect(
          page.getByRole('button', { name: 'Back up & remove registration', exact: true }),
        ).toBeDisabled();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        expect(await fixture('inspect')).toEqual(original);
        expect(await backups()).toHaveLength(0);
        checked(
          'Application registration review shows exact name and Capabilities path and requires confirmation; cancellation is read-only',
        );
        await page
          .getByRole('button', { name: `${prefix}MissingOne details`, exact: true })
          .click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
      } else {
        await scan();
        await page
          .locator('nav')
          .getByRole('button', { name: 'Clean registry', exact: true })
          .click();
        await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(token);
        await expect(page.locator('.clean-candidate')).toHaveCount(2);
        for (const kind of targets)
          await page
            .getByRole('checkbox', { name: `Select ${prefix + kind}`, exact: true })
            .check();
        await page.getByRole('button', { name: 'Review selected (2)', exact: true }).click();
        await expect(page.locator('.clean-review-items details')).toHaveCount(2);
        await page.locator('.clean-review-items details summary').first().click();
      }
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page.screenshot({
        path: resolve(output, `desktop-registered-app-${mode}-review.png`),
        fullPage: true,
      });
      await page
        .getByRole('button', {
          name: mode === 'single' ? 'Back up & remove registration' : 'Back up & clean 2 entries',
          exact: true,
        })
        .click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30000,
      });
      expect(await fixture('inspect')).toEqual({
        ...original,
        state: {
          ...original.state,
          owned: original.state.owned.map((value) =>
            targets.some((kind) => value.name === prefix + kind)
              ? { ...value, present: false, kind: null, bytes: null }
              : value,
          ),
        },
      });
      const records = await backups();
      expect(records).toHaveLength(mode === 'single' ? 1 : 3);
      for (const { record } of records) {
        expect(record.original.kind).toBe(1);
        const expected = original.state.owned.find((v) => v.name === record.valueName);
        expect(Buffer.from(record.original.bytes).toString('base64')).toBe(expected.bytes);
      }
      checked(
        `${mode}: only selected registration values are removed after individual verified backups; existing Capabilities, control values, unrelated registrations, subkeys, and permissions remain exact`,
      );
      for (const kind of targets) await restore(kind);
      expect(await fixture('inspect')).toEqual(original);
      checked(
        `${mode}: registration backups survive reload and restore exact original REG_SZ bytes without changing controls, Capabilities, or permissions`,
      );
    }
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        const cleaned = await fixture('cleanup');
        expect(cleaned.state.owned.every((v) => !v.present)).toBe(true);
        expect(cleaned.capabilitiesControl).toBe(false);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
      try {
        for (const { path } of await backups()) await unlink(path);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.registeredApplicationFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned application registration cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned RegisteredApplications values, Capabilities controls, and matching test backups are removed; existing registrations and backups remain untouched',
  );
}
