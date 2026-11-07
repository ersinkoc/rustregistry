import { expect } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
const run = promisify(execFile);

export async function verifyApplicationInventory(page, executable, checked, summary) {
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
  try {
    const original = await fixture('create');
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
      .selectOption('application_commands');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
    await expect(page.locator('tbody tr')).toHaveCount(3);
    for (const [kind, status] of [
      ['Missing', 'Review'],
      ['Found', 'Found'],
      ['Delegated', 'Unverified'],
    ]) {
      const name = `RustRegistry-E2E-App-${token}-${kind}.exe`;
      const row = page
        .locator('tbody tr')
        .filter({ has: page.getByRole('button', { name: `${name} details`, exact: true }) });
      await expect(row.locator('.status-badge')).toHaveText(status);
      await row.locator('.entry-button').click();
      await expect(page.getByRole('dialog')).toContainText('"%1"');
      await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Review disable', exact: true })).toHaveCount(
        0,
      );
      await page.keyboard.press('Escape');
    }
    checked(
      'Application open-command inventory distinguishes missing, found, and delegated targets without interpreting shell argument placeholders',
    );
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    const search = page.getByRole('textbox', { name: 'Search cleaning candidates' });
    if (await search.count()) await search.fill(token);
    else
      await expect(
        page.getByRole('heading', { name: 'No eligible entries to clean', exact: true }),
      ).toBeVisible();
    await expect(page.locator('.clean-candidate')).toHaveCount(0);
    expect(await fixture('inspect')).toEqual(original);
    checked(
      'Application command scanning preserves every owned value and permission and excludes all three read-only controls from Clean',
    );
  } finally {
    const cleaned = await fixture('cleanup');
    expect(cleaned.applications.every((item) => !item.exists)).toBe(true);
    summary.applicationFixtureCleanup = true;
  }
  checked('Owned application command fixtures are removed without touching existing registrations');
}
