import { chromium, expect } from '@playwright/test';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { once } from 'node:events';
import { verifyAppPathRecovery } from './app-path-smoke.mjs';
import { verifyUninstallRecovery } from './uninstall-smoke.mjs';
import { verifyAssociationRecovery } from './association-smoke.mjs';
import { verifyComRecovery } from './com-smoke.mjs';
import { verifyCleaning } from './clean-smoke.mjs';
import { verifyServiceRecovery } from './service-smoke.mjs';
import { verifyDisplayScale } from './display-smoke.mjs';
import { verifyApplicationInventory } from './application-smoke.mjs';

if (process.platform !== 'win32')
  throw new Error('Desktop smoke verification requires Windows x64.');
const root = resolve(import.meta.dirname, '..');
const serviceOnly = process.argv.includes('--service-only');
const expandedOnly = process.argv.includes('--expanded-only');
if (serviceOnly && expandedOnly) throw new Error('Choose only one focused verification mode.');
if (serviceOnly && !process.env.RUSTREGISTRY_SERVICE_FIXTURE_TOKEN)
  throw new Error('A prepared owned service fixture is required for service-only verification.');
const appVersion = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8')).version;
const output = resolve(root, '.temp_files');
await mkdir(output, { recursive: true });
const server = createServer();
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const port = server.address().port;
await new Promise((resolve, reject) =>
  server.close((error) => (error ? reject(error) : resolve())),
);

const executable = resolve(root, process.env.RUSTREGISTRY_EXE || 'target/release/rustregistry.exe');
const child = spawn(executable, [], {
  cwd: root,
  windowsHide: true,
  env: {
    ...process.env,
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-debugging-address=127.0.0.1`,
    WEBVIEW2_USER_DATA_FOLDER: resolve(
      output,
      `webview-smoke-profile-${process.pid}-${Date.now()}`,
    ),
  },
  stdio: 'ignore',
});
let spawnError;
child.on('error', (error) => {
  spawnError = error;
});
let browser;
const summary = {
  executable,
  version: appVersion,
  mode: serviceOnly ? 'service-only' : expandedOnly ? 'expanded-only' : 'full',
  checks: [],
  errors: [],
  skipped: [],
};
const checked = (label) => {
  summary.checks.push(label);
  console.log(`PASS ${label}`);
};

try {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null) throw new Error(`App exited before startup: ${child.exitCode}`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
        signal: AbortSignal.timeout(1000),
      });
      if (response.ok) break;
    } catch {
      /* WebView2 is still starting. */
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 10_000 });
  const context = browser.contexts()[0];
  if (!context) throw new Error('No WebView2 context was exposed.');
  let page = context.pages()[0];
  if (!page) page = await context.waitForEvent('page', { timeout: 10_000 });
  page.setDefaultTimeout(10_000);
  page.on('pageerror', (error) => summary.errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') summary.errors.push(message.text());
  });
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: 'Interface size' }).selectOption('100');
  await page.evaluate(() =>
    window.__TAURI_INTERNALS__.invoke('set_display_scale', { percent: 100 }),
  );
  await expect(page.getByText('Windows x64 · Connected locally', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Start with your first scan' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('.sidebar-version')).toContainText(`v${appVersion}`);
  checked('Packaged desktop app opens in English with a live Tauri connection and no sample data');

  const cdp = await context.newCDPSession(page);
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 960,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await verifyDisplayScale(page, cdp, output, checked, summary);
  await page.screenshot({ path: resolve(output, 'desktop-overview-dark.png'), fullPage: true });
  await page.getByRole('button', { name: 'Start scan', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
    timeout: 30_000,
  });
  await expect(page.locator('tbody tr')).toHaveCount(25);
  const total = Number((await page.locator('.count-chip').innerText()).replaceAll(',', ''));
  expect(total).toBeGreaterThan(0);
  summary.entries = total;
  checked('Real registry scan completes through native IPC and populates the paginated table');
  if (serviceOnly) {
    await verifyServiceRecovery(page, output, checked, summary);
    expect(summary.errors).toEqual([]);
    summary.passed = true;
  } else if (expandedOnly) {
    await verifyApplicationInventory(page, executable, checked, summary);
    await verifyComRecovery(page, output, checked, summary, 'InprocHandler32');
    await verifyComRecovery(page, output, checked, summary, 'LocalServer32');
    expect(summary.errors).toEqual([]);
    summary.passed = true;
  } else {
    const refused = await page.evaluate(async () => {
      try {
        await window.__TAURI_INTERNALS__.invoke('apply_change', {
          token: 'not-a-plan',
          confirmed: false,
        });
        return false;
      } catch (error) {
        return String(error).includes('Explicit confirmation');
      }
    });
    expect(refused).toBe(true);
    const unknownEntryRefused = await page.evaluate(async () => {
      try {
        await window.__TAURI_INTERNALS__.invoke('prepare_quarantine', {
          entryId: '__not_a_scanned_entry__',
        });
        return false;
      } catch (error) {
        return String(error).includes('latest scan');
      }
    });
    expect(unknownEntryRefused).toBe(true);
    const cleaningRefused = await page.evaluate(async () => {
      try {
        await window.__TAURI_INTERNALS__.invoke('apply_clean', {
          token: 'not-a-plan',
          confirmed: false,
        });
        return false;
      } catch (error) {
        return String(error).includes('Explicit confirmation');
      }
    });
    expect(cleaningRefused).toBe(true);
    const unknownCleanRefused = await page.evaluate(async () => {
      try {
        await window.__TAURI_INTERNALS__.invoke('prepare_clean', {
          mode: 'selected',
          entryIds: ['__not_a_scanned_entry__'],
        });
        return false;
      } catch (error) {
        return String(error).includes('latest scan');
      }
    });
    expect(unknownCleanRefused).toBe(true);
    checked(
      'Native single-change and cleaning commands reject unconfirmed writes and unknown scan IDs',
    );
    await page.screenshot({
      path: resolve(output, 'desktop-overview-scanned.png'),
      fullPage: true,
    });

    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect(page.locator('.table-footer')).toContainText('Showing 26–50');
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('startup');
    await expect(page.locator('tbody tr').first().locator('.category-cell')).toHaveText('Startup');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('found');
    const foundRows = await page.locator('tbody tr').count();
    expect(foundRows).toBeGreaterThan(0);
    await expect(page.locator('tbody tr').first().locator('.status-badge')).toHaveText('Found');
    checked('Pagination and combined category/status filters work on actual scan records');

    await page.locator('.entry-button').first().click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.locator('.detail-footer')).toContainText('This entry was only read.');
    await expect(page.locator('.detail-fields')).toContainText('Registry path');
    await expect(page.locator('.detail-fields')).toContainText('REG_');
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    checked('Entry details show registry evidence and close correctly with Escape');

    await page
      .getByRole('textbox', { name: 'Search entries' })
      .fill('__rustregistry_no_matching_entry_92813__');
    await expect(
      page.getByRole('heading', { name: 'No entries match your filters' }),
    ).toBeVisible();
    await expect(page.locator('tbody tr')).toHaveCount(0);
    await page.getByRole('button', { name: 'Clear filters', exact: true }).click();
    await expect(page.locator('tbody tr')).toHaveCount(25);
    checked('Search empty state is honest and clearing filters restores real entries');

    await page.locator('nav').getByRole('button', { name: 'Scan coverage', exact: true }).click();
    await expect(page.locator('.scope-item')).toHaveCount(23);
    await page.locator('.scope-item summary').first().click();
    await expect(page.locator('.scope-item').first().locator('.scope-notes')).toBeVisible();
    checked('Coverage lists all 23 actual registry locations with expandable read results');

    await page.locator('nav').getByRole('button', { name: 'Session history', exact: true }).click();
    await expect(page.locator('.history-item')).toHaveCount(1);
    await page.locator('.history-item').first().click();
    await expect(page.getByRole('heading', { name: 'Scan results', exact: true })).toBeVisible();
    checked('Session history reopens the completed scan');
    for (const category of ['shared_dlls']) {
      await page.getByRole('combobox', { name: 'Filter by category' }).selectOption(category);
      await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
      if (await page.locator('.entry-button').count()) {
        await page.locator('.entry-button').first().click();
        await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(
          0,
        );
        await expect(page.getByRole('button', { name: 'Review disable', exact: true })).toHaveCount(
          0,
        );
        await page.keyboard.press('Escape');
      } else
        await expect(
          page.getByRole('heading', { name: 'No entries match your filters', exact: true }),
        ).toBeVisible();
    }
    checked(
      'Shared DLL inventory shows real records or an honest empty state and offers no repair',
    );

    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.getByRole('heading', { name: /Local backups/ })).toBeVisible();
    await expect(page.locator('.backup-location .mono')).toContainText('backups-v1');
    const backupCount = Number(await page.locator('.count-chip').innerText());
    checked('Persistent backup discovery is available without creating or changing startup values');

    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('startup');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('review');
    let reviewed = false;
    for (const button of await page.locator('.entry-button').all()) {
      await button.click();
      const review = page.getByRole('button', { name: 'Review disable', exact: true });
      if (await review.count()) {
        await review.click();
        await expect(
          page.getByRole('heading', { name: 'Disable this startup entry?', exact: true }),
        ).toBeVisible();
        const apply = page.getByRole('button', { name: 'Back up & disable', exact: true });
        await expect(apply).toBeDisabled();
        await page.getByRole('checkbox').check();
        await expect(apply).toBeEnabled();
        await page.screenshot({
          path: resolve(output, 'desktop-change-review.png'),
          fullPage: true,
        });
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(page.getByRole('dialog')).toHaveCount(0);
        reviewed = true;
        break;
      }
      await page.keyboard.press('Escape');
    }
    if (reviewed)
      checked(
        'An eligible real entry opens an explicit review; cancellation applies no registry change',
      );
    else {
      summary.skipped.push(
        'No eligible HKCU missing-target entry exists on this machine; change review was not exercised.',
      );
      console.log(`SKIP ${summary.skipped.at(-1)}`);
    }
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.locator('.count-chip')).toHaveText(String(backupCount));
    checked('Review cancellation leaves the backup inventory unchanged');
    await verifyAppPathRecovery(page, output, checked, summary);
    await verifyUninstallRecovery(page, output, checked, summary);
    await verifyAssociationRecovery(page, output, checked, summary);
    await verifyApplicationInventory(page, executable, checked, summary);
    await verifyComRecovery(page, output, checked, summary);
    await verifyComRecovery(page, output, checked, summary, 'InprocHandler32');
    await verifyComRecovery(page, output, checked, summary, 'LocalServer32');
    await verifyCleaning(page, output, checked, summary);
    await verifyServiceRecovery(page, output, checked, summary);

    await page.getByRole('link', { name: 'RustRegistry overview', exact: true }).click();
    await page.getByRole('button', { name: 'Switch to light theme', exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.screenshot({ path: resolve(output, 'desktop-overview-light.png'), fullPage: true });
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 940,
      height: 700,
      deviceScaleFactor: 1,
      mobile: false,
    });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.screenshot({ path: resolve(output, 'desktop-compact-light.png'), fullPage: true });
    await page.getByRole('button', { name: 'Switch to dark theme', exact: true }).click();
    checked('Light/dark themes and the 940px minimum desktop layout render without page overflow');

    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1440,
      height: 960,
      deviceScaleFactor: 1,
      mobile: false,
    });
    // Synchronize with the first rendered Stop control. Playwright's click-stability
    // wait can outlast a cached native scan and send cancellation after completion.
    await page.evaluate(
      () =>
        new Promise((resolve, reject) => {
          const start = [...document.querySelectorAll('button')].find(
            (button) => button.textContent.trim() === 'Scan again',
          );
          if (!start) {
            reject(new Error('No scan button'));
            return;
          }
          const timer = setTimeout(() => {
            observer.disconnect();
            reject(new Error('Stop control did not appear'));
          }, 5000);
          const observer = new MutationObserver(() => {
            const stop = [...document.querySelectorAll('button')].find(
              (button) => button.textContent.trim() === 'Stop',
            );
            if (stop) {
              observer.disconnect();
              clearTimeout(timer);
              stop.click();
              resolve();
            }
          });
          observer.observe(document.body, { childList: true, subtree: true });
          start.click();
        }),
    );
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled();
    await expect(
      page.getByText('Scan stopped. These results only include the sections that could be read.', {
        exact: true,
      }),
    ).toBeVisible();
    checked('An in-flight real scan can be stopped and is clearly labeled as incomplete');

    await page.getByRole('button', { name: 'About RustRegistry', exact: true }).click();
    await expect(page.getByText('Read-only scanning', { exact: true })).toBeVisible();
    expect(summary.errors).toEqual([]);
    checked('No browser console or uncaught rendering errors during the desktop flow');
    summary.passed = true;
  }
} catch (error) {
  summary.passed = false;
  summary.failure = String(error);
  console.error(error);
  process.exitCode = 1;
} finally {
  const fixtureToken = process.env.RUSTREGISTRY_SERVICE_FIXTURE_TOKEN;
  if (
    fixtureToken &&
    /^[a-f0-9-]{36}$/.test(fixtureToken) &&
    summary.serviceFixtureCleanup === undefined
  ) {
    try {
      const shell = resolve(
        process.env.SystemRoot || 'C:\\Windows',
        'System32/WindowsPowerShell/v1.0/powershell.exe',
      );
      await promisify(execFile)(
        shell,
        [
          '-NoProfile',
          '-NonInteractive',
          '-File',
          resolve(root, 'scripts/service-fixture.ps1'),
          '-Action',
          'cleanup',
          '-Token',
          fixtureToken,
        ],
        { windowsHide: true, timeout: 15_000 },
      );
      summary.serviceFixtureCleanup = true;
    } catch (error) {
      summary.errors.push(String(error));
      summary.serviceFixtureCleanup = false;
      summary.passed = false;
      process.exitCode = 1;
    }
  }
  await writeFile(
    resolve(
      output,
      serviceOnly
        ? 'desktop-service-verification.json'
        : expandedOnly
          ? 'desktop-expanded-verification.json'
          : 'desktop-verification.json',
    ),
    JSON.stringify(summary, null, 2),
  );
  if (browser) await browser.close().catch(() => {});
  if (child.exitCode === null) child.kill();
}
