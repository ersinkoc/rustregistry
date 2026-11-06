import { chromium, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { once } from 'node:events';

if (process.platform !== 'win32')
  throw new Error('Desktop smoke verification requires Windows x64.');
const root = resolve(import.meta.dirname, '..');
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
    WEBVIEW2_USER_DATA_FOLDER: resolve(output, 'webview-smoke-profile'),
  },
  stdio: 'ignore',
});
let spawnError;
child.on('error', (error) => {
  spawnError = error;
});
let browser;
const summary = { executable, checks: [], errors: [] };
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
  await expect(page.getByText('Windows x64 · Connected locally', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Start with your first scan' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  checked('Packaged desktop app opens in English with a live Tauri connection and no sample data');

  const cdp = await context.newCDPSession(page);
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 960,
    deviceScaleFactor: 1,
    mobile: false,
  });
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
  await page.screenshot({ path: resolve(output, 'desktop-overview-scanned.png'), fullPage: true });

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
  await expect(page.getByRole('heading', { name: 'No entries match your filters' })).toBeVisible();
  await expect(page.locator('tbody tr')).toHaveCount(0);
  await page.getByRole('button', { name: 'Clear filters', exact: true }).click();
  await expect(page.locator('tbody tr')).toHaveCount(25);
  checked('Search empty state is honest and clearing filters restores real entries');

  await page.locator('nav').getByRole('button', { name: 'Scan coverage', exact: true }).click();
  await expect(page.locator('.scope-item')).toHaveCount(12);
  await page.locator('.scope-item summary').first().click();
  await expect(page.locator('.scope-item').first().locator('.scope-notes')).toBeVisible();
  checked('Coverage lists all 12 actual registry locations with expandable read results');

  await page.locator('nav').getByRole('button', { name: 'Session history', exact: true }).click();
  await expect(page.locator('.history-item')).toHaveCount(1);
  await page.locator('.history-item').first().click();
  await expect(page.getByRole('heading', { name: 'Scan results', exact: true })).toBeVisible();
  checked('Session history reopens the completed scan');

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
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: resolve(output, 'desktop-compact-light.png'), fullPage: true });
  await page.getByRole('button', { name: 'Switch to dark theme', exact: true }).click();
  checked('Light/dark themes and the 940px minimum desktop layout render without page overflow');

  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 960,
    deviceScaleFactor: 1,
    mobile: false,
  });
  // Queue the Stop click before starting the next scan, so even a fast real scan can be cancelled.
  const stop = page.getByRole('button', { name: 'Stop', exact: true }).click({ timeout: 5000 });
  await page.getByRole('button', { name: 'Scan again', exact: true }).click();
  await stop;
  await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled();
  await expect(
    page.getByText('Scan stopped. These results only include the sections that could be read.', {
      exact: true,
    }),
  ).toBeVisible();
  checked('An in-flight real scan can be stopped and is clearly labeled as incomplete');

  await page.getByRole('button', { name: 'About RustRegistry', exact: true }).click();
  await expect(page.getByText('Read access only', { exact: true })).toBeVisible();
  expect(summary.errors).toEqual([]);
  checked('No browser console or uncaught rendering errors during the desktop flow');
  summary.passed = true;
} catch (error) {
  summary.passed = false;
  summary.failure = String(error);
  console.error(error);
  process.exitCode = 1;
} finally {
  await writeFile(resolve(output, 'desktop-verification.json'), JSON.stringify(summary, null, 2));
  if (browser) await browser.close().catch(() => {});
  if (child.exitCode === null) child.kill();
}
