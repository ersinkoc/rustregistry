import { chromium, expect } from '@playwright/test';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { randomUUID, createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
const root = resolve(import.meta.dirname, '..'),
  output = resolve(root, '.temp_files'),
  run = promisify(execFile);
const shell = resolve(
  process.env.SystemRoot || 'C:\\Windows',
  'System32/WindowsPowerShell/v1.0/powershell.exe',
);
const executable = resolve(
  root,
  process.env.RUSTREGISTRY_EXE || 'target/release/rustregistry-webview.exe',
);
const policyToken = process.env.RUSTREGISTRY_ELEVATED_WEBVIEW_TOKEN;
if (!policyToken || !executable.endsWith(`RustRegistry-E2E-WebView-${policyToken}.exe`))
  throw Error('An owned isolated executable alias is required.');
const version = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8')).version;
await mkdir(output, { recursive: true });
const token = randomUUID(),
  server = createServer();
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const port = server.address().port;
await new Promise((ok, bad) => server.close((e) => (e ? bad(e) : ok())));
const profile = resolve(output, `webview-recovery-${token}`);
const summary = {
  version,
  executable,
  checks: [],
  errors: [],
  passed: false,
  operationFixtureCleanup: false,
};
const checked = (label) => {
  summary.checks.push(label);
  console.log(`PASS ${label}`);
};
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
const policy = async (action) => {
  const { stdout } = await run(
    shell,
    [
      '-NoProfile',
      '-NonInteractive',
      '-File',
      resolve(root, 'scripts/webview-test-policy.ps1'),
      '-Action',
      action,
      '-Token',
      policyToken,
      '-Executable',
      executable,
      '-Port',
      String(port),
      '-UserDataFolder',
      profile,
    ],
    { windowsHide: true, timeout: 15000 },
  );
  return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
};
const fixture = async (action) => {
  const { stdout } = await run(
    shell,
    [
      '-NoProfile',
      '-NonInteractive',
      '-File',
      resolve(root, 'scripts/operation-fixture.ps1'),
      '-Action',
      action,
      '-Token',
      token,
    ],
    { windowsHide: true, timeout: 60000, maxBuffer: 8 * 1024 * 1024 },
  );
  return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
};
let child,
  browser,
  page,
  original,
  storage,
  policyAttempted = false,
  fixtureAttempted = false;
const invoke = (command, args = {}) =>
  page.evaluate(({ command, args }) => window.__TAURI_INTERNALS__.invoke(command, args), {
    command,
    args,
  });
async function launch() {
  child = spawn(executable, [], {
    cwd: root,
    windowsHide: true,
    stdio: 'ignore',
    env: {
      ...process.env,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port} --remote-debugging-address=127.0.0.1`,
      WEBVIEW2_USER_DATA_FOLDER: profile,
    },
  });
  let spawnError;
  child.on('error', (e) => {
    spawnError = e;
  });
  const until = Date.now() + 30000;
  while (Date.now() < until) {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null) throw Error(`App exited ${child.exitCode}`);
    try {
      if (
        (await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(500) }))
          .ok
      )
        break;
    } catch {}
    await sleep(100);
  }
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 10000 });
  const context = browser.contexts()[0];
  page = context.pages()[0] || (await context.waitForEvent('page'));
  page.setDefaultTimeout(15000);
  page.on('pageerror', (e) => summary.errors.push(e.message));
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: 'Interface size' }).selectOption('100');
  await invoke('set_display_scale', { percent: 100 });
  const cdp = await context.newCDPSession(page);
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1600,
    height: 1100,
    deviceScaleFactor: 1,
    mobile: false,
  });
}
async function kill() {
  if (!child || child.exitCode !== null) return;
  const exit = once(child, 'exit');
  child.kill('SIGKILL');
  await exit;
  browser = undefined;
  await sleep(1000);
}
async function scan() {
  const button = page.getByRole('button', { name: 'Scan again', exact: true });
  if (await button.count()) await button.click();
  else await page.getByRole('button', { name: 'Start scan', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
    timeout: 60000,
  });
}
async function selectClean() {
  await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
  await page.getByRole('combobox', { name: 'Cleaning category' }).selectOption('startup');
  await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(original.search);
  await page.getByRole('button', { name: 'Select matching (up to 10,000)', exact: true }).click();
  await page.getByRole('button', { name: 'Review selected (1000)', exact: true }).click();
  await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(50);
  await page.getByRole('dialog').getByRole('checkbox').check();
}
const preserve = (state) => {
  expect(state.environmentPreserved).toBe(true);
  for (const value of state.current)
    expect(original.original.find((v) => v.name === value.name)).toEqual(value);
};
const ownedBackups = async () => {
  const records = [];
  if (!storage) return records;
  for (const name of await readdir(storage)) {
    if (!/^[a-f0-9-]{36}\.json$/.test(name)) continue;
    const path = resolve(storage, name),
      stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) continue;
    const record = JSON.parse(await readFile(path, 'utf8'));
    if (record.schemaVersion === 1 && original.names.includes(record.valueName))
      records.push({ record, path });
  }
  return records;
};
const backupHashes = async () => {
  const hashes = {};
  if (!storage) return hashes;
  for (const name of await readdir(storage)) {
    if (!/^[a-f0-9-]{36}\.json$/.test(name)) continue;
    hashes[name] = createHash('sha256')
      .update(await readFile(resolve(storage, name)))
      .digest('hex');
  }
  return hashes;
};
let baseline;
try {
  fixtureAttempted = true;
  original = await fixture('create');
  expect(original.current).toHaveLength(1000);
  preserve(original);
  checked('Owned 1,000 startup values created; pre-existing bytes, structure and ACLs preserved');
  policyAttempted = true;
  await policy('create');
  await launch();
  storage = (await invoke('list_backups')).storagePath;
  baseline = await backupHashes();
  summary.baselineBackups = Object.keys(baseline).length;
  await scan();
  const history = await invoke('list_scan_history');
  expect(history.scans.length).toBeGreaterThan(0);
  summary.savedScanId = history.scans[0].id;
  checked('Real scan saved to persistent compressed history');
  await selectClean();
  await page.getByRole('button', { name: 'Back up & clean 1000 entries', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 180000 });
  await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
    timeout: 60000,
  });
  let state = await fixture('inspect');
  preserve(state);
  expect(state.current).toHaveLength(0);
  let records = await ownedBackups();
  expect(records).toHaveLength(1000);
  for (const { record } of records) {
    const prior = original.original.find((v) => v.name === record.valueName);
    expect(record.original.kind).toBe(prior.type);
    expect(Buffer.from(record.original.bytes).toString('base64')).toBe(prior.data);
  }
  const clean = (await invoke('list_operations')).operations.find(
    (op) => op.kind === 'clean' && op.total === 1000,
  );
  expect(clean.state).toBe('completed');
  expect(clean.applied).toBe(1000);
  summary.fullOperationId = clean.id;
  checked(
    'GUI selected cleaning commits 1,000 entries with 1,000 exact-byte backups and one completed journal',
  );
  await page.locator('nav').getByRole('button', { name: 'Backups & restore', exact: true }).click();
  await page.getByRole('textbox', { name: 'Search backups' }).fill(original.search);
  await page.getByRole('button', { name: 'Select matching backups', exact: true }).click();
  await page.getByRole('button', { name: 'Review restore selected (1000)', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('1000 restore available');
  await page.getByRole('button', { name: 'Confirm bulk Undo', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 180000 });
  await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
    timeout: 60000,
  });
  state = await fixture('inspect');
  preserve(state);
  expect(state.current).toEqual(original.original);
  checked('GUI bulk restore of 1,000 backup selections restores every original byte');
  await selectClean();
  await page.getByRole('button', { name: 'Back up & clean 1000 entries', exact: true }).click();
  await expect
    .poll(
      async () => {
        const text = await page.getByRole('dialog').textContent();
        return /([5-8]\d\d)\s*(?:\/|of)\s*1,?000/.test(text || '');
      },
      { timeout: 90000, intervals: [20, 20, 20] },
    )
    .toBe(true);
  await kill();
  state = await fixture('inspect');
  preserve(state);
  const removed = 1000 - state.current.length;
  expect(removed).toBeGreaterThanOrEqual(500);
  expect(removed).toBeLessThan(1000);
  summary.killedCleanRemoved = removed;
  checked(
    `Native process forcibly terminated after ${removed} real commits; unattempted values remain original`,
  );
  await launch();
  const operations = await invoke('list_operations');
  const interrupted = operations.operations.find(
    (op) => op.kind === 'clean' && op.state === 'interrupted',
  );
  expect(interrupted).toBeTruthy();
  expect(interrupted.applied).toBeLessThanOrEqual(removed);
  expect(interrupted.attempted).toBeGreaterThanOrEqual(removed);
  summary.interruptedOperationId = interrupted.id;
  await page.locator('nav').getByRole('button', { name: 'Saved scans', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Saved scan history', exact: true }),
  ).toBeVisible();
  const saved = await invoke('list_scan_history');
  expect(saved.scans.some((s) => s.id === summary.savedScanId)).toBe(true);
  await page.locator('.history-item').first().click();
  await expect(
    page.getByText('Saved report — read-only. Run a fresh scan before cleaning or repairing.', {
      exact: true,
    }),
  ).toBeVisible();
  await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
  for (const button of await page
    .getByRole('button', { name: /Review (?:selected|Full Clean|Quick Clean)/ })
    .all()) {
    await expect(button).toBeDisabled();
  }
  const historicalBlocked = await invoke('prepare_clean', {
    mode: 'selected',
    entryIds: ['archived-not-live'],
    category: null,
    scanId: 'not-a-live-scan',
  }).then(
    () => false,
    () => true,
  );
  expect(historicalBlocked).toBe(true);
  checked(
    'Saved scans survive force-kill/reopen and remain read-only without fresh native repair authority',
  );
  await page.locator('nav').getByRole('button', { name: 'Recovery Center', exact: true }).click();
  const row = page.locator(`[data-operation-id="${interrupted.id}"]`);
  await expect(row).toContainText('interrupted');
  await row.getByRole('button', { name: 'Review Undo', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText(`${removed} restore available`);
  await page.screenshot({
    path: resolve(output, 'desktop-v0200-interrupted-undo.png'),
    fullPage: true,
  });
  await page.getByRole('button', { name: 'Confirm bulk Undo', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 180000 });
  await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
    timeout: 60000,
  });
  state = await fixture('inspect');
  preserve(state);
  expect(state.current).toEqual(original.original);
  checked(
    'Recovery Center Undo reconciles interrupted intent and restores exactly the changed values after reopening',
  );
  const priorScanCount = (await invoke('list_scan_history')).scans.length;
  await kill();
  await launch();
  expect(
    (await invoke('list_operations')).operations.some(
      (op) => op.sourceOperationId === interrupted.id && op.state === 'completed',
    ),
  ).toBe(true);
  expect((await invoke('list_scan_history')).scans.length).toBe(priorScanCount);
  checked('Completed Undo and scan history persist through a second restart');
  const after = await backupHashes();
  for (const [name, hash] of Object.entries(baseline)) expect(after[name]).toBe(hash);
  checked('All pre-existing backup files remain byte-identical');
  summary.passed = true;
} catch (error) {
  summary.errors.push(String(error));
  console.error(error);
  process.exitCode = 1;
} finally {
  await kill().catch((error) => summary.errors.push(String(error)));
  if (fixtureAttempted) {
    try {
      const cleaned = await fixture('cleanup');
      expect(cleaned.current).toHaveLength(0);
      expect(cleaned.environmentPreserved).toBe(true);
      summary.operationFixtureCleanup = true;
      if (original && storage) for (const { path } of await ownedBackups()) await unlink(path);
    } catch (error) {
      summary.errors.push(String(error));
      summary.passed = false;
      process.exitCode = 1;
    }
  }
  if (policyAttempted) {
    try {
      expect((await policy('cleanup')).cleaned).toBe(true);
      summary.webviewTestPolicyCleanup = true;
    } catch (error) {
      summary.errors.push(String(error));
      summary.passed = false;
      process.exitCode = 1;
    }
  }
  summary.isolatedState = resolve(dirname(executable), 'state-v0200');
  summary.passed = summary.passed && summary.errors.length === 0;
  await writeFile(
    resolve(output, 'desktop-recovery-verification.json'),
    JSON.stringify(summary, null, 2),
  );
}
