import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifyLeftoverUrls(page, output, checked, summary) {
  const token = randomUUID();
  let original,
    storage,
    failure,
    attempted = false;
  const cleanup = [];
  const fixture = async (action) => {
    const { stdout } = await run(
      resolve(
        process.env.SystemRoot || 'C:\\Windows',
        'System32/WindowsPowerShell/v1.0/powershell.exe',
      ),
      [
        '-NoProfile',
        '-NonInteractive',
        '-File',
        resolve(import.meta.dirname, 'leftover-urls-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
      ],
      { windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const one = () => original.fixtures[0];
  const entryId = (f, name) => `HKCU|shared|${f.applicationPath}|${name}`;
  const invoke = (command, args) =>
    page.evaluate(({ command, args }) => window.__TAURI_INTERNALS__.invoke(command, args), {
      command,
      args,
    });
  const backups = async () => {
    const names = new Set(original.fixtures.map((f) => f.executableName));
    const records = [];
    for (const file of await readdir(storage)) {
      if (!/^[a-f0-9-]{36}\.json$/.test(file)) continue;
      const path = resolve(storage, file);
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) continue;
      let record;
      try {
        record = JSON.parse(await readFile(path, 'utf8'));
      } catch {
        continue;
      }
      if (names.has(record.leftover?.executableName)) records.push({ path, record });
    }
    return records;
  };
  const preserved = (state, removeUrls = false, removeFirstPath = false, single = false) => {
    expect(state.environmentPreserved).toBe(true);
    const expected = structuredClone(original.current);
    for (const node of expected.paths) {
      const f = original.fixtures.find((f) => f.applicationPath === node.path);
      node.snapshot.values = node.snapshot.values.filter(
        (v) =>
          !(
            (removeUrls && f.bulk && ['SupportedProtocols', 'uSeUrL'].includes(v.name)) ||
            (removeFirstPath && f.kind === 'Bulk00' && v.name === 'pAth') ||
            (single && f.kind === 'Bulk00' && v.name === 'SupportedProtocols')
          ),
      );
    }
    expect(state.current).toEqual(expected);
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const groups = async (search) => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Application leftovers', exact: true })
      .click();
    await page.getByRole('textbox', { name: 'Search application leftovers' }).fill(search);
  };
  const blocked = async (plan, reason) => {
    const result = await page.evaluate(
      async ({ token, reason }) => {
        try {
          await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
          return { blocked: false };
        } catch (error) {
          return { blocked: new RegExp(reason, 'i').test(String(error)), error: String(error) };
        }
      },
      { token: plan.token, reason },
    );
    summary.urlLeftoversLastBlockedOutcome = result;
    expect(result.blocked).toBe(true);
  };
  const restoreNative = async (ids) => {
    const count = await page.evaluate(async (ids) => {
      for (const backupId of ids) {
        const plan = await window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId });
        await window.__TAURI_INTERNALS__.invoke('apply_change', {
          token: plan.token,
          confirmed: true,
        });
      }
      return ids.length;
    }, ids);
    expect(count).toBe(ids.length);
  };
  const restoreUi = async (backupId) => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await page.getByRole('textbox', { name: 'Search backups', exact: true }).fill(backupId);
    const row = page
      .locator('.backup-item')
      .filter({ has: page.getByText(backupId, { exact: true }) });
    await row.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText('Recovery order');
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore URL metadata', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.urlLeftoversFixtureToken = token;
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
    storage = await page.locator('.backup-location .mono').innerText();
    expect(await backups()).toHaveLength(0);
    await scan();
    for (const control of original.fixtures.filter((f) => !f.bulk)) {
      for (const name of ['SupportedProtocols', 'uSeUrL']) {
        const outcome = await page.evaluate(
          async (entryId) => {
            try {
              await window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId });
              return true;
            } catch {
              return false;
            }
          },
          entryId(control, name),
        );
        expect(outcome).toBe(false);
      }
    }
    preserved(await fixture('inspect'));
    summary.urlLeftoversControlsProtected = true;
    checked(
      'URL metadata inventory protects present installations, remaining executable mappings, MSI, duplicate/name-only owners, alternate activation, other application registrations and malformed types',
    );

    await groups(original.search);
    await expect(page.locator('.leftover-group')).toHaveCount(50);
    await page.getByRole('button', { name: 'Next leftover groups', exact: true }).click();
    await expect(page.locator('.leftover-group')).toHaveCount(2);
    await expect(page.getByText(/Showing 51–52 of 52 matching groups/)).toBeVisible();
    await page.screenshot({
      path: resolve(output, 'desktop-url-leftovers-page2.png'),
      fullPage: true,
    });
    await groups(one().displayName);
    await expect(page.locator('.leftover-group')).toHaveCount(1);
    const card = page.locator('.leftover-group');
    await card
      .getByRole('button', {
        name: `Review Application leftovers action for ${one().displayName} (uSeUrL)`,
        exact: true,
      })
      .click();
    await expect(
      page.getByRole('heading', { name: 'Remove leftover URL metadata?', exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('dialog')).toContainText('uSeUrL · REG_DWORD');
    await expect(
      page.getByRole('button', { name: 'Back up & remove URL metadata', exact: true }),
    ).toBeDisabled();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    await card
      .getByRole('button', { name: `Review cleanup for ${one().displayName}`, exact: true })
      .click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(3);
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    summary.urlLeftoversPaginationAndReviewVerified = true;
    checked(
      'All 52 leftover groups remain accessible through pages and search; distinct string/DWORD actions and group review require confirmation, and cancellation preserves all bytes',
    );

    const conflicts = [
      ['directory', 'missing'],
      ['owner', 'ownership|ambiguous'],
      ['path', 'search path'],
      ['sibling', 'URL metadata changed'],
    ];
    for (const [kind, reason] of conflicts) {
      let active = false;
      try {
        const plan = await invoke('prepare_quarantine', {
          entryId: entryId(one(), 'SupportedProtocols'),
        });
        await fixture(`conflict-${kind}-create`);
        active = true;
        await blocked(plan, reason);
        expect(await backups()).toHaveLength(0);
      } finally {
        if (active) await fixture(`conflict-${kind}-remove`);
      }
      preserved(await fixture('inspect'));
    }
    summary.urlLeftoversApplyConflictsBlocked = true;
    checked(
      'Actual post-review reinstall, duplicate ownership, preserved search-path and sibling DWORD changes block URL metadata cleanup before backup or mutation',
    );

    await card.getByRole('button', { name: 'Review URL metadata cleanup', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText('https:ftp:rr-custom');
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.screenshot({
      path: resolve(output, 'desktop-url-leftovers-review.png'),
      fullPage: true,
    });
    await page.getByRole('button', { name: 'Back up & remove URL metadata', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    preserved(await fixture('inspect'), false, false, true);
    const single = (await backups())[0];
    expect(await backups()).toHaveLength(1);
    expect(single.record.schemaVersion).toBe(26);
    expect(single.record.valueName).toBe('SupportedProtocols');
    expect(single.record.integritySha256).toMatch(/^[a-f0-9]{64}$/);
    checked(
      'Individual schema-26 cleanup removes only the selected URL scheme list while preserving UseUrl, the original search path, settings/license bytes, keys, uninstall metadata and permissions',
    );

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    const immutable = await readFile(single.path);
    for (const [kind, reason] of conflicts) {
      let active = false;
      try {
        const plan = await invoke('prepare_restore', { backupId: single.record.id });
        await fixture(`conflict-${kind}-create`);
        active = true;
        await blocked(plan, reason);
        expect(await readFile(single.path)).toEqual(immutable);
      } finally {
        if (active) await fixture(`conflict-${kind}-remove`);
      }
      preserved(await fixture('inspect'), false, false, true);
    }
    summary.urlLeftoversRestoreConflictsBlocked = true;
    checked(
      'URL metadata recovery after reload blocks four actual post-review conflicts without changing current values or immutable backup bytes',
    );
    await restoreUi(single.record.id);
    preserved(await fixture('inspect'));
    checked(
      'UI recovery restores exact original URL scheme name, REG_SZ type and UTF-16 terminators after reload while preserving every unrelated value',
    );

    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Full Clean', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Review Full Clean', exact: true })).toBeVisible(
      { timeout: 30000 },
    );
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    const included = await page.evaluate(
      async (names) => {
        const plan = await window.__TAURI_INTERNALS__.invoke('prepare_clean', {
          mode: 'full',
          entryIds: [],
          category: null,
        });
        const owned = plan.items.filter(
          (i) =>
            names.some((name) => i.registryPath.endsWith('\\' + name)) &&
            ['SupportedProtocols', 'uSeUrL'].includes(i.valueName),
        );
        await window.__TAURI_INTERNALS__.invoke('cancel_change');
        return {
          count: owned.length,
          types: [...new Set(owned.map((i) => i.valueType))],
          history: plan.items.some((i) => ['run_history', 'typed_paths'].includes(i.scope)),
        };
      },
      original.fixtures.filter((f) => f.bulk).map((f) => f.executableName),
    );
    expect(included.count).toBe(104);
    expect(included.types.sort()).toEqual(['REG_DWORD', 'REG_SZ']);
    expect(included.history).toBe(false);
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(1);
    summary.urlLeftoversFullCleanReviewVerified = true;
    checked(
      'Full Clean includes all 104 supported URL metadata values across the 52 owned apps and excludes personal history; live Full Clean review is cancelled without applying real-user changes',
    );

    await page
      .getByRole('combobox', { name: 'Cleaning category' })
      .selectOption('application_leftovers');
    await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(original.search);
    await expect(page.locator('.clean-candidate')).toHaveCount(50);
    await page.getByRole('button', { name: 'Select matching (up to 10,000)', exact: true }).click();
    await page.getByRole('button', { name: 'Review selected (104)', exact: true }).click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(50, {
      timeout: 30000,
    });
    const previous = new Set((await backups()).map((b) => b.record.id));
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & clean 104 entries', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 180000 });
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    const bulk = (await backups()).filter((b) => !previous.has(b.record.id));
    expect(bulk).toHaveLength(104);
    for (const b of bulk) {
      expect(b.record.schemaVersion).toBe(26);
      expect(b.record.integritySha256).toMatch(/^[a-f0-9]{64}$/);
    }
    preserved(await fixture('inspect'), true);
    summary.urlLeftoversCompleted104 = true;
    checked(
      'Selected cleaning applies all 104 actual string/DWORD URL metadata values in one reviewed batch, with independent schema-26 backups and exact preservation of all search paths, controls, licenses and permissions',
    );

    const pathPlan = await invoke('prepare_quarantine', { entryId: entryId(one(), 'pAth') });
    const pathCleaned = await invoke('apply_change', { token: pathPlan.token, confirmed: true });
    preserved(await fixture('inspect'), true, true);
    const first = bulk.find((b) => b.record.leftover.executableName === one().executableName);
    const early = await page.evaluate(async (backupId) => {
      try {
        await window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId });
        return '';
      } catch (error) {
        return String(error);
      }
    }, first.record.id);
    expect(early).toMatch(/search path/);
    await restoreNative([pathCleaned.backupId]);
    preserved(await fixture('inspect'), true);
    summary.urlLeftoversStagedRecoveryVerified = true;
    checked(
      'A fresh scan exposes staged search-path cleanup after URL metadata removal; recovery blocks out-of-order URL restoration and restores the newer schema-23 path backup first',
    );

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await restoreUi(first.record.id);
    await restoreNative(
      bulk
        .filter((b) => b.record.id !== first.record.id)
        .reverse()
        .map((b) => b.record.id),
    );
    preserved(await fixture('inspect'));
    summary.urlLeftoversExactRecoveryVerified = true;
    checked(
      'All 104 URL metadata backups survive reload and restore exact original names, types and bytes in either sibling order; one UI recovery and remaining native recoveries preserve every retained value and permission',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (attempted)
      try {
        const after = await fixture('cleanup');
        expect(after.environmentPreserved).toBe(true);
        expect(after.current.paths.every((f) => f.snapshot === null)).toBe(true);
      } catch (error) {
        cleanup.push(String(error));
      }
    if (storage && original)
      try {
        for (const b of await backups()) await unlink(b.path);
      } catch (error) {
        cleanup.push(String(error));
      }
    summary.urlLeftoversFixtureCleanup = cleanup.length === 0;
    summary.errors.push(...cleanup);
  }
  if (failure) throw failure;
  if (cleanup.length) throw new Error(cleanup.join('; '));
  checked(
    'Owned URL metadata/installation controls, inert files and matching test backups are conditionally removed while all pre-existing registrations, permissions and backups remain preserved',
  );
}
