import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifyLeftoverCompanions(page, output, checked, summary) {
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
        resolve(import.meta.dirname, 'leftover-types-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
        ...(action === 'create' ? ['-Companion'] : []),
      ],
      { windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const one = () => original.fixtures.find((f) => f.kind === 'One');
  const entryId = (f, extension) => `HKCU|shared|${f.applicationPath}\\SupportedTypes|${extension}`;
  const invoke = (command, args) =>
    page.evaluate(({ command, args }) => window.__TAURI_INTERNALS__.invoke(command, args), {
      command,
      args,
    });
  const backups = async () => {
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
      if (
        record.leftover?.executableName === one().executableName ||
        record.appPath?.executable === one().executableName ||
        record.uninstall?.keyName === one().anchorKey ||
        record.maintenance?.item === one().executable
      )
        records.push({ path, record });
    }
    return records;
  };
  const preserved = (state, removed = [], mapping = true, hidden = false, cache = true) => {
    expect(state.environmentPreserved).toBe(true);
    const expected = structuredClone(original.current);
    const hints = expected.applications
      .find((f) => f.kind === 'One')
      .nodes.find((n) => n.path === 'SupportedTypes');
    hints.snapshot.values = hints.snapshot.values.filter((v) => !removed.includes(v.name));
    if (!mapping)
      expected.companion.values = expected.companion.values.filter((v) => v.name !== '');
    if (hidden) {
      const anchor = expected.uninstall.find((f) => f.path.endsWith('\\' + one().anchorKey));
      anchor.snapshot.values.push({ name: 'SystemComponent', type: 4, data: 'AQAAAA==' });
      anchor.snapshot.values.sort((a, b) =>
        a.name.toLowerCase().localeCompare(b.name.toLowerCase()),
      );
    }
    if (!cache) expected.cache = [];
    expect(state.current).toEqual(expected);
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const groups = async () => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Application leftovers', exact: true })
      .click();
    await page
      .getByRole('textbox', { name: 'Search application leftovers' })
      .fill(one().displayName);
  };
  const card = () =>
    page
      .locator('.leftover-group')
      .filter({ has: page.getByRole('heading', { name: one().displayName, exact: true }) });
  const blocked = async (plan) => {
    const result = await page.evaluate(async (token) => {
      try {
        await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
        return { blocked: false };
      } catch (error) {
        return {
          blocked: /App Paths|activation|metadata/i.test(String(error)),
          error: String(error),
        };
      }
    }, plan.token);
    summary.companionLastBlockedOutcome = result;
    expect(result.blocked).toBe(true);
  };
  const restoreNative = async (ids) => {
    const count = await page.evaluate(async (ids) => {
      for (const backupId of ids) {
        const p = await window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId });
        await window.__TAURI_INTERNALS__.invoke('apply_change', {
          token: p.token,
          confirmed: true,
        });
      }
      return ids.length;
    }, ids);
    expect(count).toBe(ids.length);
  };
  const restoreUi = async (id) => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await page.getByRole('textbox', { name: 'Search backups', exact: true }).fill(id);
    const row = page.locator('.backup-item').filter({ has: page.getByText(id, { exact: true }) });
    await row.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(page.getByRole('dialog')).toContainText('Corroborating App Paths registration');
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore file-type suggestion', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.companionFixtureToken = token;
    expect(original.companion).toBe(true);
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
    storage = await page.locator('.backup-location .mono').innerText();
    expect(await backups()).toHaveLength(0);
    await scan();
    for (const control of original.fixtures.filter((f) => f.kind !== 'One')) {
      for (const extension of control.extensions.slice(0, 2)) {
        const allowed = await page.evaluate(
          async (entryId) => {
            try {
              await window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId });
              return true;
            } catch {
              return false;
            }
          },
          entryId(control, extension),
        );
        expect(allowed).toBe(false);
      }
    }
    preserved(await fixture('inspect'));
    summary.companionControlsProtected = true;
    checked(
      'Matching-registration inventory retains present installations, MSI/duplicate/name-only owners, delegated activation, conflicting App Paths targets and nonempty hints as protected controls',
    );

    await groups();
    await expect(card()).toHaveCount(1);
    await expect(card().getByRole('checkbox')).toHaveCount(5);
    await expect(card()).toContainText('Corroborating App Paths registration');
    await card()
      .getByRole('button', {
        name: `Review Application leftovers action for ${one().displayName} (${one().extensions[0]})`,
        exact: true,
      })
      .click();
    await expect(page.getByRole('dialog')).toContainText('Corroborating executable mapping');
    await expect(
      page.getByRole('button', { name: 'Back up & remove suggestion', exact: true }),
    ).toBeDisabled();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    await card()
      .getByRole('button', { name: `Review cleanup for ${one().displayName}`, exact: true })
      .click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(5);
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    summary.companionGroupingAndReviewVerified = true;
    checked(
      'One exact-identity group unifies both registration roots and all five separate hint/mapping/uninstall/cache actions; reviews show counterpart evidence, require confirmation and cancel without changes',
    );

    const conflicts = ['mapping', 'path', 'metadata', 'activation'];
    for (const kind of conflicts) {
      let active = false;
      try {
        const plan = await invoke('prepare_quarantine', {
          entryId: entryId(one(), one().extensions[0]),
        });
        await fixture(`conflict-companion-${kind}-create`);
        active = true;
        await blocked(plan);
        expect(await backups()).toHaveLength(0);
      } finally {
        if (active) await fixture(`conflict-companion-${kind}-remove`);
      }
      preserved(await fixture('inspect'));
    }
    summary.companionApplyConflictsBlocked = true;
    checked(
      'Four actual post-review App Paths mapping, search-path, custom-metadata and alternate-activation changes block suggestion cleanup before backup or mutation',
    );

    await card().getByRole('button', { name: 'Review file-type cleanup', exact: true }).click();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.screenshot({
      path: resolve(output, 'desktop-companion-review.png'),
      fullPage: true,
    });
    await page.getByRole('button', { name: 'Back up & remove suggestion', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    preserved(await fixture('inspect'), [one().extensions[0]]);
    const single = (await backups())[0];
    expect(await backups()).toHaveLength(1);
    expect(single.record.schemaVersion).toBe(27);
    expect(single.record.leftover.supportedType.appPaths.values).toHaveLength(4);
    expect(single.record.original).toEqual({ kind: 1, bytes: [0, 0] });
    checked(
      'Individual schema-27 cleanup removes only one exact empty hint while preserving its sibling, both registration roots, executable mapping, paths, commands, license data, files and permissions',
    );

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    const immutable = await readFile(single.path);
    for (const kind of conflicts) {
      let active = false;
      try {
        const plan = await invoke('prepare_restore', { backupId: single.record.id });
        await fixture(`conflict-companion-${kind}-create`);
        active = true;
        await blocked(plan);
        expect(await readFile(single.path)).toEqual(immutable);
      } finally {
        if (active) await fixture(`conflict-companion-${kind}-remove`);
      }
      preserved(await fixture('inspect'), [one().extensions[0]]);
    }
    summary.companionRestoreConflictsBlocked = true;
    checked(
      'Schema-27 recovery after reload rejects four actual counterpart changes without replacing new data, recreating keys or changing immutable backup bytes',
    );
    await restoreUi(single.record.id);
    preserved(await fixture('inspect'));
    checked(
      'UI recovery restores exact original suggestion name, REG_SZ type and UTF-16 bytes while retaining the corroborating App Paths record exactly',
    );

    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Full Clean', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Review Full Clean', exact: true })).toBeVisible(
      { timeout: 30000 },
    );
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    const included = await page.evaluate(
      async ({ path, application }) => {
        const plan = await window.__TAURI_INTERNALS__.invoke('prepare_clean', {
          mode: 'full',
          entryIds: [],
          category: null,
        });
        const hints = plan.items.filter(
          (i) =>
            i.registryPath === 'HKCU\\' + application + '\\SupportedTypes' &&
            i.supportingEvidence.some(
              ([label]) => label === 'Corroborating App Paths registration',
            ),
        );
        const mapping = plan.items.filter(
          (i) => i.registryPath === 'HKCU\\' + path && i.valueName === '',
        );
        await window.__TAURI_INTERNALS__.invoke('cancel_change');
        return { hints: hints.length, mappings: mapping.length };
      },
      { path: original.companionPath, application: one().applicationPath },
    );
    expect(included).toEqual({ hints: 2, mappings: 1 });
    preserved(await fixture('inspect'));
    summary.companionFullCleanReviewVerified = true;
    checked(
      'Full Clean reviews both new corroborated hints and the separately supported executable mapping; live Full Clean is cancelled without applying real-user changes',
    );

    await groups();
    const previous = new Set((await backups()).map((b) => b.record.id));
    await card()
      .getByRole('button', { name: `Review cleanup for ${one().displayName}`, exact: true })
      .click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(5);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & clean 5 entries', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0, { timeout: 30000 });
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    const mixed = (await backups()).filter((b) => !previous.has(b.record.id));
    expect(mixed.map((b) => b.record.schemaVersion).sort((a, b) => a - b)).toEqual([
      2, 3, 20, 27, 27,
    ]);
    preserved(await fixture('inspect'), one().extensions.slice(0, 2), false, true, false);
    summary.companionMixedCleanupVerified = true;
    checked(
      'Selected group cleaning completes all five reviewed actions with independent schema-2/3/20/27/27 backups, including a captured executable mapping becoming absent between hint operations',
    );

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    const hints = mixed.filter((b) => b.record.schemaVersion === 27);
    await restoreUi(hints[0].record.id);
    preserved(await fixture('inspect'), [hints[1].record.valueName], false, true, false);
    await restoreNative([mixed.find((b) => b.record.schemaVersion === 2).record.id]);
    await restoreNative([
      hints[1].record.id,
      ...mixed.filter((b) => [3, 20].includes(b.record.schemaVersion)).map((b) => b.record.id),
    ]);
    preserved(await fixture('inspect'));
    summary.companionIndependentRecoveryVerified = true;
    checked(
      'Mixed backups survive reload: one hint restores while the executable mapping stays absent, the mapping then restores independently, and all remaining hints/uninstall/cache data recover exact bytes and permissions',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (attempted)
      try {
        const state = await fixture('cleanup');
        expect(state.environmentPreserved).toBe(true);
        expect(state.current.companion).toBeNull();
        expect(state.current.applications.every((f) => !f.nodes.length)).toBe(true);
      } catch (error) {
        cleanup.push(String(error));
      }
    if (storage && original)
      try {
        for (const b of await backups()) await unlink(b.path);
      } catch (error) {
        cleanup.push(String(error));
      }
    summary.companionFixtureCleanup = cleanup.length === 0;
    summary.errors.push(...cleanup);
  }
  if (failure) throw failure;
  if (cleanup.length) throw new Error(cleanup.join('; '));
  checked(
    'Owned companion/application/uninstall controls, inert files, cache data and matching test backups are conditionally removed while all pre-existing user data and permissions remain preserved',
  );
}
