import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);
export async function verifyLeftoverTypes(page, output, checked, summary) {
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
      ],
      { windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const one = () => original.fixtures.find((f) => f.kind === 'One');
  const entryId = (f, extension) => `HKCU|shared|${f.applicationPath}\\SupportedTypes|${extension}`;
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
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const preserved = (state, removed = [], hidden = false, cache = false) => {
    expect(state.environmentPreserved).toBe(true);
    const expected = structuredClone(original.current);
    const node = expected.applications
      .find((f) => f.kind === 'One')
      .nodes.find((n) => n.path === 'SupportedTypes');
    node.snapshot.values = node.snapshot.values.filter((v) => !removed.includes(v.name));
    if (hidden) {
      const anchor = expected.uninstall.find((f) => f.path.endsWith(`\\${one().anchorKey}`));
      anchor.snapshot.values.push({ name: 'SystemComponent', type: 4, data: 'AQAAAA==' });
      anchor.snapshot.values.sort((a, b) =>
        a.name.toLowerCase().localeCompare(b.name.toLowerCase()),
      );
    }
    if (cache) expected.cache = [];
    expect(state.current).toEqual(expected);
  };
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
        record.uninstall?.keyName === one().anchorKey ||
        record.maintenance?.item === one().executable
      )
        records.push({ record, path });
    }
    return records;
  };
  const prepare = async (id) =>
    page.evaluate(
      (entryId) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId }),
      id,
    );
  const blocked = async (p) => {
    const result = await page.evaluate(async (token) => {
      try {
        await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
        return { blocked: false, error: null };
      } catch (error) {
        return { blocked: true, error: String(error) };
      }
    }, p.token);
    summary.leftoverTypesLastBlockedOutcome = result;
    expect(result.blocked).toBe(true);
  };
  const restore = async (b) => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await page.getByRole('textbox', { name: 'Search backups', exact: true }).fill(b.record.id);
    const row = page
      .locator('.backup-item')
      .filter({ has: page.getByText(b.record.id, { exact: true }) });
    await row.getByRole('button', { name: 'Review restore', exact: true }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByRole('checkbox').check();
    await dialog.getByRole('button', { name: /^Restore / }).click();
    await expect(dialog).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.leftoverTypesFixtureToken = token;
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
    storage = await page.locator('.backup-location .mono').innerText();
    await scan();
    await groups();
    await expect(card()).toHaveCount(1);
    await expect(card().getByRole('checkbox')).toHaveCount(4);
    for (const control of original.fixtures.filter((f) => f.kind !== 'One')) {
      for (const extension of control.extensions.slice(0, 2)) {
        const result = await page.evaluate(
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
        expect(result).toBe(false);
      }
    }
    expect(
      await page.evaluate(
        async (entryId) => {
          try {
            await window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId });
            return true;
          } catch {
            return false;
          }
        },
        entryId(one(), one().extensions[2]),
      ),
    ).toBe(false);
    summary.leftoverTypesControlsProtected = true;
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    checked(
      'SupportedTypes inventory groups sibling hints once; found, MSI, shared/expanded-owner, name-only, delegated, App Paths-counterpart and nonempty-value controls remain protected',
    );
    await card()
      .getByRole('button', {
        name: `Review Application leftovers action for ${one().displayName} (${one().extensions[0]})`,
        exact: true,
      })
      .click();
    await expect(
      page.getByRole('heading', { name: 'Remove leftover file-type suggestion?', exact: true }),
    ).toBeVisible();
    const apply = page.getByRole('button', { name: 'Back up & remove suggestion', exact: true });
    await expect(apply).toBeDisabled();
    await expect(page.getByRole('dialog')).toContainText(one().command);
    await expect(page.getByRole('dialog')).toContainText(one().extensions[0]);
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    for (const box of await card().getByRole('checkbox').all()) await box.uncheck();
    await card()
      .getByRole('checkbox', {
        name: `Select Application leftovers cleanup for ${one().displayName} (${one().extensions[1]})`,
        exact: true,
      })
      .check();
    await card()
      .getByRole('button', { name: `Review cleanup for ${one().displayName}`, exact: true })
      .click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(1);
    await expect(page.getByRole('dialog')).toContainText(one().extensions[1]);
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    for (const box of await card().getByRole('checkbox').all()) await box.check();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    summary.leftoverTypesSelectionVerified = true;
    checked(
      'File-type actions are individually identified, require confirmation, allow selecting one sibling, and cancellation preserves all bytes and creates no backup',
    );
    const quick = await page.evaluate(() =>
      window.__TAURI_INTERNALS__.invoke('prepare_clean', {
        mode: 'quick',
        entryIds: [],
        category: 'application_leftovers',
      }),
    );
    expect(
      quick.items.some((item) =>
        item.registryPath.endsWith(`\\${one().executableName}\\SupportedTypes`),
      ),
    ).toBe(true);
    await page.evaluate(() => window.__TAURI_INTERNALS__.invoke('cancel_change'));
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    checked(
      'Category-scoped Quick Clean includes the supported hints and its cancelled review leaves current registrations, default selections and backup storage unchanged',
    );
    const conflicts = [
      'directory',
      'metadata',
      'anchor',
      'duplicate',
      'command',
      'value',
      'app-path',
    ];
    summary.leftoverTypesConflictStages = [];
    const traceConflict = async (phase) => {
      const state = await fixture('inspect');
      const hints = state.current.applications
        .find((f) => f.kind === 'One')
        .nodes.find((n) => n.path === 'SupportedTypes').snapshot.values;
      const anchor = state.current.uninstall.find((f) => f.path.endsWith(`\\${one().anchorKey}`));
      const stage = {
        phase,
        hints: hints.length,
        cache: state.current.cache.length,
        hidden: anchor.snapshot.values.some((v) => v.name === 'SystemComponent'),
      };
      summary.leftoverTypesConflictStages.push(stage);
      console.log('CONFLICT', JSON.stringify(stage));
    };
    for (const kind of conflicts) {
      let active = false;
      try {
        const p = await prepare(entryId(one(), one().extensions[0]));
        await traceConflict(`${kind}:prepared`);
        await fixture(`conflict-${kind}-create`);
        active = true;
        await blocked(p);
        await traceConflict(`${kind}:blocked`);
        expect(await backups()).toHaveLength(0);
      } finally {
        if (active) await fixture(`conflict-${kind}-remove`);
      }
      await traceConflict(`${kind}:removed`);
      preserved(await fixture('inspect'));
    }
    summary.leftoverTypesApplyConflictsBlocked = true;
    checked(
      'Actual post-review reinstall, application/anchor metadata, duplicate ownership, command, value and App Paths conflicts block hint removal before backup or mutation',
    );
    await groups();
    await card().getByRole('button', { name: 'Review file-type cleanup', exact: true }).click();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.screenshot({
      path: resolve(output, 'desktop-leftover-types-review.png'),
      fullPage: true,
    });
    await page.getByRole('button', { name: 'Back up & remove suggestion', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    preserved(await fixture('inspect'), [one().extensions[0]]);
    const single = (await backups())[0];
    expect((await backups()).length).toBe(1);
    expect(single.record.schemaVersion).toBe(25);
    expect(single.record.valueName).toBe(one().extensions[0]);
    expect(single.record.original).toEqual({ kind: 1, bytes: [0, 0] });
    checked(
      'Individual schema-25 cleanup removes only one exact empty REG_SZ hint while preserving sibling data, open command, icon, licenses, uninstall metadata, keys and permissions',
    );
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    const bytes = await readFile(single.path);
    for (const kind of conflicts) {
      let active = false;
      try {
        const p = await page.evaluate(
          (backupId) => window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId }),
          single.record.id,
        );
        await fixture(`conflict-${kind}-create`);
        active = true;
        await blocked(p);
        expect(await readFile(single.path)).toEqual(bytes);
      } finally {
        if (active) await fixture(`conflict-${kind}-remove`);
      }
      preserved(await fixture('inspect'), [one().extensions[0]]);
    }
    summary.leftoverTypesRestoreConflictsBlocked = true;
    checked(
      'Restart-safe hint recovery rejects seven actual post-review conflicts without overwriting a new value or changing immutable backup bytes',
    );
    await restore(single);
    preserved(await fixture('inspect'));
    checked(
      'UI restoration returns exact original suggestion name, type and empty bytes after reload without executing commands or changing sibling hints',
    );
    const before = new Set((await backups()).map((b) => b.record.id));
    await scan();
    await groups();
    await card()
      .getByRole('button', { name: `Review cleanup for ${one().displayName}`, exact: true })
      .click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(4);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & clean 4 entries', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    preserved(await fixture('inspect'), one().extensions.slice(0, 2), true, true);
    const mixed = (await backups()).filter((b) => !before.has(b.record.id));
    expect(mixed.map((b) => b.record.schemaVersion).sort((a, b) => a - b)).toEqual([3, 20, 25, 25]);
    checked(
      'Selected group cleaning applies two sibling hints plus supported uninstall/cache actions, each with a separate verified schema-25/25/3/20 backup',
    );
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    for (const b of mixed.sort((a, b) => a.record.schemaVersion - b.record.schemaVersion))
      await restore(b);
    preserved(await fixture('inspect'));
    summary.leftoverTypesIndependentRecoveryVerified = true;
    checked(
      'Mixed hint/uninstall/cache backups survive restart and restore independently with complete original raw values, metadata and permissions preserved',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (attempted)
      try {
        const after = await fixture('cleanup');
        expect(after.environmentPreserved).toBe(true);
        expect(after.current.applications.every((f) => !f.nodes.length)).toBe(true);
      } catch (error) {
        cleanup.push(String(error));
      }
    if (storage && original)
      try {
        for (const b of await backups()) await unlink(b.path);
      } catch (error) {
        cleanup.push(String(error));
      }
    summary.leftoverTypesFixtureCleanup = cleanup.length === 0;
    summary.errors.push(...cleanup);
  }
  if (failure) throw failure;
  if (cleanup.length) throw new Error(cleanup.join('; '));
  checked(
    'Owned application trees, uninstall controls, active-path control, cache fields, inert file and matching test backups are conditionally cleaned without changing existing user data',
  );
}
