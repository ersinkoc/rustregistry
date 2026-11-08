import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifyFileReferenceRecovery(page, output, checked, summary) {
  const token = randomUUID();
  const shell = resolve(
    process.env.SystemRoot || 'C:\\Windows',
    'System32/WindowsPowerShell/v1.0/powershell.exe',
  );
  const fixture = async (action, slot = 'font') => {
    const { stdout } = await run(
      shell,
      [
        '-NoProfile',
        '-NonInteractive',
        '-File',
        resolve(import.meta.dirname, 'file-reference-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
        '-Slot',
        slot,
      ],
      { windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const slots = ['font', 'h64', 'h32', 'w64', 'w32'];
  const paths = {
    font: 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts',
    h64: 'Software\\Microsoft\\Windows\\HTML Help',
    h32: 'Software\\Microsoft\\Windows\\HTML Help',
    w64: 'Software\\Microsoft\\Windows\\Help',
    w32: 'Software\\Microsoft\\Windows\\Help',
  };
  const locations = {
    font: 'user_font',
    h64: 'html_help64',
    h32: 'html_help32',
    w64: 'win_help64',
    w32: 'win_help32',
  };
  let original,
    storagePath,
    failure,
    attempted = false;
  const cleanupErrors = [];
  const info = (slot, kind) => original.fixtures.find((f) => f.slot === slot && f.kind === kind);
  const id = (slot, kind) =>
    `${slot === 'font' ? 'HKCU' : 'HKLM'}|${slot === 'font' ? 'shared' : slot.endsWith('32') ? '32' : '64'}|${paths[slot]}|${info(slot, kind).name}`;
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const results = async (slot) => {
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page
      .getByRole('combobox', { name: 'Filter by category' })
      .selectOption(slot === 'font' ? 'fonts' : 'help_files');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page
      .getByRole('textbox', { name: 'Search entries' })
      .fill(slot === 'font' ? original.search : `${original.search}-${slot}`);
  };
  const preserved = (current, removed = []) => {
    for (const before of original.views) {
      const after = current.views.find((v) => v.slot === before.slot);
      expect(after.exists).toBe(true);
      expect(after.acl).toBe(before.acl);
      for (const child of before.children) expect(after.children).toContain(child);
      expect(after.marker).toEqual(before.marker);
      const values = new Map(after.values.map((v) => [v.name.toLowerCase(), v]));
      const absent = new Set(
        removed.filter((r) => r.slot === before.slot).map((r) => r.name.toLowerCase()),
      );
      for (const value of before.values) {
        if (absent.has(value.name.toLowerCase()))
          expect(values.has(value.name.toLowerCase())).toBe(false);
        else expect(values.get(value.name.toLowerCase())).toEqual(value);
      }
    }
  };
  const backups = async () => {
    expect(storagePath).toMatch(/^[a-z]:\\/i);
    const found = [];
    for (const file of await readdir(storagePath).catch((e) => {
      if (e.code === 'ENOENT') return [];
      throw e;
    })) {
      if (!/^[a-f0-9-]{36}\.json$/.test(file)) continue;
      const path = resolve(storagePath, file);
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) continue;
      let record;
      try {
        record = JSON.parse(await readFile(path, 'utf8'));
      } catch {
        continue;
      }
      if (
        record.schemaVersion === 21 &&
        slots.some((slot) =>
          ['One', 'Two'].some(
            (kind) =>
              record.fileReference?.location === locations[slot] &&
              record.valueName === info(slot, kind).name,
          ),
        )
      )
        found.push({ path, record });
    }
    return found;
  };
  const changed = (entries) => entries.map(([slot, kind]) => info(slot, kind));
  const restore = async (b) => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    const card = page
      .locator('.backup-item')
      .filter({ has: page.getByText(b.record.id, { exact: true }) });
    await card.getByRole('button', { name: 'Review restore', exact: true }).click();
    const font = b.record.fileReference.location === 'user_font';
    await expect(
      page.getByRole('heading', {
        name: font ? 'Restore font reference?' : 'Restore help-file reference?',
        exact: true,
      }),
    ).toBeVisible();
    await expect(page.getByRole('dialog')).toContainText(b.record.fileReference.target);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page
      .getByRole('button', {
        name: font ? 'Restore font mapping' : 'Restore help mapping',
        exact: true,
      })
      .click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const blockedApply = async (plan, match) => {
    const outcome = await page.evaluate(
      async ({ token, match }) => {
        try {
          await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
          return { blocked: false, error: null };
        } catch (e) {
          return { blocked: String(e).includes(match), error: String(e) };
        }
      },
      { token: plan.token, match },
    );
    summary.fileReferenceLastApplyOutcome = outcome;
    return outcome.blocked;
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.fileReferenceFixtureToken = token;
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
    storagePath = await page.locator('.backup-location .mono').innerText();
    await scan();
    for (const slot of slots) {
      await results(slot);
      const controls =
        slot === 'font'
          ? [
              ['One', 'Review'],
              ['Two', 'Review'],
              ['Found', 'Found'],
              ['Relative', 'Unverified'],
              ['Windows', 'Review'],
              ['Collection', 'Review'],
              ['WrongType', 'Unverified'],
              ['Expanded', 'Unverified'],
              ['Counterpart', 'Review'],
            ]
          : [
              ['One', 'Review'],
              ['Two', 'Review'],
              ['Found', 'Found'],
              ['Windows', slot.endsWith('32') ? 'Unverified' : 'Review'],
              ['Expanded', 'Unverified'],
              ['Relative', 'Unverified'],
              ['WrongType', 'Unverified'],
              ['WrongExtension', 'Unverified'],
            ];
      for (const [kind, status] of controls) {
        const button = page.getByRole('button', {
          name: `${info(slot, kind).name} details`,
          exact: true,
        });
        await expect(
          page.locator('tbody tr').filter({ has: button }).locator('.status-badge'),
        ).toHaveText(status);
        await button.click();
        const review = page.getByRole('button', {
          name: slot === 'font' ? 'Review font repair' : 'Review help repair',
          exact: true,
        });
        if (['One', 'Two'].includes(kind)) await expect(review).toBeEnabled();
        else await expect(review).toHaveCount(0);
        await page.keyboard.press('Escape');
      }
    }
    checked(
      'Font inventory separates absolute missing/found, relative, Windows, collection, binary, expanded and matching-machine-name controls while preserving packaged font child data',
    );
    checked(
      'Both architectures of HTML Help and WinHelp distinguish registered-directory targets, Windows/expanded/relative/invalid controls and existing inert documents without loading fonts or opening help',
    );

    for (const slot of slots) {
      const p = await page.evaluate(
        (entryId) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId }),
        id(slot, 'One'),
      );
      expect(p.resolvedFile).toBe(info(slot, 'One').target);
      let added = false;
      try {
        await fixture('conflict-file-create', slot);
        added = true;
        expect(await blockedApply(p, 'not confirmed missing')).toBe(true);
        expect(await backups()).toHaveLength(0);
      } finally {
        if (added) await fixture('conflict-file-remove', slot);
      }
    }
    preserved(await fixture('inspect'));
    summary.fileReferenceApplyConflictBlocked = true;
    checked(
      'Real files appearing after review block font and all four machine help-view apply attempts before backups or registry changes',
    );
    const fontPlan = await page.evaluate(
      (entryId) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId }),
      id('font', 'One'),
    );
    let fontConflict = false;
    try {
      await fixture('conflict-font-create');
      fontConflict = true;
      const fontConflictView = await fixture('inspect');
      summary.fontConflictVisibleToIndependentReader = fontConflictView.views
        .find((v) => v.slot === 'machine_fonts')
        .values.some((v) => v.name === info('font', 'One').name);
      expect(summary.fontConflictVisibleToIndependentReader).toBe(true);
      expect(await blockedApply(fontPlan, 'matching machine font')).toBe(true);
      expect(await backups()).toHaveLength(0);
    } finally {
      if (fontConflict) await fixture('conflict-font-remove');
    }
    preserved(await fixture('inspect'));
    summary.fontCounterpartApplyBlocked = true;
    checked(
      'A real matching machine font name introduced after user-font review blocks apply without overwriting either mapping or creating a backup',
    );

    for (const category of ['fonts', 'help_files']) {
      await page
        .locator('nav')
        .getByRole('button', { name: 'Clean registry', exact: true })
        .click();
      await page.getByRole('combobox', { name: 'Cleaning category' }).selectOption(category);
      await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(original.search);
      await expect(page.locator('.clean-candidate')).toHaveCount(category === 'fonts' ? 2 : 8);
      await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog.locator('.clean-review-items details').first()).toBeVisible();
      for (const slot of category === 'fonts' ? ['font'] : slots.slice(1))
        for (const kind of ['One', 'Two'])
          await expect(dialog).toContainText(info(slot, kind).name);
      for (const item of await dialog.locator('.clean-review-items details').all())
        await expect(item.locator('summary')).toContainText(
          category === 'fonts'
            ? 'Remove supported missing font reference'
            : 'Remove missing help-file registration',
        );
      await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    }
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    checked(
      'Category-scoped Quick Clean and candidate search include only supported font/help mappings; both review cancellations preserve raw values and create no backups',
    );

    for (const slot of slots) {
      const beforeIds = new Set((await backups()).map((b) => b.record.id));
      await results(slot);
      const buttonName = `${info(slot, 'One').name} details`;
      await page.getByRole('button', { name: buttonName, exact: true }).click();
      await page
        .getByRole('button', {
          name: slot === 'font' ? 'Review font repair' : 'Review help repair',
          exact: true,
        })
        .click();
      const applyName =
        slot === 'font' ? 'Back up & remove font reference' : 'Back up & remove help reference';
      const apply = page.getByRole('button', { name: applyName, exact: true });
      await expect(apply).toBeDisabled();
      await expect(page.getByRole('dialog')).toContainText(info(slot, 'One').target);
      await page.getByRole('dialog').getByRole('checkbox').check();
      await expect(apply).toBeEnabled();
      if (['font', 'h64'].includes(slot))
        await page.screenshot({
          path: resolve(output, `desktop-${slot}-reference-review.png`),
          fullPage: true,
        });
      await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
      preserved(await fixture('inspect'));
      expect((await backups()).map((b) => b.record.id).sort()).toEqual([...beforeIds].sort());
      await page.getByRole('button', { name: buttonName, exact: true }).click();
      await page
        .getByRole('button', {
          name: slot === 'font' ? 'Review font repair' : 'Review help repair',
          exact: true,
        })
        .click();
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page.getByRole('button', { name: applyName, exact: true }).click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30000,
      });
      preserved(await fixture('inspect'), changed([[slot, 'One']]));
      const records = (await backups()).filter((b) => !beforeIds.has(b.record.id));
      expect(records).toHaveLength(1);
      const b = records[0];
      expect(b.record.fileReference.location).toBe(locations[slot]);
      expect(b.record.fileReference.name).toBe(info(slot, 'One').name);
      expect(b.record.fileReference.target).toBe(info(slot, 'One').target);
      const prior = original.views
        .find((v) => v.slot === slot)
        .values.find((v) => v.name === b.record.valueName);
      expect(Buffer.from(b.record.original.bytes).toString('base64')).toBe(prior.data);
      checked(
        `${slot}: explicit individual review/cancel and schema-21 removal affect only the selected raw value; files, other views, package metadata, existing registrations and permissions remain exact`,
      );
      await page.reload();
      await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
      const backupBytes = await readFile(b.path);
      let conflict = false;
      try {
        const p = await page.evaluate(
          (backupId) => window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId }),
          b.record.id,
        );
        await fixture('conflict-file-create', slot);
        conflict = true;
        expect(await blockedApply(p, 'not confirmed missing')).toBe(true);
        expect(await readFile(b.path)).toEqual(backupBytes);
        preserved(await fixture('inspect'), changed([[slot, 'One']]));
      } finally {
        if (conflict) await fixture('conflict-file-remove', slot);
      }
      if (slot === 'font') {
        let added = false;
        try {
          const p = await page.evaluate(
            (backupId) => window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId }),
            b.record.id,
          );
          await fixture('conflict-font-create');
          added = true;
          expect(await blockedApply(p, 'matching machine font')).toBe(true);
          expect(await readFile(b.path)).toEqual(backupBytes);
          preserved(await fixture('inspect'), changed([[slot, 'One']]));
        } finally {
          if (added) await fixture('conflict-font-remove');
        }
        summary.fontCounterpartRestoreBlocked = true;
      }
      await restore(b);
      preserved(await fixture('inspect'));
      checked(
        `${slot}: backup survives reload, real post-review file conflicts block restore, and UI restoration returns exact original type/bytes without overwriting other values or permissions`,
      );
    }
    summary.fileReferenceRestoreConflictBlocked = true;
    const beforeIds = new Set((await backups()).map((b) => b.record.id));
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('combobox', { name: 'Cleaning category' }).selectOption('all');
    await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(original.search);
    await expect(page.locator('.clean-candidate')).toHaveCount(10);
    for (const slot of slots)
      for (const kind of ['One', 'Two'])
        await page
          .getByRole('checkbox', { name: `Select ${info(slot, kind).name}`, exact: true })
          .check();
    await page.getByRole('button', { name: 'Review selected (10)', exact: true }).click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(10);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & clean 10 entries', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    preserved(
      await fixture('inspect'),
      changed(
        slots.flatMap((slot) => [
          [slot, 'One'],
          [slot, 'Two'],
        ]),
      ),
    );
    const records = (await backups()).filter((b) => !beforeIds.has(b.record.id));
    expect(records).toHaveLength(10);
    checked(
      'Selected Clean removes ten explicitly chosen font/help values across all five repair locations, with separate verified backups and all other values, files, children and permissions preserved',
    );
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    for (const b of records) await restore(b);
    preserved(await fixture('inspect'));
    checked(
      'All ten selected backups survive reload and restore exact original raw bytes in the correct shared/user or machine architecture location without loading a font or help document',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        const after = await fixture('cleanup');
        if (original)
          for (const before of original.baseline) {
            const current = after.views.find((v) => v.slot === before.slot);
            if (before.exists) {
              expect(current.exists).toBe(true);
              expect(current.acl).toBe(before.acl);
              for (const value of before.values)
                expect(current.values.find((v) => v.name === value.name)).toEqual(value);
              for (const child of before.children) expect(current.children).toContain(child);
            }
            for (const f of original.fixtures.filter((f) => f.slot === before.slot))
              expect(current.values.some((v) => v.name === f.name)).toBe(false);
          }
      } catch (e) {
        cleanupErrors.push(String(e));
      }
    }
    if (storagePath && original) {
      try {
        for (const b of await backups()) await unlink(b.path);
      } catch (e) {
        cleanupErrors.push(String(e));
      }
    }
    summary.fileReferenceFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned font/help fixture cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned font/help values, package marker, inert documents, matching backups and empty setup-created roots are cleaned while all pre-existing roots and data remain preserved',
  );
}
