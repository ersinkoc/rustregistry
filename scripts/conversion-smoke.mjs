import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifyConversionRecovery(page, output, checked, summary) {
  const token = randomUUID();
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
        resolve(import.meta.dirname, 'conversion-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
      ],
      { windowsHide: true, timeout: 20000, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  let original,
    attempted = false,
    failure;
  const cleanupErrors = [];
  const info = (kind) => original.fixtures.find((f) => f.kind === kind);
  const results = async () => {
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page
      .getByRole('combobox', { name: 'Filter by category' })
      .selectOption('com_conversions');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(original.search);
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
      const stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 262144) continue;
      let record;
      try {
        record = JSON.parse(await readFile(path, 'utf8'));
      } catch {
        continue;
      }
      if (
        record.schemaVersion === 19 &&
        original?.fixtures.some(
          (f) => ['One', 'Two'].includes(f.kind) && record.conversion?.owner === f.owner,
        )
      )
        matches.push({ path, record });
    }
    return matches;
  };
  const removed = (targets) => ({
    ...original,
    views: original.views.map((view) => ({
      ...view,
      classes: view.classes.map((program) =>
        view.view === 'Registry64' && targets.includes(program.kind)
          ? {
              ...program,
              nodes: program.nodes.map((node) =>
                node.path === 'AutoConvertTo'
                  ? { ...node, values: node.values.filter((v) => v.name !== '') }
                  : node,
              ),
            }
          : program,
      ),
    })),
  });
  const restore = async (kind) => {
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    const backup = page
      .locator('.backup-item')
      .filter({ has: page.getByRole('heading', { name: info(kind).name, exact: true }) })
      .first();
    await expect(backup).toContainText('COM conversion reference');
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Restore COM conversion reference?', exact: true }),
    ).toBeVisible();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore conversion reference', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.conversionFixtureToken = token;
    await scan();
    await results();
    await expect(page.locator('tbody tr')).toHaveCount(12);
    for (const [kind, status] of [
      ['One', 'Review'],
      ['Two', 'Review'],
      ['Found32', 'Found'],
      ['Found64', 'Found'],
      ['ReadOnly32', 'Review'],
      ['Machine', 'Found'],
      ['Complex', 'Review'],
      ['Malformed', 'Unverified'],
      ['Empty', 'Unverified'],
      ['WrongType', 'Unverified'],
      ['Self', 'Unverified'],
      ['Counterpart', 'Review'],
    ]) {
      const row = page.locator('tbody tr').filter({
        has: page.getByRole('button', { name: `${info(kind).name} details`, exact: true }),
      });
      await expect(row.locator('.status-badge')).toHaveText(status);
      await row.locator('.entry-button').click();
      if (['One', 'Two'].includes(kind))
        await expect(
          page.getByRole('button', { name: 'Review repair', exact: true }),
        ).toBeEnabled();
      else
        await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(
          0,
        );
      if (kind === 'Complex') await expect(page.getByRole('dialog')).toContainText('TreatAs');
      if (kind === 'Counterpart')
        await expect(page.getByRole('dialog')).toContainText('counterpart');
      if (kind === 'WrongType') await expect(page.getByRole('dialog')).toContainText('REG_SZ');
      await page.keyboard.press('Escape');
    }
    checked(
      'AutoConvertTo inventory checks real 32-bit-only, 64-bit-only and read-only machine class targets, complex/malformed references and 32-bit class counterparts; only guarded native user missing-target references offer repair',
    );

    const entryId = `HKCU|64|Software\\Classes\\CLSID\\${info('One').owner}\\AutoConvertTo|`;
    const plan = await page.evaluate(
      (id) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId: id }),
      entryId,
    );
    expect(plan.scope).toBe('com_conversion');
    let conflict = false;
    try {
      conflict = true;
      await fixture('conflict-create');
      const blocked = await page.evaluate(async (token) => {
        try {
          await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
          return false;
        } catch (error) {
          return String(error).includes('target CLSID exists');
        }
      }, plan.token);
      expect(blocked).toBe(true);
      expect(await backups()).toHaveLength(0);
    } finally {
      if (conflict) await fixture('conflict-remove');
    }
    expect(await fixture('inspect')).toEqual(original);
    summary.conversion32BitConflictBlocked = true;
    checked(
      'A real 32-bit conversion CLSID appearing after review blocks native apply before any backup or mapping change; removing only the owned class control restores the exact baseline',
    );

    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    for (const kind of ['One', 'Two'])
      await expect(page.getByRole('dialog')).toContainText(info(kind).name);
    for (const kind of [
      'Found32',
      'Found64',
      'ReadOnly32',
      'Machine',
      'Complex',
      'Malformed',
      'Empty',
      'WrongType',
      'Self',
      'Counterpart',
    ])
      await expect(page.getByRole('dialog')).not.toContainText(info(kind).name);
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    expect(await backups()).toHaveLength(0);
    checked(
      'Quick Clean includes only guarded missing-local-target conversion references; cancellation preserves all raw mappings, descriptions, class controls, unrelated names, and permissions without backups',
    );
    for (const mode of ['single', 'selected']) {
      const targets = mode === 'single' ? ['One'] : ['One', 'Two'];
      if (mode === 'single') {
        await results();
        await page
          .getByRole('button', { name: `${info('One').name} details`, exact: true })
          .click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
        await expect(
          page.getByRole('heading', {
            name: 'Disable missing-target COM conversion reference?',
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.getByRole('dialog')).toContainText(info('One').target);
        await expect(page.getByRole('dialog')).toContainText(info('One').owner);
        await expect(page.getByRole('dialog')).toContainText(
          'legacy document conversion requirements',
        );
        await expect(
          page.getByRole('button', { name: 'Back up & disable conversion reference', exact: true }),
        ).toBeDisabled();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        expect(await fixture('inspect')).toEqual(original);
        expect(await backups()).toHaveLength(0);
        checked(
          'AutoConvertTo review displays the exact conversion CLSID and current-user scope, requires confirmation, and cancels without mutation',
        );
        await page
          .getByRole('button', { name: `${info('One').name} details`, exact: true })
          .click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
      } else {
        await scan();
        await page
          .locator('nav')
          .getByRole('button', { name: 'Clean registry', exact: true })
          .click();
        await page
          .getByRole('textbox', { name: 'Search cleaning candidates' })
          .fill(original.search);
        await expect(page.locator('.clean-candidate')).toHaveCount(2);
        for (const kind of targets)
          await page
            .getByRole('checkbox', { name: `Select ${info(kind).name}`, exact: true })
            .check();
        await page.getByRole('button', { name: 'Review selected (2)', exact: true }).click();
        await expect(page.locator('.clean-review-items details')).toHaveCount(2);
        await page.locator('.clean-review-items details summary').first().click();
      }
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page.screenshot({
        path: resolve(output, `desktop-conversion-${mode}-review.png`),
        fullPage: true,
      });
      await page
        .getByRole('button', {
          name:
            mode === 'single'
              ? 'Back up & disable conversion reference'
              : 'Back up & clean 2 entries',
          exact: true,
        })
        .click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30000,
      });
      expect(await fixture('inspect')).toEqual(removed(targets));
      const records = await backups();
      expect(records).toHaveLength(mode === 'single' ? 1 : 3);
      for (const { record } of records) {
        const program = original.views[0].classes.find((p) => p.owner === record.conversion.owner);
        const value = program.nodes
          .find((n) => n.path === 'AutoConvertTo')
          .values.find((v) => v.name === '');
        expect(record.original.kind).toBe(value.kind);
        expect(Buffer.from(record.original.bytes).toString('base64')).toBe(value.bytes);
        const values = (path) =>
          program.nodes
            .find((n) => n.path === path)
            .values.map((v) => ({
              name: v.name,
              value: { kind: v.kind, bytes: [...Buffer.from(v.bytes, 'base64')] },
            }));
        expect(record.conversion.guard).toEqual({
          values: values(''),
        });
      }
      if (mode === 'single') {
        let conflict = false;
        try {
          conflict = true;
          await fixture('conflict-create');
          const blocked = await page.evaluate(async (backupId) => {
            try {
              await window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId });
              return false;
            } catch (error) {
              return String(error).includes('target CLSID exists');
            }
          }, records[0].record.id);
          expect(blocked).toBe(true);
          expect(await backups()).toHaveLength(1);
        } finally {
          if (conflict) await fixture('conflict-remove');
        }
        expect(await fixture('inspect')).toEqual(removed(targets));
        summary.conversionRestoreConflictBlocked = true;
        checked(
          'A 32-bit target appearing after repair blocks restore without overwriting the removed mapping or its backup; removing only the owned conflict makes exact restore available again',
        );
      }
      await results();
      await page.getByRole('button', { name: `${info('One').name} details`, exact: true }).click();
      await expect(page.getByRole('dialog')).toContainText('conversion_mapping_absent');
      await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
      await page.keyboard.press('Escape');
      checked(
        `${mode}: only selected native conversion defaults are removed after individual verified backups; descriptions, both registry-view reads, owning class descriptions, class controls, other mappings, keys, and permissions stay exact; absent mappings offer no repeat repair`,
      );
      for (const kind of targets) await restore(kind);
      expect(await fixture('inspect')).toEqual(original);
      checked(
        `${mode}: AutoConvertTo backups survive reload and restore exact original REG_SZ bytes and metadata without opening or converting documents, loading classes or changing other registrations`,
      );
    }
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        const cleaned = await fixture('cleanup');
        expect(
          cleaned.views.every(
            (v) => v.classes.every((p) => !p.exists) && v.targets.every((t) => !t.exists),
          ),
        ).toBe(true);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
      try {
        for (const { path } of await backups()) await unlink(path);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.conversionFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned AutoConvertTo cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned AutoConvertTo trees, 32/64-bit class controls, and matching backups are removed; existing CLSID roots, unrelated names, permissions, and the read-only machine control are preserved',
  );
}
