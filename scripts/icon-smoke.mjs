import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, dirname, basename } from 'node:path';
const run = promisify(execFile);

export async function verifyIconRecovery(page, output, checked, summary) {
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
        resolve(import.meta.dirname, 'icon-fixture.ps1'),
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
  const exported = [];
  const info = (kind) => original.fixtures.find((f) => f.kind === kind);
  const results = async () => {
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page
      .getByRole('combobox', { name: 'Filter by category' })
      .selectOption('application_icons');
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
        record.schemaVersion === 15 &&
        original?.fixtures.some(
          (f) => ['One', 'Two'].includes(f.kind) && record.icon?.executable === f.name,
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
      applications: view.applications.map((program) =>
        targets.includes(program.kind)
          ? {
              ...program,
              nodes: program.nodes.map((node) =>
                node.path === 'DefaultIcon'
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
    await expect(backup).toContainText('Application icon reference');
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Restore application icon reference?', exact: true }),
    ).toBeVisible();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore icon reference', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.iconFixtureToken = token;
    await scan();
    await results();
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('review');
    await expect(page.locator('tbody tr')).toHaveCount(3);
    for (let index = 0; index < 2; index++) {
      const previous = exported.at(-1);
      await page.getByRole('button', { name: 'Export filtered JSON', exact: true }).click();
      const receipt = page.locator('[aria-label="Exported report path"]');
      if (previous) await expect(receipt).not.toHaveText(previous);
      await expect(receipt).toHaveText(/\.json$/i);
      const path = await receipt.innerText();
      expect(dirname(resolve(path)).toLowerCase()).toBe(
        resolve(dirname(storagePath), 'reports-v1').toLowerCase(),
      );
      expect(basename(path)).toMatch(/^RustRegistry-findings-\d+-[a-f0-9-]{36}\.json$/);
      exported.push(path);
      if (index === 0)
        await page.screenshot({
          path: resolve(output, 'desktop-filtered-export.png'),
          fullPage: true,
        });
      const document = JSON.parse(await readFile(path, 'utf8'));
      expect(document.format).toBe('rustregistry.findings');
      expect(document.schemaVersion).toBe(1);
      expect(document.filters).toEqual({
        query: original.search,
        category: 'application_icons',
        status: 'review',
      });
      expect(document.exportedEntries).toBe(3);
      expect(document.entries).toHaveLength(3);
      expect(document.totalEntries).toBeGreaterThan(3);
      expect(document.scan.cancelled).toBe(false);
      expect(document.entries.map((e) => e.name).sort()).toEqual(
        ['One', 'Two', 'Complex'].map((k) => info(k).name).sort(),
      );
      expect(
        document.entries.every(
          (e) =>
            e.category === 'application_icons' &&
            e.assessment.status === 'review' &&
            !Object.hasOwn(e, 'iconState'),
        ),
      ).toBe(true);
    }
    expect(exported[0]).not.toBe(exported[1]);
    await page.getByRole('textbox', { name: 'Search entries' }).fill(original.search + '-no-match');
    await expect(
      page.getByRole('button', { name: 'Export filtered JSON', exact: true }),
    ).toBeDisabled();
    await results();
    expect(await fixture('inspect')).toEqual(original);
    expect(await backups()).toHaveLength(0);
    checked(
      'Filtered JSON exports save exactly the selected category/status/search results, preserve both previous reports, disable empty exports, and never alter registry data or backups',
    );
    await expect(page.locator('tbody tr')).toHaveCount(6);
    for (const [kind, status] of [
      ['One', 'Review'],
      ['Two', 'Review'],
      ['Found', 'Found'],
      ['Resource', 'Unverified'],
      ['Empty', 'Unverified'],
      ['Complex', 'Review'],
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
      await page.keyboard.press('Escape');
    }
    checked(
      'Application icon inventory distinguishes literal missing/found files, resource expressions, absent values and complex metadata; only guarded current-user icon references offer repair',
    );

    const entryId = `HKCU|shared|Software\\Classes\\Applications\\${info('One').name}\\DefaultIcon|`;
    const plan = await page.evaluate(
      (id) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId: id }),
      entryId,
    );
    expect(plan.scope).toBe('application_icon');
    let conflict = false;
    try {
      conflict = true;
      await fixture('conflict-create');
      const blocked = await page.evaluate(async (token) => {
        try {
          await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
          return false;
        } catch (error) {
          return String(error).includes('icon file is not confirmed missing');
        }
      }, plan.token);
      expect(blocked).toBe(true);
      expect(await backups()).toHaveLength(0);
    } finally {
      if (conflict) await fixture('conflict-remove');
    }
    expect(await fixture('inspect')).toEqual(original);
    summary.iconFileConflictBlocked = true;
    checked(
      'An owned icon file appearing after review blocks native apply before any backup or mapping change; removing only the owned inert icon file restores the exact baseline',
    );

    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    for (const kind of ['One', 'Two'])
      await expect(page.getByRole('dialog')).toContainText(info(kind).name);
    for (const kind of ['Found', 'Resource', 'Empty', 'Complex'])
      await expect(page.getByRole('dialog')).not.toContainText(info(kind).name);
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    expect(await backups()).toHaveLength(0);
    checked(
      'Quick Clean includes only verified missing icon references; cancellation preserves all raw mappings, descriptions, control records, unrelated names, and permissions without backups',
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
            name: 'Remove missing application icon reference?',
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.getByRole('dialog')).toContainText(info('One').path);
        await expect(
          page.getByRole('button', { name: 'Back up & remove icon reference', exact: true }),
        ).toBeDisabled();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        expect(await fixture('inspect')).toEqual(original);
        expect(await backups()).toHaveLength(0);
        checked(
          'Icon review displays the exact icon path and current-user scope, requires confirmation, and cancels without mutation',
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
        path: resolve(output, `desktop-icon-${mode}-review.png`),
        fullPage: true,
      });
      await page
        .getByRole('button', {
          name: mode === 'single' ? 'Back up & remove icon reference' : 'Back up & clean 2 entries',
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
        const program = original.views[0].applications.find(
          (p) => p.name === record.icon.executable,
        );
        const value = program.nodes
          .find((n) => n.path === 'DefaultIcon')
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
        expect(record.icon.guard).toEqual({
          applicationValues: values(''),
          shellValues: values('shell'),
          verbValues: values('shell\\open'),
          commandValues: values('shell\\open\\command'),
        });
      }
      await results();
      await page.getByRole('button', { name: `${info('One').name} details`, exact: true }).click();
      await expect(page.getByRole('dialog')).toContainText('icon_mapping_absent');
      await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
      await page.keyboard.press('Escape');
      checked(
        `${mode}: only selected icon defaults are removed after individual verified backups; descriptions, both registry-view reads, application commands/visibility metadata, control records, other mappings, keys, and permissions stay exact; absent mappings offer no repeat repair`,
      );
      for (const kind of targets) await restore(kind);
      expect(await fixture('inspect')).toEqual(original);
      checked(
        `${mode}: Icon backups survive reload and restore exact original REG_SZ/REG_EXPAND_SZ bytes and metadata without executing commands, decoding icons, or changing defaults`,
      );
    }
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        const cleaned = await fixture('cleanup');
        expect(cleaned.views.every((v) => v.applications.every((p) => !p.exists))).toBe(true);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
      try {
        for (const { path } of await backups()) await unlink(path);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    for (const path of exported) {
      try {
        const document = JSON.parse(await readFile(path, 'utf8'));
        if (document.format !== 'rustregistry.findings' || document.filters.query !== token)
          throw new Error('Owned report identity changed');
        await unlink(path);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.iconExportCleanup = cleanupErrors.length === 0;
    summary.iconFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned icon cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned application trees, inert files, and matching backups are removed; existing Applications roots, unrelated names, permissions are preserved',
  );
}
