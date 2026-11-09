import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve, dirname, basename } from 'node:path';
const run = promisify(execFile);

export async function verifyMenuRecovery(page, output, checked, summary) {
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
        resolve(import.meta.dirname, 'menu-fixture.ps1'),
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
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('shell_menus');
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
        [16, 18].includes(record.schemaVersion) &&
        original?.fixtures.some(
          (f) =>
            ['One', 'Two', 'Three', 'Four'].includes(f.kind) &&
            record.menu?.verbName === f.verb &&
            record.menu?.location === f.location,
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
      roots: view.roots.map((root) => ({
        ...root,
        menus: root.menus.map((menu) =>
          targets.includes(menu.kind)
            ? {
                ...menu,
                nodes: menu.nodes.map((node) =>
                  node.path === ''
                    ? {
                        ...node,
                        values: [
                          ...node.values,
                          { name: 'ProgrammaticAccessOnly', kind: 1, bytes: 'AAA=' },
                        ].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase())),
                      }
                    : node,
                ),
              }
            : menu,
        ),
      })),
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
    await expect(backup).toContainText('Context-menu visibility');
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Restore context-menu visibility?', exact: true }),
    ).toBeVisible();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore menu visibility', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.menuFixtureToken = token;
    await scan();
    await results();
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('review');
    await expect(page.locator('tbody tr')).toHaveCount(6);
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
          path: resolve(output, 'desktop-menu-export.png'),
          fullPage: true,
        });
      const document = JSON.parse(await readFile(path, 'utf8'));
      expect(document.format).toBe('rustregistry.findings');
      expect(document.schemaVersion).toBe(1);
      expect(document.filters).toEqual({
        query: original.search,
        category: 'shell_menus',
        status: 'review',
      });
      expect(document.exportedEntries).toBe(6);
      expect(document.entries).toHaveLength(6);
      expect(document.totalEntries).toBeGreaterThan(6);
      expect(document.scan.cancelled).toBe(false);
      expect(document.entries.map((e) => e.name).sort()).toEqual(
        ['One', 'Two', 'Three', 'Four', 'Protected', 'FolderProtected']
          .map((k) => info(k).name)
          .sort(),
      );
      expect(
        document.entries.every(
          (e) =>
            e.category === 'shell_menus' &&
            e.assessment.status === 'review' &&
            !Object.hasOwn(e, 'menuSnapshot'),
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
    await expect(page.locator('tbody tr')).toHaveCount(13);
    for (const [kind, status] of [
      ['One', 'Review'],
      ['Two', 'Review'],
      ['Three', 'Review'],
      ['Four', 'Review'],
      ['FilesystemFound', 'Found'],
      ['FilesystemDelegated', 'Unverified'],
      ['FolderHidden', 'Unverified'],
      ['FolderProtected', 'Review'],
      ['Found', 'Found'],
      ['Protected', 'Review'],
      ['Empty', 'Unverified'],
      ['Delegated', 'Unverified'],
      ['Hidden', 'Unverified'],
    ]) {
      const row = page.locator('tbody tr').filter({
        has: page.getByRole('button', { name: `${info(kind).name} details`, exact: true }),
      });
      await expect(row.locator('.status-badge')).toHaveText(status);
      await row.locator('.entry-button').click();
      if (['One', 'Two', 'Three', 'Four'].includes(kind))
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
      'Static menu inventory distinguishes missing/found commands, delegated and absent commands, protected verbs and already-hidden entries; only guarded custom user menus offer repair',
    );

    const entryId = `HKCU|shared|Software\\Classes\\AllFileSystemObjects\\shell\\${info('Three').verb}\\command|`;
    const plan = await page.evaluate(
      (id) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId: id }),
      entryId,
    );
    expect(plan.scope).toBe('shell_menu');
    let conflict = false;
    try {
      conflict = true;
      await fixture('conflict-create');
      const blocked = await page.evaluate(async (token) => {
        try {
          await window.__TAURI_INTERNALS__.invoke('apply_change', { token, confirmed: true });
          return false;
        } catch (error) {
          return String(error).includes('not confirmed missing');
        }
      }, plan.token);
      expect(blocked).toBe(true);
      expect(await backups()).toHaveLength(0);
    } finally {
      if (conflict) await fixture('conflict-remove');
    }
    expect(await fixture('inspect')).toEqual(original);
    summary.menuFileConflictBlocked = true;
    checked(
      'An owned executable appearing after review blocks native apply before any backup or mapping change; removing only the owned inert executable restores the exact baseline',
    );

    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    for (const kind of ['One', 'Two', 'Three', 'Four'])
      await expect(page.getByRole('dialog')).toContainText(info(kind).name);
    for (const kind of [
      'Found',
      'Protected',
      'Empty',
      'Delegated',
      'Hidden',
      'FilesystemFound',
      'FilesystemDelegated',
      'FolderHidden',
      'FolderProtected',
    ])
      await expect(page.getByRole('dialog')).not.toContainText(info(kind).name);
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    expect(await backups()).toHaveLength(0);
    checked(
      'Quick Clean includes only verified custom missing-target menus; cancellation preserves all raw mappings, descriptions, control records, unrelated names, and permissions without backups',
    );
    for (const mode of ['single', 'selected']) {
      const targets = mode === 'single' ? ['Three'] : ['One', 'Two', 'Three', 'Four'];
      if (mode === 'single') {
        await results();
        await page
          .getByRole('button', { name: `${info('Three').name} details`, exact: true })
          .click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
        await expect(
          page.getByRole('heading', {
            name: 'Hide broken context-menu entry?',
            exact: true,
          }),
        ).toBeVisible();
        await expect(page.getByRole('dialog')).toContainText(info('Three').command);
        await expect(
          page.getByRole('button', { name: 'Back up & hide menu entry', exact: true }),
        ).toBeDisabled();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        expect(await fixture('inspect')).toEqual(original);
        expect(await backups()).toHaveLength(0);
        checked(
          'Menu review displays the exact preserved command and current-user scope, requires confirmation, and cancels without mutation',
        );
        await page
          .getByRole('button', { name: `${info('Three').name} details`, exact: true })
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
        await expect(page.locator('.clean-candidate')).toHaveCount(4);
        for (const kind of targets)
          await page
            .getByRole('checkbox', { name: `Select ${info(kind).name}`, exact: true })
            .check();
        await page.getByRole('button', { name: 'Review selected (4)', exact: true }).click();
        await expect(page.locator('.clean-review-items details')).toHaveCount(4);
        await page.locator('.clean-review-items details summary').first().click();
      }
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page.screenshot({
        path: resolve(output, `desktop-menu-${mode}-review.png`),
        fullPage: true,
      });
      await page
        .getByRole('button', {
          name: mode === 'single' ? 'Back up & hide menu entry' : 'Back up & clean 4 entries',
          exact: true,
        })
        .click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
        timeout: 30000,
      });
      expect(await fixture('inspect')).toEqual(removed(targets));
      const records = await backups();
      expect(records).toHaveLength(mode === 'single' ? 1 : 5);
      for (const { record } of records) {
        const fixtureInfo = original.fixtures.find(
          (f) => f.verb === record.menu.verbName && f.location === record.menu.location,
        );
        expect(record.schemaVersion).toBe(
          ['all_file_system_objects', 'folder'].includes(fixtureInfo.location) ? 18 : 16,
        );
        const root = original.views[0].roots.find((r) => r.location === fixtureInfo.location);
        const menu = root.menus.find((m) => m.verb === fixtureInfo.verb);
        const value = menu.nodes
          .find((n) => n.path === 'command')
          .values.find((v) => v.name === '');
        expect(record.original.kind).toBe(value.kind);
        expect(Buffer.from(record.original.bytes).toString('base64')).toBe(value.bytes);
        const convert = (values) =>
          values.map((v) => ({
            name: v.name,
            value: { kind: v.kind, bytes: [...Buffer.from(v.bytes, 'base64')] },
          }));
        expect(record.menu.snapshot).toEqual({
          userRootValues: convert(root.values),
          machineRootValues: root.machineExists ? convert(root.machineValues) : null,
          verbValues: convert(menu.nodes.find((n) => n.path === '').values),
          commandValues: convert(menu.nodes.find((n) => n.path === 'command').values),
        });
      }
      if (mode === 'single') {
        await page
          .locator('nav')
          .getByRole('button', { name: 'Backups & restore', exact: true })
          .click();
        const search = page.getByRole('textbox', { name: 'Search backups', exact: true });
        const state = page.getByRole('combobox', { name: 'Filter backups by state', exact: true });
        await search.fill(original.search);
        await state.selectOption('restore_available');
        await expect(page.locator('.backup-item')).toHaveCount(1);
        await expect(page.locator('.backup-item')).toContainText(info('Three').name);
        await search.fill(records[0].record.id.toUpperCase());
        await expect(page.locator('.backup-item')).toHaveCount(1);
        await search.fill(`Software\\Classes\\AllFileSystemObjects\\shell\\${info('Three').verb}`);
        await expect(page.locator('.backup-item')).toHaveCount(1);
        await search.fill('Context-menu visibility');
        const inventory = await page.evaluate(() =>
          window.__TAURI_INTERNALS__.invoke('list_backups'),
        );
        await expect(page.locator('.backup-item')).toHaveCount(
          inventory.backups.filter(
            (b) => b.scope === 'shell_menu' && b.state === 'restore_available',
          ).length,
        );
        await search.fill(original.search);
        await state.selectOption('conflict');
        await expect(
          page.getByRole('heading', { name: 'No matching backups', exact: true }),
        ).toBeVisible();
        await expect(page.getByRole('button', { name: 'Review restore', exact: true })).toHaveCount(
          0,
        );
        await page.getByRole('button', { name: 'Clear backup filters', exact: true }).click();
        await expect(search).toHaveValue('');
        await expect(state).toHaveValue('all');
        await expect(page.locator('.backup-item')).toHaveCount(
          Math.min(inventory.backups.length, 50),
        );
        await page.screenshot({
          path: resolve(output, 'desktop-backup-discovery.png'),
          fullPage: true,
        });
        expect(await fixture('inspect')).toEqual(removed(targets));
        expect(await backups()).toEqual(records);
        summary.backupSearchVerified = true;
        checked(
          'Backup search finds saved entries by ID, registry path and displayed scope; state filters combine with search, show honest empty results, clear back to the complete inventory and never alter registry data, backup bytes or restore eligibility',
        );
      }
      await results();
      await page
        .getByRole('button', { name: `${info('Three').name} details`, exact: true })
        .click();
      await expect(page.getByRole('dialog')).toContainText('shell_menu_hidden');
      await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
      await page.keyboard.press('Escape');
      checked(
        `${mode}: only selected menu visibility flags are added after individual verified backups; descriptions, both registry-view reads, commands, display/root metadata, control records, other mappings, keys, and permissions stay exact; already-hidden menus offer no repeated hiding`,
      );
      for (const kind of targets) await restore(kind);
      expect(await fixture('inspect')).toEqual(original);
      if (mode === 'single') {
        await page
          .locator('nav')
          .getByRole('button', { name: 'Backups & restore', exact: true })
          .click();
        const search = page.getByRole('textbox', { name: 'Search backups', exact: true });
        const state = page.getByRole('combobox', { name: 'Filter backups by state', exact: true });
        await search.fill(original.search);
        await state.selectOption('original_present');
        await expect(page.locator('.backup-item')).toHaveCount(1);
        await expect(
          page
            .locator('.backup-item')
            .getByRole('button', { name: 'Original present', exact: true }),
        ).toBeDisabled();
        await page.getByRole('button', { name: 'Refresh', exact: true }).click();
        await expect(page.getByRole('button', { name: 'Refresh', exact: true })).toBeEnabled();
        await expect(search).toHaveValue(original.search);
        await expect(state).toHaveValue('original_present');
        await expect(page.locator('.backup-item')).toHaveCount(1);
        await state.selectOption('restore_available');
        await expect(
          page.getByRole('heading', { name: 'No matching backups', exact: true }),
        ).toBeVisible();
        await page.getByRole('button', { name: 'Clear backup filters', exact: true }).click();
        summary.backupStateFilterVerified = true;
        checked(
          'After restoring a new filesystem-menu backup, Original present is disabled, Restore available excludes it, and refresh preserves the selected search/state without changing eligibility',
        );
      }
      checked(
        `${mode}: Menu backups survive reload and restore exact original REG_SZ/REG_EXPAND_SZ bytes and metadata without executing commands, loading icons, or changing defaults`,
      );
    }
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        const cleaned = await fixture('cleanup');
        expect(
          cleaned.views.every((v) =>
            v.roots.every((root) => root.menus.every((menu) => !menu.exists)),
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
    for (const path of exported) {
      try {
        const document = JSON.parse(await readFile(path, 'utf8'));
        if (
          document.format !== 'rustregistry.findings' ||
          document.filters.query !== token.replaceAll('-', '')
        )
          throw new Error('Owned report identity changed');
        await unlink(path);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.menuExportCleanup = cleanupErrors.length === 0;
    summary.menuFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned menu cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned custom menu trees, inert files, and matching backups are removed; existing shell roots, unrelated names, permissions are preserved',
  );
}
