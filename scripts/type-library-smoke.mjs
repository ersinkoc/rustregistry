import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifyTypeLibraryRecovery(page, output, checked, summary) {
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
        resolve(import.meta.dirname, 'type-library-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
      ],
      { windowsHide: true, timeout: 15000, encoding: 'utf8' },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  const scan = async () => {
    await page.getByRole('button', { name: 'Scan again', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  const results = async () => {
    await page
      .locator('nav')
      .getByRole('button', { name: /Scan results/ })
      .click();
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('type_libraries');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page.getByRole('textbox', { name: 'Search entries' }).fill(token);
  };
  await page.locator('nav').getByRole('button', { name: 'Backups & restore', exact: true }).click();
  await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
  const storagePath = await page.locator('.backup-location .mono').innerText();
  let original,
    attempted = false,
    failure;
  const cleanupErrors = [];
  const info = (kind) => original.fixtures.find((f) => f.kind === kind);
  const name = (kind, platform = 'win64', version = '1.0') =>
    `${info(kind).name} · ${version} · 0 · ${platform}`;
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
        record.schemaVersion === 11 &&
        original?.fixtures.some(
          (f) => ['One', 'Two'].includes(f.kind) && f.id === record.typeLibrary?.libraryId,
        ) &&
        record.typeLibrary.version === '1.0' &&
        record.typeLibrary.locale === '0' &&
        record.typeLibrary.platform === 'win64'
      )
        matches.push({ path, record });
    }
    return matches;
  };
  const removed = (targets) => ({
    ...original,
    views: original.views.map((view) => ({
      ...view,
      libraries: view.libraries.map((library) =>
        targets.includes(library.kind)
          ? {
              ...library,
              nodes: library.nodes.map((node) =>
                node.path === '1.0\\0\\win64' ? { ...node, values: [] } : node,
              ),
            }
          : library,
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
      .filter({ has: page.getByRole('heading', { name: name(kind), exact: true }) })
      .first();
    await expect(backup).toContainText('Type library · win64');
    await backup.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Restore type library mapping?', exact: true }),
    ).toBeVisible();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore library mapping', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.typeLibraryFixtureToken = token;
    await scan();
    await results();
    await expect(page.locator('tbody tr')).toHaveCount(12);
    for (const kind of ['One', 'Two', 'Found', 'Complex', 'Windows'])
      for (const platform of ['win32', 'win64']) {
        const row = page.locator('tbody tr').filter({
          has: page.getByRole('button', { name: `${name(kind, platform)} details`, exact: true }),
        });
        const status =
          platform === 'win32' || kind === 'Windows'
            ? 'Unverified'
            : kind === 'Found'
              ? 'Found'
              : 'Review';
        await expect(row.locator('.status-badge')).toHaveText(status);
        await row.locator('.entry-button').click();
        if (platform === 'win64' && ['One', 'Two'].includes(kind))
          await expect(
            page.getByRole('button', { name: 'Review repair', exact: true }),
          ).toBeEnabled();
        else
          await expect(
            page.getByRole('button', { name: 'Review repair', exact: true }),
          ).toHaveCount(0);
        await page.keyboard.press('Escape');
      }
    checked(
      'TypeLib inventory distinguishes missing/found win64 paths, preserved win32 mappings, Windows exclusions, and multi-version read-only controls',
    );
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    for (const kind of ['One', 'Two'])
      await expect(page.getByRole('dialog')).toContainText(name(kind));
    for (const kind of ['Found', 'Complex', 'Windows'])
      await expect(page.getByRole('dialog')).not.toContainText(info(kind).name);
    for (const kind of ['One', 'Two'])
      await expect(page.getByRole('dialog')).not.toContainText(name(kind, 'win32'));
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    expect(await fixture('inspect')).toEqual(original);
    expect(await backups()).toHaveLength(0);
    checked(
      'Quick Clean includes only guarded win64 library mappings; cancel preserves both registry-view reads, every metadata byte and permission, and the inert file without backups',
    );
    for (const mode of ['single', 'selected']) {
      const targets = mode === 'single' ? ['One'] : ['One', 'Two'];
      if (mode === 'single') {
        await results();
        await page.getByRole('button', { name: `${name('One')} details`, exact: true }).click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
        await expect(
          page.getByRole('heading', { name: 'Disable missing type library mapping?', exact: true }),
        ).toBeVisible();
        await expect(page.getByRole('dialog')).toContainText(info('One').path);
        await expect(page.getByRole('dialog')).toContainText('Shared registry · win64 library');
        await expect(
          page.getByRole('button', { name: 'Back up & disable library mapping', exact: true }),
        ).toBeDisabled();
        await page.getByRole('button', { name: 'Cancel', exact: true }).click();
        expect(await fixture('inspect')).toEqual(original);
        expect(await backups()).toHaveLength(0);
        checked(
          'Type library review shows the exact file path and shared-key/win64 distinction, requires confirmation, and cancels without mutation',
        );
        await page.getByRole('button', { name: `${name('One')} details`, exact: true }).click();
        await page.getByRole('button', { name: 'Review repair', exact: true }).click();
      } else {
        await scan();
        await page
          .locator('nav')
          .getByRole('button', { name: 'Clean registry', exact: true })
          .click();
        await page.getByRole('textbox', { name: 'Search cleaning candidates' }).fill(token);
        await expect(page.locator('.clean-candidate')).toHaveCount(2);
        for (const kind of targets)
          await page.getByRole('checkbox', { name: `Select ${name(kind)}`, exact: true }).check();
        await page.getByRole('button', { name: 'Review selected (2)', exact: true }).click();
        await expect(page.locator('.clean-review-items details')).toHaveCount(2);
        await page.locator('.clean-review-items details summary').first().click();
      }
      await page.getByRole('dialog').getByRole('checkbox').check();
      await page.screenshot({
        path: resolve(output, `desktop-type-library-${mode}-review.png`),
        fullPage: true,
      });
      await page
        .getByRole('button', {
          name:
            mode === 'single' ? 'Back up & disable library mapping' : 'Back up & clean 2 entries',
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
        const library = original.views[0].libraries.find(
          (l) => l.id === record.typeLibrary.libraryId,
        );
        const value = library.nodes.find((n) => n.path === '1.0\\0\\win64').values[0];
        expect(record.original.kind).toBe(value.kind);
        expect(Buffer.from(record.original.bytes).toString('base64')).toBe(value.bytes);
        const nodes = library.nodes
          .map((node) => ({
            path: node.path,
            values:
              node.path === '1.0\\0\\win64'
                ? []
                : node.values.map((v) => ({
                    name: v.name,
                    value: { kind: v.kind, bytes: [...Buffer.from(v.bytes, 'base64')] },
                  })),
          }))
          .sort((a, b) =>
            a.path.toLowerCase() < b.path.toLowerCase()
              ? -1
              : a.path.toLowerCase() > b.path.toLowerCase()
                ? 1
                : 0,
          );
        expect(record.typeLibrary.guard.nodes).toEqual(nodes);
      }
      await results();
      await page.getByRole('button', { name: `${name('One')} details`, exact: true }).click();
      await expect(page.getByRole('dialog')).toContainText('type_library_mapping_absent');
      await expect(page.getByRole('button', { name: 'Review repair', exact: true })).toHaveCount(0);
      await page.keyboard.press('Escape');
      checked(
        `${mode}: only selected win64 defaults are removed after separate verified backups; win32 values, all metadata/permissions, other libraries, and the inert file remain exact; absent mappings offer no repeated repair`,
      );
      for (const kind of targets) await restore(kind);
      expect(await fixture('inspect')).toEqual(original);
      checked(
        `${mode}: type library backups survive reload and restore exact original types/bytes with both view reads, all metadata, win32 mappings, and permissions unchanged`,
      );
    }
  } catch (error) {
    failure = error;
  } finally {
    if (attempted) {
      try {
        const cleaned = await fixture('cleanup');
        expect(cleaned.existingFile).toBe(false);
        expect(cleaned.views.every((v) => v.libraries.every((l) => !l.exists))).toBe(true);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
      try {
        for (const { path } of await backups()) await unlink(path);
      } catch (error) {
        cleanupErrors.push(String(error));
      }
    }
    summary.typeLibraryFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned type library cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned TypeLib trees, inert file, and matching test backups are cleaned without changing existing root data, library names, or permissions',
  );
}
