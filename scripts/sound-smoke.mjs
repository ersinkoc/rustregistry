import { expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
const run = promisify(execFile);

export async function verifySoundRecovery(page, output, checked, summary) {
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
        resolve(import.meta.dirname, 'sound-fixture.ps1'),
        '-Action',
        action,
        '-Token',
        token,
      ],
      { windowsHide: true, timeout: 30000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 },
    );
    return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
  };
  let original,
    storagePath,
    failure,
    attempted = false;
  const cleanupErrors = [];
  const eventNode = (tree, event) => tree.children.find((c) => c.name === event).node;
  const currentNode = (tree, event) =>
    eventNode(tree, event).children.find((c) => c.name === '.Current').node;
  const mapping = (tree, event) => currentNode(tree, event).values.find((v) => v.name === '');
  const info = (event) => original.fixtures.find((f) => f.event === event);
  const id = (event) =>
    `HKCU|shared|AppEvents\\Schemes\\Apps\\${original.application}\\${event}\\.Current|`;
  const preserved = (state, cleared = []) => {
    expect(state.environmentPreserved).toBe(true);
    const expected = structuredClone(original.tree);
    for (const event of cleared) {
      const value = mapping(expected, event);
      value.type = 1;
      value.data = 'AAA=';
    }
    expect(state.tree).toEqual(expected);
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
    await page.getByRole('combobox', { name: 'Filter by category' }).selectOption('sound_events');
    await page.getByRole('combobox', { name: 'Filter by status' }).selectOption('all');
    await page
      .getByRole('textbox', { name: 'Search entries' })
      .fill(`${original.application} / MissingOne / .Current`);
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
      if (record.schemaVersion === 22 && record.sound?.application === original.application)
        found.push({ path, record });
    }
    return found;
  };
  const blocked = async (plan, match) => {
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
    summary.soundLastBlockedOutcome = outcome;
    expect(outcome.blocked).toBe(true);
  };
  const prepare = async () =>
    page.evaluate(
      (entryId) => window.__TAURI_INTERNALS__.invoke('prepare_quarantine', { entryId }),
      id('MissingOne'),
    );
  const restore = async (b) => {
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    const card = page
      .locator('.backup-item')
      .filter({ has: page.getByText(b.record.id, { exact: true }) });
    await card.getByRole('button', { name: 'Review restore', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Restore sound assignment?', exact: true }),
    ).toBeVisible();
    await expect(page.getByRole('dialog')).toContainText(b.record.sound.target);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Restore sound assignment', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
  };
  try {
    attempted = true;
    original = await fixture('create');
    summary.soundFixtureToken = token;
    await page
      .locator('nav')
      .getByRole('button', { name: 'Backups & restore', exact: true })
      .click();
    await expect(page.locator('.backup-location .mono')).toHaveText(/^[a-z]:\\/i);
    storagePath = await page.locator('.backup-location .mono').innerText();
    await scan();
    await results();
    for (const [event, status] of [
      ['MissingOne', 'Review'],
      ['MissingTwo', 'Review'],
      ['Found', 'Found'],
      ['Empty', 'Found'],
      ['Absent', 'Unverified'],
      ['Expanded', 'Unverified'],
      ['Relative', 'Unverified'],
      ['Windows', 'Review'],
      ['WrongType', 'Unverified'],
      ['WrongExtension', 'Unverified'],
      ['Nested', 'Review'],
      ['SystemDefault', 'Review'],
    ]) {
      await page
        .getByRole('textbox', { name: 'Search entries' })
        .fill(`${original.application} / ${event} / .Current`);
      const button = page.getByRole('button', { name: `${info(event).name} details`, exact: true });
      await expect(
        page.locator('tbody tr').filter({ has: button }).locator('.status-badge'),
      ).toHaveText(status);
      await button.click();
      const review = page.getByRole('button', { name: 'Review sound repair', exact: true });
      if (['MissingOne', 'MissingTwo'].includes(event)) await expect(review).toBeEnabled();
      else await expect(review).toHaveCount(0);
      await page.keyboard.press('Escape');
    }
    for (const scheme of ['.Default', '.None', 'OwnedSaved']) {
      await page
        .getByRole('textbox', { name: 'Search entries' })
        .fill(`${original.application} / MissingOne / ${scheme}`);
      await page
        .getByRole('button', {
          name: `${original.application} / MissingOne / ${scheme} details`,
          exact: true,
        })
        .click();
      await expect(
        page.getByRole('button', { name: 'Review sound repair', exact: true }),
      ).toHaveCount(0);
      await page.keyboard.press('Escape');
    }
    preserved(await fixture('inspect'));
    checked(
      'Sound inventory separates current missing/found files, explicit empty and absent assignments, expanded/relative/Windows/invalid/nested controls and read-only saved/default/No Sounds schemes without playback',
    );
    let conflict = false;
    try {
      const p = await prepare();
      await fixture('conflict-file-create');
      conflict = true;
      await blocked(p, 'not confirmed missing');
      expect(await backups()).toHaveLength(0);
      preserved(await fixture('inspect'));
    } finally {
      if (conflict) await fixture('conflict-file-remove');
    }
    summary.soundApplyFileConflictBlocked = true;
    checked(
      'A real audio-path file appearing after review blocks sound repair before any backup or assignment change',
    );
    conflict = false;
    try {
      const p = await prepare();
      await fixture('conflict-metadata-create');
      conflict = true;
      await blocked(p, 'metadata changed');
      expect(await backups()).toHaveLength(0);
    } finally {
      if (conflict) await fixture('conflict-metadata-remove');
    }
    preserved(await fixture('inspect'));
    summary.soundApplyMetadataConflictBlocked = true;
    checked(
      'Saved-scheme metadata added after review blocks current sound repair; removing only the owned conflict restores eligibility',
    );
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('combobox', { name: 'Cleaning category' }).selectOption('sound_events');
    await page
      .getByRole('textbox', { name: 'Search cleaning candidates' })
      .fill(original.application);
    await expect(page.locator('.clean-candidate')).toHaveCount(2);
    await page.getByRole('button', { name: 'Review Quick Clean', exact: true }).click();
    const quick = page.getByRole('dialog');
    for (const event of ['MissingOne', 'MissingTwo'])
      await expect(quick).toContainText(info(event).name);
    await expect(quick.locator('.clean-review-items details')).toHaveCount(2);
    await expect(quick).toContainText('explicit empty');
    await quick.getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    checked(
      'Category-scoped Quick Clean includes only supported current sound assignments and review cancellation preserves all schemes without backups',
    );
    await results();
    await page
      .getByRole('button', { name: `${info('MissingOne').name} details`, exact: true })
      .click();
    await page.getByRole('button', { name: 'Review sound repair', exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Clear missing sound assignment?', exact: true }),
    ).toBeVisible();
    const apply = page.getByRole('button', {
      name: 'Back up & clear sound assignment',
      exact: true,
    });
    await expect(apply).toBeDisabled();
    await expect(page.getByRole('dialog')).toContainText(info('MissingOne').target);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await expect(apply).toBeEnabled();
    await page.screenshot({
      path: resolve(output, 'desktop-sound-repair-review.png'),
      fullPage: true,
    });
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    preserved(await fixture('inspect'));
    expect(await backups()).toHaveLength(0);
    await page
      .getByRole('button', { name: `${info('MissingOne').name} details`, exact: true })
      .click();
    await page.getByRole('button', { name: 'Review sound repair', exact: true }).click();
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page
      .getByRole('button', { name: 'Back up & clear sound assignment', exact: true })
      .click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    preserved(await fixture('inspect'), ['MissingOne']);
    const records = await backups();
    expect(records).toHaveLength(1);
    const b = records[0];
    expect(b.record.sound.target).toBe(info('MissingOne').target);
    expect(b.record.sound.event).toBe('MissingOne');
    expect(Buffer.from(b.record.original.bytes).toString('base64')).toBe(
      mapping(original.tree, 'MissingOne').data,
    );
    checked(
      'Individual sound review requires explicit confirmation, cancellation is read-only, and schema-22 repair writes only the chosen exact empty REG_SZ while every key, saved scheme, other value and permission remains intact',
    );
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    const backupBytes = await readFile(b.path);
    for (const kind of ['file', 'metadata']) {
      conflict = false;
      try {
        const p = await page.evaluate(
          (backupId) => window.__TAURI_INTERNALS__.invoke('prepare_restore', { backupId }),
          b.record.id,
        );
        await fixture(`conflict-${kind}-create`);
        conflict = true;
        await blocked(p, kind === 'file' ? 'not confirmed missing' : 'metadata changed');
        expect(await readFile(b.path)).toEqual(backupBytes);
      } finally {
        if (conflict) await fixture(`conflict-${kind}-remove`);
      }
    }
    preserved(await fixture('inspect'), ['MissingOne']);
    summary.soundRestoreFileConflictBlocked = true;
    summary.soundRestoreMetadataConflictBlocked = true;
    checked(
      'The sound backup survives reload and both real post-review file and saved-metadata conflicts block restore without modifying its bytes or overwriting the cleared assignment',
    );
    await restore(b);
    preserved(await fixture('inspect'));
    checked(
      'UI sound restoration returns the exact original REG_SZ bytes after reload, preserving selected/default/saved schemes, unrelated applications and permissions without playing audio',
    );
    const before = new Set((await backups()).map((b) => b.record.id));
    await page.locator('nav').getByRole('button', { name: 'Clean registry', exact: true }).click();
    await page.getByRole('combobox', { name: 'Cleaning category' }).selectOption('sound_events');
    await page
      .getByRole('textbox', { name: 'Search cleaning candidates' })
      .fill(original.application);
    await expect(page.locator('.clean-candidate')).toHaveCount(2);
    for (const event of ['MissingOne', 'MissingTwo'])
      await page.getByRole('checkbox', { name: `Select ${info(event).name}`, exact: true }).check();
    await page.getByRole('button', { name: 'Review selected (2)', exact: true }).click();
    await expect(page.getByRole('dialog').locator('.clean-review-items details')).toHaveCount(2);
    await page.getByRole('dialog').getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Back up & clean 2 entries', exact: true }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Scan again', exact: true })).toBeEnabled({
      timeout: 30000,
    });
    preserved(await fixture('inspect'), ['MissingOne', 'MissingTwo']);
    const selected = (await backups()).filter((b) => !before.has(b.record.id));
    expect(selected).toHaveLength(2);
    for (const record of selected)
      expect(Buffer.from(record.record.original.bytes).toString('base64')).toBe(
        mapping(original.tree, record.record.sound.event).data,
      );
    checked(
      'Selected Clean clears exactly two chosen sound assignments with separate verified backups while all saved schemes, metadata, files and permissions remain unchanged',
    );
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
    for (const b of selected) await restore(b);
    preserved(await fixture('inspect'));
    checked(
      'Both selected sound backups survive reload and restore exact original bytes in the correct event without recreating keys or altering fallback settings',
    );
  } catch (error) {
    failure = error;
  } finally {
    if (attempted)
      try {
        const after = await fixture('cleanup');
        expect(after.tree).toBeNull();
        expect(after.environmentPreserved).toBe(true);
      } catch (e) {
        cleanupErrors.push(String(e));
      }
    if (storagePath && original)
      try {
        for (const b of await backups()) await unlink(b.path);
      } catch (e) {
        cleanupErrors.push(String(e));
      }
    summary.soundFixtureCleanup = cleanupErrors.length === 0;
    summary.errors.push(...cleanupErrors);
  }
  if (failure) throw failure;
  if (cleanupErrors.length)
    throw new Error(`Owned sound cleanup failed: ${cleanupErrors.join('; ')}`);
  checked(
    'Owned sound registrations, inert files and matching backups are conditionally cleaned while the pre-existing sound configuration and unrelated applications remain preserved',
  );
}
