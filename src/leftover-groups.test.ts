import { describe, expect, it } from 'vitest';
import { leftoverGroups, leftoverActionName } from './leftover-groups';
import type { RegistryEntry } from './model';
function hint(id: string, extension: string, repairable = true): RegistryEntry {
  return {
    id,
    name: 'Removed app',
    category: 'application_leftovers',
    hive: 'HKCU',
    view: 'shared',
    keyPath: 'Software\\Classes\\Applications\\old.exe\\SupportedTypes',
    valueName: extension,
    valueType: 'REG_SZ',
    rawValue: '',
    publisher: null,
    version: null,
    leftoverRepairable: repairable,
    assessment: {
      status: 'review',
      code: 'application_leftover_candidate',
      target: 'C:\\Gone\\old.exe',
      explanation: 'Owned evidence',
    },
    leftoverEvidence: {
      applicationName: 'Removed app',
      directory: 'C:\\Gone',
      executable: 'C:\\Gone\\old.exe',
      uninstaller: 'C:\\Gone\\remove.exe',
      uninstallPath: 'HKCU\\Uninstall\\Owner',
      applicationPath: 'Software\\Classes\\Applications\\old.exe',
      relatedIds: [],
    },
  };
}
describe('application leftover grouping', () => {
  it('combines sibling hints into one evidence group and retains every independently reviewable action', () => {
    const entries = [hint('a', '.one', false), hint('b', '.two')];
    const before = structuredClone(entries);
    const groups = leftoverGroups(entries);
    expect(groups).toHaveLength(1);
    expect(groups[0].id).toBe('b');
    expect(new Set(groups[0].leftoverEvidence?.relatedIds)).toEqual(new Set(['a', 'b']));
    expect(entries).toEqual(before);
  });
  it('never groups by product name alone or merges distinct uninstall owners', () => {
    const a = hint('a', '.one');
    const b = hint('b', '.two');
    b.leftoverEvidence = { ...b.leftoverEvidence!, uninstallPath: 'HKCU\\Uninstall\\Other' };
    expect(leftoverGroups([a, b])).toHaveLength(2);
  });
  it('labels each file-type action distinctly while leaving search-path names unchanged', () => {
    const a = hint('a', '.one'),
      b = hint('b', '.two');
    expect(leftoverActionName(a)).toBe('Removed app (.one)');
    expect(leftoverActionName(b)).toBe('Removed app (.two)');
    expect(
      leftoverActionName({
        ...a,
        keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\old.exe',
        valueName: 'Path',
      }),
    ).toBe('Removed app');
  });
});
