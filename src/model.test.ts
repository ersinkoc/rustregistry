import { describe, expect, it } from 'vitest';
import { countStatuses, filterEntries } from './model';
import type { RegistryEntry } from './model';

const entries: RegistryEntry[] = [
  {
    id: '1',
    name: 'Insight application',
    category: 'startup',
    hive: 'HKCU',
    keyPath: 'Software\\Run',
    view: 'shared',
    valueName: 'App',
    valueType: 'REG_SZ',
    rawValue: 'C:\\app.exe',
    publisher: 'Example',
    version: null,
    assessment: {
      status: 'found',
      code: 'target_found',
      explanation: 'Found',
      target: 'C:\\app.exe',
    },
  },
  {
    id: '2',
    name: 'Editor',
    category: 'app_paths',
    hive: 'HKLM',
    keyPath: 'Software\\App Paths',
    view: '64',
    valueName: '',
    valueType: 'REG_SZ',
    rawValue: 'D:\\editor.exe',
    publisher: null,
    version: null,
    assessment: {
      status: 'review',
      code: 'target_missing',
      explanation: 'Missing',
      target: 'D:\\editor.exe',
    },
  },
  {
    id: '3',
    name: 'Installer',
    category: 'uninstall',
    hive: 'HKLM',
    keyPath: 'Software\\Uninstall',
    view: '32',
    valueName: 'InstallLocation',
    valueType: '—',
    rawValue: '',
    publisher: null,
    version: null,
    assessment: {
      status: 'unknown',
      code: 'value_unavailable',
      explanation: 'No location',
      target: null,
    },
  },
];

describe('registry result exploration', () => {
  it('combines category, status and case-insensitive text filters', () => {
    expect(filterEntries(entries, 'INSIGHT', 'startup', 'found').map((e) => e.id)).toEqual(['1']);
    expect(filterEntries(entries, 'D:\\editor', 'app_paths', 'review').map((e) => e.id)).toEqual([
      '2',
    ]);
    expect(filterEntries(entries, '', 'all', 'unknown').map((e) => e.id)).toEqual(['3']);
  });
  it('does not present unrelated records when filters have no match', () => {
    expect(filterEntries(entries, 'absent', 'all', 'all')).toEqual([]);
    expect(filterEntries(entries, '', 'startup', 'review')).toEqual([]);
    expect(filterEntries([], '', 'all', 'all')).toEqual([]);
  });
  it('counts uncertainty separately from review recommendations', () => {
    expect(countStatuses(entries)).toEqual({ found: 1, review: 1, unknown: 1 });
    expect(countStatuses([])).toEqual({ found: 0, review: 0, unknown: 0 });
  });
});
