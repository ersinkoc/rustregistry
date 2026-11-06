import { describe, expect, it } from 'vitest';
import { canQuarantine } from './Changes';
import type { RegistryEntry } from './model';

const entry: RegistryEntry = {
  id: 'example',
  name: 'Example',
  category: 'startup',
  hive: 'HKCU',
  keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  view: 'shared',
  valueName: 'Example',
  valueType: 'REG_SZ',
  rawValue: 'C:\\Missing\\app.exe',
  publisher: null,
  version: null,
  assessment: {
    status: 'review',
    code: 'target_missing',
    explanation: 'Missing',
    target: 'C:\\Missing\\app.exe',
  },
};
describe('protected change availability', () => {
  it('offers review for a named, missing-target HKCU Run value', () => {
    expect(canQuarantine(entry)).toBe(true);
    expect(canQuarantine({ ...entry, valueType: 'REG_EXPAND_SZ' })).toBe(true);
  });
  it('does not offer changes to other scopes or uncertain targets', () => {
    for (const changed of [
      { ...entry, hive: 'HKLM' },
      { ...entry, keyPath: `${entry.keyPath}Once` },
      { ...entry, view: '32' },
      { ...entry, valueName: '' },
      { ...entry, valueType: 'REG_BINARY' },
      { ...entry, assessment: { ...entry.assessment, status: 'found' as const } },
      { ...entry, assessment: { ...entry.assessment, code: 'path_inaccessible' } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
});
