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
  it('offers COM repair only for a verified current-user 64-bit default DLL mapping', () => {
    const com = {
      ...entry,
      category: 'com' as const,
      view: '64',
      valueName: '',
      comRepairable: true,
      keyPath: 'Software\\Classes\\CLSID\\{11111111-1111-4111-8111-111111111111}\\InprocServer32',
    };
    expect(canQuarantine(com)).toBe(true);
    expect(canQuarantine({ ...com, valueType: 'REG_EXPAND_SZ' })).toBe(true);
    for (const changed of [
      { ...com, hive: 'HKLM' },
      { ...com, view: '32' },
      { ...com, view: 'shared' },
      { ...com, comRepairable: false },
      { ...com, valueName: 'ThreadingModel' },
      { ...com, valueType: 'REG_BINARY' },
      { ...com, keyPath: com.keyPath.replace('InprocServer32', 'LocalServer32') },
      { ...com, assessment: { ...entry.assessment, status: 'unknown' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers only verified current-user orphaned Open with suggestions', () => {
    const association = {
      ...entry,
      category: 'file_associations' as const,
      keyPath: 'Software\\Classes\\.rrtest\\OpenWithProgids',
      valueName: 'Example.Document',
      valueType: 'REG_NONE',
      associationRepairable: true,
      assessment: { ...entry.assessment, code: 'progid_missing' },
    };
    expect(canQuarantine(association)).toBe(true);
    expect(canQuarantine({ ...association, valueType: 'REG_SZ' })).toBe(true);
    for (const changed of [
      { ...association, hive: 'HKLM' },
      { ...association, view: '32' },
      { ...association, associationRepairable: false },
      { ...association, valueType: 'REG_EXPAND_SZ' },
      { ...association, keyPath: 'Software\\Classes\\.rrtest' },
      { ...association, keyPath: 'Software\\Classes\\.rrtest\\UserChoice' },
      { ...association, valueName: '' },
      { ...association, assessment: { ...entry.assessment, code: 'progid_registered' } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers backed-up repair for a verified orphaned current-user uninstall entry', () => {
    const uninstall = {
      ...entry,
      category: 'uninstall' as const,
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Example',
      valueName: 'InstallLocation',
      uninstallRepairable: true,
    };
    expect(canQuarantine(uninstall)).toBe(true);
  });
  it('offers repair review for a guarded, missing-target HKCU App Paths default value', () => {
    const appPath = {
      ...entry,
      category: 'app_paths' as const,
      name: 'broken.exe',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\broken.exe',
      valueName: '',
      appPathRepairable: true,
    };
    expect(canQuarantine(appPath)).toBe(true);
  });
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
  it('requires verified App Paths evidence and rejects machine or nested entries', () => {
    const app = {
      ...entry,
      category: 'app_paths' as const,
      name: 'broken.exe',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\broken.exe',
      valueName: '',
      appPathRepairable: true,
    };
    for (const changed of [
      { ...app, appPathRepairable: false },
      { ...app, hive: 'HKLM' },
      { ...app, keyPath: `${app.keyPath}\\child.exe` },
      { ...app, valueName: 'Path' },
      { ...app, view: '32' },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('does not offer uninstall repair for hidden, unverified, machine-wide, or nested entries', () => {
    const uninstall = {
      ...entry,
      category: 'uninstall' as const,
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Example',
      valueName: 'InstallLocation',
      uninstallRepairable: true,
    };
    for (const changed of [
      { ...uninstall, uninstallRepairable: false },
      { ...uninstall, uninstallHidden: true },
      { ...uninstall, hive: 'HKLM' },
      { ...uninstall, view: '32' },
      { ...uninstall, keyPath: `${uninstall.keyPath}\\child` },
      { ...uninstall, valueName: 'UninstallString' },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
});
