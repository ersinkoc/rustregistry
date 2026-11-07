import { describe, expect, it } from 'vitest';
import { filterBackups, type SearchableBackup } from './backups';
const records: SearchableBackup[] = [
  {
    id: '11111111-one',
    name: 'Editor menu',
    registryPath: 'HKCU\\Software\\Classes\\Folder\\shell\\Editor',
    valueName: 'ProgrammaticAccessOnly',
    scope: 'shell_menu',
    state: 'restore_available',
  },
  {
    id: '22222222-two',
    name: 'Legacy redirect',
    registryPath: 'HKCU\\Software\\Classes\\CLSID\\{example}\\TreatAs',
    valueName: '',
    scope: 'com_redirection',
    state: 'original_present',
  },
  {
    id: '33333333-three',
    name: 'Changed application',
    registryPath: 'HKCU\\Software\\Vendor',
    valueName: 'App',
    scope: 'registered_app',
    state: 'conflict',
  },
  {
    id: '44444444-four',
    name: 'Unavailable service',
    registryPath: 'HKLM\\SYSTEM\\Services\\Example',
    valueName: 'Start',
    scope: 'service',
    state: 'unverified',
  },
];
describe('backup discovery filters', () => {
  it('matches name, identifier, registry path, value name and displayed scope case-insensitively', () => {
    for (const query of [
      ' editor MENU ',
      '11111111',
      'Classes\\Folder',
      'programmaticaccessonly',
      'Context-menu visibility',
    ])
      expect(filterBackups(records, query, 'all')).toEqual([records[0]]);
    expect(filterBackups(records, 'COM class redirection', 'all')).toEqual([records[1]]);
  });
  it('combines state and query without offering a conflicting or unverified backup as restorable', () => {
    expect(filterBackups(records, '', 'restore_available')).toEqual([records[0]]);
    expect(filterBackups(records, 'application', 'restore_available')).toEqual([]);
    expect(filterBackups(records, 'application', 'conflict')).toEqual([records[2]]);
    expect(filterBackups(records, '', 'unverified')).toEqual([records[3]]);
    expect(filterBackups(records, '', 'original_present')).toEqual([records[1]]);
  });
  it('clearing filters restores every record in original order without mutating inventory', () => {
    const original = structuredClone(records);
    const result = filterBackups(records, '  ', 'all');
    expect(result).toEqual(records);
    expect(result).not.toBe(records);
    expect(result[0]).toBe(records[0]);
    filterBackups(records, 'missing text', 'conflict');
    expect(records).toEqual(original);
    expect(filterBackups([], 'anything', 'all')).toEqual([]);
  });
});
