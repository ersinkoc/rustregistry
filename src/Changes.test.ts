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
  it('offers only guarded native current-user orphaned proxy references', () => {
    const mapping = {
      ...entry,
      category: 'com_proxies' as RegistryEntry['category'],
      keyPath:
        'Software\\Classes\\Interface\\{11111111-1111-4111-8111-111111111111}\\ProxyStubClsid32',
      view: '64',
      valueName: '',
      rawValue: '{22222222-2222-4222-8222-222222222222}',
      proxyRepairable: true,
      assessment: { ...entry.assessment, code: 'proxy_clsid_missing' },
    };
    expect(canQuarantine(mapping)).toBe(true);
    for (const changed of [
      { ...mapping, hive: 'HKLM' },
      { ...mapping, view: '32' },
      { ...mapping, view: 'shared' },
      { ...mapping, proxyRepairable: false },
      { ...mapping, valueName: 'Named' },
      { ...mapping, valueType: 'REG_DWORD' },
      { ...mapping, rawValue: '%CLSID%' },
      { ...mapping, keyPath: `${mapping.keyPath}\\Nested` },
      { ...mapping, assessment: { ...mapping.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers only guarded native current-user interface type-library references', () => {
    const mapping = {
      ...entry,
      category: 'interfaces' as RegistryEntry['category'],
      keyPath: 'Software\\Classes\\Interface\\{11111111-1111-4111-8111-111111111111}\\TypeLib',
      view: '64',
      valueName: '',
      rawValue: '{22222222-2222-4222-8222-222222222222}',
      interfaceRepairable: true,
      assessment: { ...entry.assessment, code: 'interface_library_missing' },
    };
    expect(canQuarantine(mapping)).toBe(true);
    for (const changed of [
      { ...mapping, hive: 'HKLM' },
      { ...mapping, view: '32' },
      { ...mapping, view: 'shared' },
      { ...mapping, interfaceRepairable: false },
      { ...mapping, valueName: 'Version' },
      { ...mapping, valueType: 'REG_DWORD' },
      { ...mapping, rawValue: '%LIBID%' },
      { ...mapping, keyPath: `${mapping.keyPath}\\Nested` },
      { ...mapping, assessment: { ...mapping.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers only guarded current-user orphaned COM ProgID mappings', () => {
    const mapping = {
      ...entry,
      category: 'prog_ids' as const,
      keyPath: 'Software\\Classes\\Example.Component.1\\CLSID',
      valueName: '',
      rawValue: '{11111111-1111-4111-8111-111111111111}',
      progIdRepairable: true,
      assessment: { ...entry.assessment, code: 'clsid_missing' },
    };
    expect(canQuarantine(mapping)).toBe(true);
    for (const changed of [
      { ...mapping, hive: 'HKLM' },
      { ...mapping, view: '32' },
      { ...mapping, progIdRepairable: false },
      { ...mapping, valueName: 'NamedValue' },
      { ...mapping, valueType: 'REG_DWORD' },
      { ...mapping, rawValue: '%CLSID%' },
      {
        ...mapping,
        keyPath: mapping.keyPath.replace('Example.Component.1', 'Example_Component.1'),
      },
      { ...mapping, keyPath: `${mapping.keyPath}\\Nested` },
      { ...mapping, assessment: { ...mapping.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers only guarded neutral current-user win64 type library mappings', () => {
    const library = {
      ...entry,
      category: 'type_libraries' as const,
      keyPath: 'Software\\Classes\\TypeLib\\{11111111-1111-4111-8111-111111111111}\\1.0\\0\\win64',
      valueName: '',
      typeLibraryRepairable: true,
    };
    expect(canQuarantine(library)).toBe(true);
    for (const changed of [
      { ...library, hive: 'HKLM' },
      { ...library, view: '32' },
      { ...library, typeLibraryRepairable: false },
      { ...library, valueName: 'NamedValue' },
      { ...library, keyPath: library.keyPath.replace('win64', 'win32') },
      { ...library, keyPath: library.keyPath.replace('\\0\\win64', '\\409\\win64') },
      { ...library, keyPath: `${library.keyPath}\\Nested` },
      { ...library, valueType: 'REG_DWORD' },
      { ...library, assessment: { ...entry.assessment, status: 'unknown' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers only verified current-user orphaned registered applications', () => {
    const registration = {
      ...entry,
      category: 'registered_applications' as const,
      keyPath: 'Software\\RegisteredApplications',
      valueName: 'Example.Player',
      valueType: 'REG_SZ',
      rawValue: 'Software\\Example\\Player\\Capabilities',
      registeredAppRepairable: true,
      assessment: { ...entry.assessment, code: 'capabilities_missing' },
    };
    expect(canQuarantine(registration)).toBe(true);
    for (const changed of [
      { ...registration, hive: 'HKLM' },
      { ...registration, view: '32' },
      { ...registration, registeredAppRepairable: false },
      { ...registration, valueType: 'REG_EXPAND_SZ' },
      { ...registration, keyPath: `${registration.keyPath}\\Nested` },
      { ...registration, valueName: '' },
      { ...registration, assessment: { ...registration.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers shared DLL repair only for verified zero-count machine-wide 64-bit references', () => {
    const shared: RegistryEntry = {
      ...entry,
      category: 'shared_dlls',
      hive: 'HKLM',
      view: '64',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs',
      valueName: 'C:\\RustRegistryMissing\\zero.dll',
      valueType: 'REG_DWORD',
      rawValue: 'Reference count: 0',
      sharedDllRepairable: true,
    };
    expect(canQuarantine(shared)).toBe(true);
    for (const changed of [
      { ...shared, sharedDllRepairable: false },
      { ...shared, hive: 'HKCU' },
      { ...shared, view: '32' },
      { ...shared, valueType: 'REG_SZ' },
      { ...shared, rawValue: 'Reference count: 1' },
      { ...shared, valueName: 'relative.dll' },
      { ...shared, keyPath: `${shared.keyPath}\\Nested` },
      { ...shared, assessment: { ...entry.assessment, status: 'unknown' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers backed-up application suggestion repair only for verified current-user open commands', () => {
    const application: RegistryEntry = {
      ...entry,
      category: 'application_commands',
      valueName: '',
      applicationRepairable: true,
      keyPath: 'Software\\Classes\\Applications\\Example.exe\\shell\\open\\command',
    };
    expect(canQuarantine(application)).toBe(true);
    for (const changed of [
      { ...application, applicationRepairable: false },
      { ...application, applicationHidden: true },
      { ...application, hive: 'HKLM' },
      { ...application, view: '64' },
      { ...application, valueName: 'NoOpenWith' },
      { ...application, valueType: 'REG_BINARY' },
      { ...application, keyPath: `${application.keyPath}\\Nested` },
      { ...application, assessment: { ...entry.assessment, status: 'unknown' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers service repair only with verified fixed-scope SCM configuration access', () => {
    const service = {
      ...entry,
      category: 'services' as const,
      hive: 'HKLM',
      keyPath: 'SYSTEM\\CurrentControlSet\\Services\\ExampleService',
      valueName: 'ImagePath',
      serviceRepairable: true,
    };
    expect(canQuarantine(service)).toBe(true);
    for (const changed of [
      { ...service, serviceRepairable: false },
      { ...service, hive: 'HKCU' },
      { ...service, view: '64' },
      { ...service, valueName: 'Start' },
      { ...service, keyPath: `${service.keyPath}\\Parameters` },
      { ...service, assessment: { ...entry.assessment, status: 'unknown' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
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
      { ...com, keyPath: com.keyPath.replace('InprocServer32', 'TreatAs') },
      { ...com, assessment: { ...entry.assessment, status: 'unknown' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('includes verified COM handlers and local servers in cleaning while keeping application commands read-only', () => {
    for (const server of ['InprocHandler32', 'LocalServer32']) {
      const mapping: RegistryEntry = {
        ...entry,
        category: 'com',
        view: '64',
        valueName: '',
        comRepairable: true,
        keyPath: `Software\\Classes\\CLSID\\{11111111-1111-4111-8111-111111111111}\\${server}`,
      };
      expect(canQuarantine(mapping)).toBe(true);
      for (const changed of [
        { ...mapping, comRepairable: false },
        { ...mapping, hive: 'HKLM' },
        { ...mapping, view: '32' },
        { ...mapping, keyPath: `${mapping.keyPath}\\Nested` },
      ])
        expect(canQuarantine(changed)).toBe(false);
    }
    expect(
      canQuarantine({
        ...entry,
        category: 'application_commands',
        keyPath: 'Software\\Classes\\Applications\\missing.exe\\shell\\open\\command',
      }),
    ).toBe(false);
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
