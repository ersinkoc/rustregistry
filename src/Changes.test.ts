import { describe, expect, it } from 'vitest';
import { canQuarantine, isQuickCleanCandidate } from './Changes';
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
  it('offers correlated URL metadata in individual and automatic cleaning, preserving namespace and type guards', () => {
    const url: RegistryEntry = {
      ...entry,
      category: 'application_leftovers',
      leftoverRepairable: true,
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\old.exe',
      valueName: 'UseUrl',
      valueType: 'REG_DWORD',
      rawValue: '1',
      assessment: { ...entry.assessment, code: 'application_leftover_candidate' },
    };
    expect(canQuarantine(url)).toBe(true);
    expect(isQuickCleanCandidate(url)).toBe(true);
    expect(
      canQuarantine({
        ...url,
        valueName: 'SupportedProtocols',
        valueType: 'REG_SZ',
        rawValue: 'https:custom+scheme',
      }),
    ).toBe(true);
    for (const changed of [
      { ...url, valueType: 'REG_SZ' },
      { ...url, rawValue: '2' },
      { ...url, hive: 'HKLM' },
      { ...url, valueName: 'DropTarget' },
      { ...url, keyPath: url.keyPath + '\\Nested' },
      { ...url, leftoverRepairable: false },
      { ...url, valueName: 'SupportedProtocols', valueType: 'REG_EXPAND_SZ' },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers a corroborated empty file-type suggestion without granting other scopes or values eligibility', () => {
    const hint = {
      ...entry,
      category: 'application_leftovers',
      keyPath: 'Software\\Classes\\Applications\\old.exe\\SupportedTypes',
      valueName: '.ONE',
      rawValue: '',
      leftoverRepairable: true,
      assessment: { ...entry.assessment, code: 'application_leftover_candidate' },
    } as RegistryEntry;
    expect(canQuarantine(hint)).toBe(true);
    for (const changed of [
      { ...hint, hive: 'HKLM' },
      { ...hint, view: '32' },
      { ...hint, valueName: 'Path' },
      { ...hint, rawValue: 'preserve' },
      { ...hint, valueType: 'REG_NONE' },
      { ...hint, leftoverRepairable: false },
      { ...hint, keyPath: hint.keyPath + '\\Child' },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers correlated leftover search-path cleanup only for exact native user evidence', () => {
    const leftover = {
      ...entry,
      category: 'application_leftovers',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\old.exe',
      valueName: 'Path',
      rawValue: 'C:\\Removed App',
      leftoverRepairable: true,
      assessment: { ...entry.assessment, code: 'application_leftover_candidate' },
    } as unknown as RegistryEntry;
    expect(canQuarantine(leftover)).toBe(true);
    for (const changed of [
      { ...leftover, hive: 'HKLM' },
      { ...leftover, view: '32' },
      { ...leftover, valueName: '' },
      { ...leftover, leftoverRepairable: false },
      { ...leftover, valueType: 'REG_EXPAND_SZ' },
      { ...leftover, keyPath: leftover.keyPath + '\\Child' },
      { ...leftover, assessment: { ...leftover.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers missing current sound assignments only with native guarded evidence', () => {
    const sound = {
      ...entry,
      category: 'sound_events',
      keyPath: 'AppEvents\\Schemes\\Apps\\CustomApp\\CustomEvent\\.Current',
      valueName: '',
      rawValue: 'C:\\Removed\\event.wav',
      soundRepairable: true,
      assessment: { ...entry.assessment, code: 'sound_file_missing' },
    } as unknown as RegistryEntry;
    expect(canQuarantine(sound)).toBe(true);
    for (const changed of [
      { ...sound, hive: 'HKLM' },
      { ...sound, view: '32' },
      { ...sound, soundRepairable: false },
      { ...sound, valueName: 'Metadata' },
      { ...sound, valueType: 'REG_EXPAND_SZ' },
      { ...sound, keyPath: sound.keyPath.replace('.Current', '.Default') },
      { ...sound, assessment: { ...sound.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers font-reference repair only for supported missing current-user mappings', () => {
    const font = {
      ...entry,
      category: 'fonts',
      keyPath: 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts',
      valueName: 'Example Font (TrueType)',
      rawValue: 'C:\\Removed\\font.ttf',
      fileReferenceRepairable: true,
      assessment: { ...entry.assessment, code: 'font_file_missing' },
    } as unknown as RegistryEntry;
    expect(canQuarantine(font)).toBe(true);
    for (const changed of [
      { ...font, hive: 'HKLM' },
      { ...font, view: '32' },
      { ...font, fileReferenceRepairable: false },
      { ...font, valueType: 'REG_EXPAND_SZ' },
      { ...font, keyPath: font.keyPath + '\\Package' },
      { ...font, assessment: { ...font.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers help-reference repair in each explicitly checked machine architecture view', () => {
    for (const view of ['32', '64'])
      for (const root of ['Help', 'HTML Help']) {
        const help = {
          ...entry,
          category: 'help_files',
          hive: 'HKLM',
          view,
          keyPath: `Software\\Microsoft\\Windows\\${root}`,
          valueName: root === 'Help' ? 'manual.hlp' : 'manual.chm',
          rawValue: 'C:\\Removed\\Help',
          fileReferenceRepairable: true,
          assessment: { ...entry.assessment, code: 'help_file_missing' },
        } as unknown as RegistryEntry;
        expect(canQuarantine(help)).toBe(true);
        for (const changed of [
          { ...help, hive: 'HKCU' },
          { ...help, view: 'shared' },
          { ...help, fileReferenceRepairable: false },
          { ...help, valueType: 'REG_EXPAND_SZ' },
          { ...help, keyPath: help.keyPath + '\\Policies' },
        ])
          expect(canQuarantine(changed)).toBe(false);
      }
  });
  it('offers stale MUI cache cleanup and optional history through separate native evidence', () => {
    const cache = {
      ...entry,
      category: 'mui_cache',
      maintenanceRepairable: true,
      keyPath: 'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache',
      valueName: 'C:\\Missing\\app.exe',
      assessment: { ...entry.assessment, code: 'cache_target_missing' },
    } as unknown as RegistryEntry;
    expect(canQuarantine(cache)).toBe(true);
    for (const changed of [
      { ...cache, hive: 'HKLM' },
      { ...cache, view: '32' },
      { ...cache, maintenanceRepairable: false },
      { ...cache, keyPath: `${cache.keyPath}\\Other` },
      { ...cache, assessment: { ...cache.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
    const history = {
      ...cache,
      category: 'usage_history',
      keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
      valueName: 'RunMRU',
      assessment: { ...entry.assessment, status: 'found', code: 'optional_history' },
    } as unknown as RegistryEntry;
    expect(canQuarantine(history)).toBe(true);
    expect(isQuickCleanCandidate(history)).toBe(false);
    expect(isQuickCleanCandidate(cache)).toBe(true);
    expect(
      canQuarantine({ ...history, keyPath: history.keyPath.replace('RunMRU', 'RecentDocs') }),
    ).toBe(false);
  });
  it('offers individual AutoConvertTo recovery only for guarded native current-user references', () => {
    const conversion = {
      ...entry,
      category: 'com_conversions' as const,
      view: '64',
      keyPath: 'Software\\Classes\\CLSID\\{11111111-1111-4111-8111-111111111111}\\AutoConvertTo',
      valueName: '',
      valueType: 'REG_SZ',
      conversionRepairable: true,
      assessment: { ...entry.assessment, code: 'conversion_clsid_missing' },
    };
    expect(canQuarantine(conversion)).toBe(true);
    for (const changed of [
      { ...conversion, hive: 'HKLM' },
      { ...conversion, view: '32' },
      { ...conversion, conversionRepairable: false },
      { ...conversion, valueType: 'REG_EXPAND_SZ' },
      { ...conversion, valueName: 'Other' },
      { ...conversion, keyPath: `${conversion.keyPath}\\nested` },
      { ...conversion, keyPath: conversion.keyPath.replace('AutoConvertTo', 'TreatAs') },
      { ...conversion, assessment: { ...conversion.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers backed-up recovery for guarded folder and all-filesystem menu commands', () => {
    for (const root of ['AllFileSystemObjects', 'Folder']) {
      const menu = {
        ...entry,
        category: 'shell_menus' as const,
        keyPath: `Software\\Classes\\${root}\\shell\\Example.Custom\\command`,
        valueName: '',
        menuRepairable: true,
        menuHidden: false,
      };
      expect(canQuarantine(menu)).toBe(true);
      for (const changed of [
        { ...menu, hive: 'HKLM' },
        { ...menu, view: '64' },
        { ...menu, menuHidden: true },
        { ...menu, menuRepairable: false },
        { ...menu, keyPath: `${menu.keyPath}\\nested` },
      ])
        expect(canQuarantine(changed)).toBe(false);
    }
  });
  it('offers individual TreatAs recovery only for verified native current-user REG_SZ references', () => {
    const redirection = {
      ...entry,
      category: 'com_redirections' as const,
      view: '64',
      keyPath: 'Software\\Classes\\CLSID\\{11111111-1111-4111-8111-111111111111}\\TreatAs',
      valueName: '',
      valueType: 'REG_SZ',
      redirectionRepairable: true,
      assessment: { ...entry.assessment, code: 'redirection_clsid_missing' },
    };
    expect(canQuarantine(redirection)).toBe(true);
    for (const changed of [
      { ...redirection, hive: 'HKLM' },
      { ...redirection, view: '32' },
      { ...redirection, redirectionRepairable: false },
      { ...redirection, valueType: 'REG_EXPAND_SZ' },
      { ...redirection, keyPath: `${redirection.keyPath}\\nested` },
      { ...redirection, valueName: 'Other' },
      { ...redirection, assessment: { ...redirection.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers only guarded visible current-user custom context-menu commands', () => {
    const menu = {
      ...entry,
      category: 'shell_menus' as RegistryEntry['category'],
      keyPath: 'Software\\Classes\\*\\shell\\Example.Custom\\command',
      valueName: '',
      menuRepairable: true,
      menuHidden: false,
    };
    expect(canQuarantine(menu)).toBe(true);
    for (const changed of [
      { ...menu, hive: 'HKLM' },
      { ...menu, view: '64' },
      { ...menu, menuRepairable: false },
      { ...menu, menuHidden: true },
      { ...menu, valueName: 'Named' },
      { ...menu, keyPath: `${menu.keyPath}\\Nested` },
      { ...menu, assessment: { ...menu.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
  it('offers only guarded user application icon references', () => {
    const icon = {
      ...entry,
      category: 'application_icons' as RegistryEntry['category'],
      keyPath: 'Software\\Classes\\Applications\\Example.exe\\DefaultIcon',
      valueName: '',
      rawValue: 'C:\\Missing\\example.ico',
      iconRepairable: true,
    };
    expect(canQuarantine(icon)).toBe(true);
    for (const changed of [
      { ...icon, hive: 'HKLM' },
      { ...icon, view: '32' },
      { ...icon, iconRepairable: false },
      { ...icon, valueName: 'Named' },
      { ...icon, valueType: 'REG_BINARY' },
      { ...icon, keyPath: `${icon.keyPath}\\Nested` },
      { ...icon, assessment: { ...icon.assessment, status: 'found' as const } },
    ])
      expect(canQuarantine(changed)).toBe(false);
  });
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
