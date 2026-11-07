import { useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from '@tauri-apps/api/core';
import {
  ArchiveRestore,
  Clock3,
  Info,
  LockKeyhole,
  RotateCw,
  ShieldCheck,
  TriangleAlert,
  X,
} from 'lucide-react';
import type { RegistryEntry } from './model';

export interface ChangePlan {
  token: string;
  action: 'quarantine' | 'restore';
  name: string;
  valueName: string;
  registryPath: string;
  registryView?: string;
  originalValue: string;
  valueType: string;
  expiresAt: number;
  scope:
    | 'startup'
    | 'app_path'
    | 'uninstall'
    | 'association'
    | 'com'
    | 'service'
    | 'application'
    | 'shared_dll'
    | 'registered_app'
    | 'type_library'
    | 'prog_id'
    | 'interface'
    | 'com_proxy';
  preservedValues: number;
  uninstallCommand?: string | null;
  componentWasPresent: boolean;
  serviceExecutable?: string | null;
  applicationCommand?: string | null;
}
export interface ChangeResult {
  backupId: string;
  action: string;
  message: string;
}
interface Backup {
  id: string;
  name: string;
  valueName: string;
  createdAt: number;
  state: 'restore_available' | 'original_present' | 'conflict' | 'unverified';
  note: string;
  scope:
    | 'startup'
    | 'app_path'
    | 'uninstall'
    | 'association'
    | 'com'
    | 'service'
    | 'application'
    | 'shared_dll'
    | 'registered_app'
    | 'type_library'
    | 'prog_id'
    | 'interface'
    | 'com_proxy';
  registryPath: string;
  registryView?: string;
}
interface Inventory {
  storagePath: string;
  backups: Backup[];
  warnings: string[];
}

export function canQuarantine(entry: RegistryEntry) {
  if (entry.category === 'com_proxies') {
    const mapping =
      /^software\\classes\\interface\\\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\proxystubclsid32$/i.exec(
        entry.keyPath,
      );
    return Boolean(
      mapping &&
      entry.hive === 'HKCU' &&
      entry.view === '64' &&
      entry.proxyRepairable === true &&
      entry.valueName === '' &&
      ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'proxy_clsid_missing' &&
      /^\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}$/i.test(entry.rawValue),
    );
  }

  if (entry.category === 'interfaces') {
    const mapping =
      /^software\\classes\\interface\\\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\typelib$/i.exec(
        entry.keyPath,
      );
    return Boolean(
      mapping &&
      entry.hive === 'HKCU' &&
      entry.view === '64' &&
      entry.interfaceRepairable === true &&
      entry.valueName === '' &&
      ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'interface_library_missing' &&
      /^\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}$/i.test(entry.rawValue),
    );
  }

  if (entry.category === 'prog_ids') {
    const mapping = /^software\\classes\\([a-z][a-z0-9]*(?:\.[a-z0-9]+)+)\\clsid$/i.exec(
      entry.keyPath,
    );
    return Boolean(
      mapping &&
      mapping[1].length <= 39 &&
      entry.hive === 'HKCU' &&
      entry.view === 'shared' &&
      entry.progIdRepairable === true &&
      entry.valueName === '' &&
      ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'clsid_missing' &&
      /^\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}$/i.test(entry.rawValue),
    );
  }

  if (entry.category === 'type_libraries')
    return (
      entry.hive === 'HKCU' &&
      entry.view === 'shared' &&
      entry.typeLibraryRepairable === true &&
      entry.valueName === '' &&
      ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'target_missing' &&
      /^software\\classes\\typelib\\\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\[a-f0-9]{1,4}\.[a-f0-9]{1,4}\\0\\win64$/i.test(
        entry.keyPath,
      )
    );

  if (entry.category === 'registered_applications')
    return (
      entry.hive === 'HKCU' &&
      entry.view === 'shared' &&
      entry.registeredAppRepairable === true &&
      entry.keyPath.toLowerCase() === 'software\\registeredapplications' &&
      entry.valueType === 'REG_SZ' &&
      Boolean(entry.valueName) &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'capabilities_missing'
    );

  if (entry.category === 'shared_dlls')
    return (
      entry.hive === 'HKLM' &&
      entry.view === '64' &&
      entry.sharedDllRepairable === true &&
      entry.keyPath.toLowerCase() === 'software\\microsoft\\windows\\currentversion\\shareddlls' &&
      entry.valueType === 'REG_DWORD' &&
      entry.rawValue === 'Reference count: 0' &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'target_missing' &&
      /^[a-z]:\\[^%~/:*?"<>|]+\.dll$/i.test(entry.valueName)
    );
  if (entry.category === 'application_commands')
    return (
      entry.hive === 'HKCU' &&
      entry.view === 'shared' &&
      entry.valueName === '' &&
      entry.applicationRepairable === true &&
      entry.applicationHidden !== true &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'target_missing' &&
      ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
      /^software\\classes\\applications\\[a-z0-9][^\\/:*?"<>|\x00-\x1f\x7f-\uffff]*\.exe\\shell\\open\\command$/i.test(
        entry.keyPath,
      )
    );
  if (entry.category === 'services')
    return (
      ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
      entry.hive === 'HKLM' &&
      entry.view === 'shared' &&
      entry.valueName === 'ImagePath' &&
      entry.serviceRepairable === true &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'target_missing' &&
      /^system\\currentcontrolset\\services\\[a-z0-9][a-z0-9_.-]{0,255}$/i.test(entry.keyPath)
    );

  if (entry.category === 'com')
    return (
      entry.hive === 'HKCU' &&
      entry.view === '64' &&
      entry.comRepairable === true &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'target_missing' &&
      entry.valueName === '' &&
      ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
      /^software\\classes\\clsid\\\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\(inprocserver32|inprochandler32|localserver32)$/i.test(
        entry.keyPath,
      )
    );

  if (entry.category === 'file_associations')
    return (
      entry.hive === 'HKCU' &&
      entry.view === 'shared' &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'progid_missing' &&
      entry.associationRepairable === true &&
      ['REG_NONE', 'REG_SZ'].includes(entry.valueType) &&
      /^software\\classes\\\.[a-z0-9_+-]+\\openwithprogids$/i.test(entry.keyPath) &&
      /^[a-z][a-z0-9._-]*\.[a-z0-9_-]+$/i.test(entry.valueName)
    );

  return (
    entry.hive === 'HKCU' &&
    entry.view === 'shared' &&
    entry.assessment.status === 'review' &&
    entry.assessment.code === 'target_missing' &&
    ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
    ((entry.category === 'startup' &&
      entry.keyPath.toLowerCase() === 'software\\microsoft\\windows\\currentversion\\run' &&
      Boolean(entry.valueName)) ||
      (entry.category === 'app_paths' &&
        entry.appPathRepairable === true &&
        entry.valueName === '' &&
        /^software\\microsoft\\windows\\currentversion\\app paths\\[^\\/:*?"<>|]+\.exe$/i.test(
          entry.keyPath,
        )) ||
      (entry.category === 'uninstall' &&
        entry.uninstallRepairable === true &&
        entry.uninstallHidden !== true &&
        entry.valueName === 'InstallLocation' &&
        /^software\\microsoft\\windows\\currentversion\\uninstall\\[^\\/:*?"<>|]+$/i.test(
          entry.keyPath,
        )))
  );
}

export function ChangeConfirmation({
  plan,
  busy,
  onCancel,
  onConfirm,
}: {
  plan: ChangePlan;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [agreed, setAgreed] = useState(false);
  const [clock, setClock] = useState(Date.now());
  const restore = plan.action === 'restore';
  const appPath = plan.scope === 'app_path';
  const uninstall = plan.scope === 'uninstall';
  const association = plan.scope === 'association';
  const com = plan.scope === 'com';
  const comLocal = com && /\\LocalServer32$/i.test(plan.registryPath);
  const comServer = plan.registryPath.split('\\').at(-1);
  const comLabel = comLocal
    ? 'COM server command'
    : comServer === 'InprocHandler32'
      ? 'COM handler mapping'
      : 'COM DLL mapping';
  const service = plan.scope === 'service';
  const application = plan.scope === 'application';
  const sharedDll = plan.scope === 'shared_dll';
  const registeredApp = plan.scope === 'registered_app';
  const typeLibrary = plan.scope === 'type_library';
  const progId = plan.scope === 'prog_id';
  const comInterface = plan.scope === 'interface';
  const comProxy = plan.scope === 'com_proxy';
  const expired = clock >= plan.expiresAt;
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => {
      clearInterval(timer);
      dialog?.close();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className="change-dialog"
      aria-labelledby="change-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <div className="detail-top">
        <span className="eyebrow">REVIEW A SINGLE CHANGE</span>
        <button
          className="icon-button"
          disabled={busy}
          aria-label="Cancel change"
          onClick={onCancel}
        >
          <X size={19} />
        </button>
      </div>
      <div className="detail-symbol review">
        {restore ? <ArchiveRestore size={27} /> : <ShieldCheck size={27} />}
      </div>
      <h2 id="change-title">
        {comProxy
          ? restore
            ? 'Restore COM proxy reference?'
            : 'Disable orphaned COM proxy reference?'
          : comInterface
            ? restore
              ? 'Restore interface TypeLib reference?'
              : 'Disable orphaned interface TypeLib reference?'
            : progId
              ? restore
                ? 'Restore COM ProgID mapping?'
                : 'Disable orphaned COM ProgID mapping?'
              : typeLibrary
                ? restore
                  ? 'Restore type library mapping?'
                  : 'Disable missing type library mapping?'
                : registeredApp
                  ? restore
                    ? 'Restore application registration?'
                    : 'Remove orphaned application registration?'
                  : sharedDll
                    ? restore
                      ? 'Restore shared DLL reference?'
                      : 'Remove zero-count shared DLL reference?'
                    : application
                      ? restore
                        ? 'Restore application suggestion?'
                        : 'Hide broken application suggestion?'
                      : service
                        ? restore
                          ? 'Restore service startup?'
                          : 'Disable this missing-target service?'
                        : com
                          ? restore
                            ? `Restore ${comLabel}?`
                            : `Repair broken ${comLabel}?`
                          : association
                            ? restore
                              ? 'Restore Open with suggestion?'
                              : 'Repair orphaned file association?'
                            : uninstall
                              ? restore
                                ? 'Restore uninstall entry visibility?'
                                : 'Repair orphaned uninstall entry?'
                              : appPath
                                ? restore
                                  ? 'Restore application path?'
                                  : 'Repair broken application path?'
                                : restore
                                  ? 'Restore startup entry?'
                                  : 'Disable this startup entry?'}
      </h2>
      <p className="change-intro">
        {comProxy
          ? restore
            ? 'Restore the exact original proxy CLSID only while its default remains absent, the class is still absent from both hives and architecture views, and every TypeLib, description, structure, and machine counterpart check matches.'
            : 'After a verified backup, remove only this current-user 64-bit interface’s orphaned ProxyStubClsid32 default reference. TypeLib and Version metadata, keys, 32-bit mappings, files, and permissions are preserved. No proxy is loaded or activated.'
          : comInterface
            ? restore
              ? 'Restore the exact original TypeLib reference only while it remains absent, the library remains absent from both hives, and the interface metadata and machine counterpart checks still match.'
              : 'After a verified backup, only this current-user 64-bit interface’s orphaned TypeLib default reference is removed. Version and proxy metadata, keys, 32-bit mappings, files, and permissions are preserved. No library is loaded or COM object activated.'
            : progId
              ? restore
                ? 'Restore the exact original CLSID mapping only while its value remains absent, its target class is still absent from both user/machine 32/64-bit views, and every description and fallback check still matches.'
                : 'The referenced COM class is absent from both hives and both architecture views. After a verified backup, only this current-user ProgID’s default CLSID mapping is removed. Keys, descriptions, class registrations, default application selections, and files are preserved. No COM object is activated.'
              : typeLibrary
                ? restore
                  ? 'Restore the exact original win64 mapping only while its value is absent, its file remains missing, and every guarded registration and fallback check still matches.'
                  : 'The literal local win64 library file is missing. After a verified backup, only this default mapping value is removed. The library keys, win32 mappings, version and locale information, help metadata, and permissions are preserved. No library is loaded, registered, or unregistered.'
                : registeredApp
                  ? restore
                    ? 'Restore the exact original application name and Capabilities path only while the value is absent, the target remains missing, and no machine counterpart exists.'
                    : 'This current-user registration points to a missing Capabilities key. After a verified backup, only this named RegisteredApplications value is removed. Default application selections, UserChoice, ProgIDs, Capabilities keys, commands, files, and permissions are preserved.'
                  : sharedDll
                    ? restore
                      ? 'This restores the exact original DWORD zero only if the value is still absent and the local DLL remains missing. A new counter, changed key structure, or reappearing file blocks restore.'
                      : 'The local DLL was not found and this reference count is exactly zero. After a verified backup, only this named registry value is removed. A zero count does not establish all application ownership; review the exact path. Positive counters and DLL files are preserved.'
                    : application
                      ? restore
                        ? 'This removes the backed-up NoOpenWith flag only when all guarded application metadata and the original command still match. The application may appear in optional suggestions again.'
                        : 'The executable in this simple open command is missing. After a verified backup, only an empty NoOpenWith flag is added to the application registration. The exact open command, keys, and default application selections are preserved.'
                      : service
                        ? restore
                          ? 'This restores the original Manual startup type through Windows Service Control Manager. The service remains stopped. Its executable, account, permissions, and configuration must still match the backup.'
                          : 'This stopped, independent LocalService registration points to a missing executable. After a verified backup, only its startup type changes from Manual to Disabled through Windows Service Control Manager. No service is started, stopped, or deleted.'
                        : com
                          ? restore
                            ? `This restores the exact original 64-bit ${comLocal ? 'server command' : 'DLL mapping'}. Applications may use it through COM later. The class and server metadata must still match the backup.`
                            : `The explicit local ${comLocal ? 'executable' : 'DLL'} is missing. After a verified backup, only the default ${comServer} value is removed. The registration keys and permissions are preserved; no COM object is activated and no command is run.`
                          : association
                            ? restore
                              ? 'This restores the exact original Open with suggestion only if its guarded metadata is unchanged. Default application selections and UserChoice remain untouched.'
                              : 'This optional Open with suggestion points to an application registration missing from both user and machine Classes roots. A verified backup is saved before removing only this suggestion. It does not choose a replacement application or repair missing files.'
                            : uninstall
                              ? restore
                                ? 'This restores the original visibility flag only if every other registry value still matches the backup. No installer or uninstaller will be run.'
                                : 'The installation folder and local uninstall executable are both missing. After a full verified backup, this sets SystemComponent=1 to hide the orphaned listing. The registration key and its permissions stay in place.'
                              : appPath
                                ? restore
                                  ? 'This restores the exact original executable mapping. The existing key and all other metadata must still match the backup.'
                                  : 'The explicit local executable target is missing. This removes only the broken default mapping after saving a verified backup. It does not guess a replacement location.'
                                : restore
                                  ? 'This puts the exact original value back into your startup list. Its command may run at your next sign-in.'
                                  : 'The local target is currently missing. After saving and verifying a backup, RustRegistry will remove only this value from your startup list.'}
      </p>
      <dl className="detail-fields">
        <div className="full-field">
          <dt>Entry</dt>
          <dd>{plan.name}</dd>
        </div>
        <div className="full-field">
          <dt>Registry path</dt>
          <dd className="code-field">{plan.registryPath}</dd>
        </div>
        {(com || sharedDll || typeLibrary || progId || comInterface || comProxy) && (
          <div className="full-field">
            <dt>Registry view</dt>
            <dd>
              {progId ? (
                'Shared ProgID · target checked in both hives and architecture views'
              ) : typeLibrary ? (
                'Shared registry · win64 library · current user'
              ) : (
                <>
                  {plan.registryView} bit · {sharedDll ? 'machine-wide' : 'current user'}
                </>
              )}
            </dd>
          </div>
        )}
        <div>
          <dt>Value name</dt>
          <dd className={sharedDll ? 'code-field' : undefined}>{plan.valueName || '(Default)'}</dd>
        </div>
        <div>
          <dt>Value type</dt>
          <dd className="mono">{plan.valueType}</dd>
        </div>
        <div className="full-field">
          <dt>
            {comProxy
              ? 'Exact original proxy CLSID reference'
              : comInterface
                ? 'Exact original TypeLib reference'
                : progId
                  ? 'Exact original CLSID reference'
                  : typeLibrary
                    ? 'Exact original type library file path'
                    : registeredApp
                      ? 'Exact original Capabilities registry path'
                      : sharedDll
                        ? 'Original reference count'
                        : application
                          ? 'Original NoOpenWith flag'
                          : service
                            ? 'Original startup type'
                            : com
                              ? comLocal
                                ? 'Exact original COM server command'
                                : 'Exact original COM DLL path'
                              : association
                                ? 'Original suggestion data'
                                : uninstall
                                  ? 'Original installation folder'
                                  : appPath
                                    ? 'Exact original executable path'
                                    : 'Exact original command'}
          </dt>
          <dd className="code-field">{plan.originalValue}</dd>
        </div>
      </dl>
      {sharedDll && (
        <p className="change-intro">
          Existing Windows registry write access is required. The app does not elevate automatically
          or change permissions. Only the 64-bit view is changed; other values and the 32-bit view
          stay intact. No DLL is loaded, unregistered, replaced, or deleted.
        </p>
      )}
      {application && (
        <>
          <dl className="detail-fields">
            <div className="full-field">
              <dt>Original open command · preserved, never executed</dt>
              <dd className="code-field">{plan.applicationCommand}</dd>
            </div>
            <div className="full-field">
              <dt>NoOpenWith change</dt>
              <dd>{restore ? 'Empty REG_SZ → absent' : 'Absent → empty REG_SZ'}</dd>
            </div>
          </dl>
          <p className="change-intro">
            All {plan.preservedValues} original values are backed up. Explicit Open with lists can
            still show this application. This flag also limits recent-file Jump List tracking for
            unregistered file types. It does not repair missing files or disable the open command.
          </p>
        </>
      )}
      {service && (
        <>
          <dl className="detail-fields uninstall-evidence">
            <div className="full-field">
              <dt>Executable command · never executed</dt>
              <dd className="code-field">{plan.serviceExecutable}</dd>
            </div>
            <div className="full-field">
              <dt>Startup type change</dt>
              <dd>{restore ? '4 (Disabled) → 3 (Manual)' : '3 (Manual) → 4 (Disabled)'}</dd>
            </div>
          </dl>
          <p className="change-intro">
            The backup includes {plan.preservedValues} registry/security value(s) and the SCM
            configuration. Windows configuration access is required. SCM updates are rechecked
            before and after; avoid concurrent service configuration changes.
          </p>
        </>
      )}
      {uninstall && (
        <>
          <dl className="detail-fields uninstall-evidence">
            <div className="full-field">
              <dt>Original uninstall command · never executed</dt>
              <dd className="code-field">{plan.uninstallCommand}</dd>
            </div>
            <div className="full-field">
              <dt>SystemComponent change</dt>
              <dd>
                {restore
                  ? `1 → ${plan.componentWasPresent ? '0' : 'absent'}`
                  : `${plan.componentWasPresent ? '0' : 'absent'} → 1`}
              </dd>
            </div>
          </dl>
          <p className="change-intro">
            All {plan.preservedValues} original registry values are included in the backup. Only the
            visibility flag changes. The record stays in the registry and in RustRegistry’s
            inventory.
          </p>
        </>
      )}
      {com && (
        <p className="change-intro">
          The COM class, {comServer} key, and {plan.preservedValues} other metadata value(s) remain
          in place. Alternative activation keys, changed metadata, or a same-view machine
          registration block repair and restore.
        </p>
      )}
      {association && (
        <p className="change-intro">
          The extension key, {plan.preservedValues} other suggestion(s), and all default selections
          stay in place. A changed selection, new application registration, or changed metadata
          blocks the operation.
        </p>
      )}
      {appPath && (
        <p className="change-intro">
          The registry key and {plan.preservedValues} other value(s), including any Path metadata,
          stay in place. Changed metadata or a newly populated default value blocks restore.
        </p>
      )}
      <div className="change-guarantee">
        <LockKeyhole size={18} />
        <p>
          {comProxy
            ? 'The backup preserves exact proxy mapping bytes and all supported description, TypeLib, and Version metadata. A new class in any checked view, machine counterpart, changed values or structure, or missing keys blocks repair and restore.'
            : comInterface
              ? 'The backup preserves exact mapping bytes and all supported description, Version, and proxy metadata. New libraries, machine counterparts, changed values or structure, and missing keys block changes.'
              : progId
                ? 'A separate verified backup preserves the original mapping type/bytes and description. A class appearing in any checked view, a same-named machine ProgID, changed metadata, or missing keys blocks repair and restore.'
                : typeLibrary
                  ? 'A separate verified backup preserves the original mapping type and bytes and the supported registration metadata. New files, machine counterparts, modified metadata, or missing keys block both repair and restore.'
                  : registeredApp
                    ? 'A separate verified backup preserves the exact original REG_SZ bytes. New registrations, reappearing Capabilities, registry links, or changed evidence block repair and restore.'
                    : sharedDll
                      ? 'A verified backup preserves the original DWORD type and all four bytes. Repair and restore both recheck that the target is missing; no key or file is recreated.'
                      : application
                        ? 'Only suggestion visibility changes. The original open command, default application selections, registry keys, files, and permissions are preserved.'
                        : service
                          ? 'No executable path, service account, permissions, or files are changed. Restore does not start the service; a later explicit start can run its configured executable.'
                          : com
                            ? 'No DLL is loaded or registered, no COM object is activated, no command is run, and no key, file, or permission is changed. A verified backup is required before removing this one value.'
                            : association
                              ? 'Only this named suggestion can change. No key, default application selection, UserChoice value, application file, or permission is changed.'
                              : uninstall
                                ? 'A full verified value backup is required. Any changed metadata blocks repair or restore. Application files and key permissions are never changed.'
                                : restore
                                  ? 'Restore is blocked if any value with this name already exists. Existing values are never overwritten.'
                                  : 'No key or application file will be deleted. A verified backup is required before this one registry value can be removed.'}
        </p>
      </div>
      <label className="confirmation-check">
        <input
          type="checkbox"
          checked={agreed}
          disabled={busy || expired}
          onChange={(event) => setAgreed(event.target.checked)}
        />
        <span>
          {comProxy
            ? 'I reviewed this exact interface and proxy CLSID and understand the reference change.'
            : comInterface
              ? 'I reviewed this exact interface and TypeLib reference and understand the mapping change.'
              : progId
                ? 'I reviewed this exact ProgID and CLSID reference and understand the mapping change.'
                : typeLibrary
                  ? 'I reviewed this exact library path and understand that only its win64 mapping changes.'
                  : registeredApp
                    ? 'I reviewed this exact application name and Capabilities path and understand this registration change.'
                    : sharedDll
                      ? 'I reviewed this exact DLL path and understand that only its zero-count registry reference changes.'
                      : application
                        ? 'I reviewed the original command and understand the suggestion visibility change.'
                        : service
                          ? 'I reviewed this service and understand that only its startup type changes.'
                          : com
                            ? 'I reviewed this exact 64-bit COM mapping and understand the change.'
                            : association
                              ? 'I reviewed this exact suggestion and understand the file association change.'
                              : uninstall
                                ? 'I reviewed this entry and understand this only changes listing visibility.'
                                : appPath
                                  ? 'I reviewed this exact value and understand the application path change.'
                                  : 'I reviewed this exact value and understand the startup change.'}
        </span>
      </label>
      {expired && (
        <p role="alert" className="amber">
          This review expired. Cancel and review the change again.
        </p>
      )}
      <div className="change-buttons">
        <button className="secondary-button" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
        <button
          className="primary-button"
          disabled={!agreed || busy || expired}
          onClick={onConfirm}
        >
          {busy ? <RotateCw className="spin" size={16} /> : <ShieldCheck size={16} />}
          {busy
            ? 'Applying…'
            : comProxy
              ? restore
                ? 'Restore proxy reference'
                : 'Back up & disable proxy reference'
              : comInterface
                ? restore
                  ? 'Restore TypeLib reference'
                  : 'Back up & disable TypeLib reference'
                : progId
                  ? restore
                    ? 'Restore ProgID mapping'
                    : 'Back up & disable ProgID mapping'
                  : typeLibrary
                    ? restore
                      ? 'Restore library mapping'
                      : 'Back up & disable library mapping'
                    : registeredApp
                      ? restore
                        ? 'Restore registration'
                        : 'Back up & remove registration'
                      : sharedDll
                        ? restore
                          ? 'Restore zero-count reference'
                          : 'Back up & remove reference'
                        : application
                          ? restore
                            ? 'Restore suggestion visibility'
                            : 'Back up & hide suggestion'
                          : service
                            ? restore
                              ? 'Restore Manual startup'
                              : 'Back up & disable service'
                            : com
                              ? restore
                                ? 'Restore original value'
                                : 'Back up & disable mapping'
                              : association
                                ? restore
                                  ? 'Restore original value'
                                  : 'Back up & remove suggestion'
                                : uninstall
                                  ? restore
                                    ? 'Restore original visibility'
                                    : 'Back up & hide entry'
                                  : restore
                                    ? 'Restore original value'
                                    : appPath
                                      ? 'Back up & repair'
                                      : 'Back up & disable'}
        </button>
      </div>
    </dialog>
  );
}

export function BackupsPanel({
  revision,
  busy,
  onRestore,
}: {
  revision: number;
  busy: boolean;
  onRestore: (id: string) => void;
}) {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    if (!isTauri()) return;
    setLoading(true);
    invoke<Inventory>('list_backups')
      .then((result) => {
        if (active) {
          setInventory(result);
          setError('');
        }
      })
      .catch((cause) => {
        if (active) setError(String(cause));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [revision, refresh]);
  return (
    <>
      <div className="coverage-intro">
        <div className="coverage-symbol">
          <ArchiveRestore size={28} />
        </div>
        <div>
          <h2>A way back, before every change.</h2>
          <p>
            Original registry bytes are saved locally before a value is changed. Backups survive app
            restarts. Restore checks the live value and never overwrites a conflict.
          </p>
        </div>
      </div>
      {error && (
        <div className="notice error-notice" role="alert">
          <TriangleAlert size={17} />
          <p>{error}</p>
        </div>
      )}
      {inventory?.warnings.map((warning, index) => (
        <div key={index} className="notice error-notice">
          <TriangleAlert size={17} />
          <p>{warning}</p>
        </div>
      ))}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>
              Local backups <span className="count-chip">{inventory?.backups.length ?? 0}</span>
            </h2>
            <p>
              State is checked against the original registration and, for services, the live Windows
              configuration.
            </p>
          </div>
          <button
            className="secondary-button"
            disabled={loading || busy || !isTauri()}
            onClick={() => setRefresh((value) => value + 1)}
          >
            <RotateCw size={14} className={loading ? 'spin' : ''} />
            Refresh
          </button>
        </div>
        {!inventory?.backups.length ? (
          <div className="empty-state">
            <div className="empty-icon">
              <ArchiveRestore size={29} />
            </div>
            <h3>{loading ? 'Checking local backups…' : 'No local backups yet'}</h3>
            <p>
              Review an eligible missing-target entry to create your first verified backup. A scan
              alone never creates a backup or changes the registry.
            </p>
          </div>
        ) : (
          <div className="backup-list">
            {inventory.backups.map((backup) => (
              <article className="backup-item" key={backup.id}>
                <span className={`history-icon ${backup.state === 'conflict' ? 'amber' : ''}`}>
                  <ArchiveRestore size={20} />
                </span>
                <div className="backup-description">
                  <h3>{backup.name}</h3>
                  <p>{backup.note}</p>
                  <small>
                    <Clock3 size={12} />
                    {new Date(backup.createdAt).toLocaleString('en-US')}
                    <span>
                      ·{' '}
                      {backup.scope === 'com_proxy'
                        ? 'COM proxy reference'
                        : backup.scope === 'interface'
                          ? 'COM interface TypeLib reference'
                          : backup.scope === 'prog_id'
                            ? 'COM ProgID mapping'
                            : backup.scope === 'type_library'
                              ? 'Type library · win64'
                              : backup.scope === 'registered_app'
                                ? 'Application registration'
                                : backup.scope === 'shared_dll'
                                  ? 'Shared DLL reference · 64 bit'
                                  : backup.scope === 'application'
                                    ? 'Application suggestion'
                                    : backup.scope === 'service'
                                      ? 'Service startup'
                                      : backup.scope === 'com'
                                        ? `COM mapping · ${backup.registryView} bit`
                                        : backup.scope === 'association'
                                          ? 'File association'
                                          : backup.scope === 'uninstall'
                                            ? 'Uninstall'
                                            : backup.scope === 'app_path'
                                              ? 'Application path'
                                              : 'Startup'}{' '}
                      · {backup.valueName || '(Default)'}
                    </span>
                  </small>
                  <code>{backup.id}</code>
                  <p className="mono">{backup.registryPath}</p>
                </div>
                <button
                  className="secondary-button"
                  disabled={busy || backup.state !== 'restore_available'}
                  onClick={() => onRestore(backup.id)}
                >
                  {backup.state === 'restore_available'
                    ? 'Review restore'
                    : backup.state === 'original_present'
                      ? 'Original present'
                      : backup.state === 'conflict'
                        ? 'Conflict blocked'
                        : 'Unverified'}
                </button>
              </article>
            ))}
          </div>
        )}
      </section>
      <div className="notice info-notice backup-location">
        <Info size={17} />
        <p>
          <strong>Local backup folder</strong>
          <br />
          <span className="mono">{inventory?.storagePath ?? 'Available in the desktop app.'}</span>
          <br />
          Keep this folder intact. Backups contain original commands, local paths, and guarded
          registration metadata.
        </p>
      </div>
    </>
  );
}
