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
  scope: 'startup' | 'app_path' | 'uninstall' | 'association' | 'com';
  preservedValues: number;
  uninstallCommand?: string | null;
  componentWasPresent: boolean;
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
  scope: 'startup' | 'app_path' | 'uninstall' | 'association' | 'com';
  registryPath: string;
  registryView?: string;
}
interface Inventory {
  storagePath: string;
  backups: Backup[];
  warnings: string[];
}

export function canQuarantine(entry: RegistryEntry) {
  if (entry.category === 'com')
    return (
      entry.hive === 'HKCU' &&
      entry.view === '64' &&
      entry.comRepairable === true &&
      entry.assessment.status === 'review' &&
      entry.assessment.code === 'target_missing' &&
      entry.valueName === '' &&
      ['REG_SZ', 'REG_EXPAND_SZ'].includes(entry.valueType) &&
      /^software\\classes\\clsid\\\{[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}\\inprocserver32$/i.test(
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
        {com
          ? restore
            ? 'Restore COM DLL mapping?'
            : 'Repair broken COM DLL mapping?'
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
        {com
          ? restore
            ? 'This restores the exact original 64-bit DLL mapping. If the DLL exists later, applications may load it through COM. The class and server metadata must still match the backup.'
            : 'The explicit local DLL is missing. After a verified backup, only the default InprocServer32 path is removed. This disables this broken mapping; it does not repair missing DLL files or choose a replacement.'
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
        {com && (
          <div className="full-field">
            <dt>Registry view</dt>
            <dd>{plan.registryView} bit · current user</dd>
          </div>
        )}
        <div>
          <dt>Value name</dt>
          <dd>{plan.valueName || '(Default)'}</dd>
        </div>
        <div>
          <dt>Value type</dt>
          <dd className="mono">{plan.valueType}</dd>
        </div>
        <div className="full-field">
          <dt>
            {com
              ? 'Exact original COM DLL path'
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
          The COM class, InprocServer32 key, and {plan.preservedValues} other metadata value(s)
          remain in place. Alternative activation keys, changed metadata, or a same-view machine
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
          {com
            ? 'No DLL is loaded or registered, no COM object is activated, and no key, file, or permission is changed. A verified backup is required before removing this one path value.'
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
          {com
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
              State is checked against the original current-user Run, App Paths, Uninstall, or Open
              with location.
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
                      {backup.scope === 'com'
                        ? `COM DLL · ${backup.registryView} bit`
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
