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
  originalValue: string;
  valueType: string;
  expiresAt: number;
  scope: 'startup' | 'app_path';
  preservedValues: number;
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
  scope: 'startup' | 'app_path';
  registryPath: string;
}
interface Inventory {
  storagePath: string;
  backups: Backup[];
  warnings: string[];
}

export function canQuarantine(entry: RegistryEntry) {
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
        {appPath
          ? restore
            ? 'Restore application path?'
            : 'Repair broken application path?'
          : restore
            ? 'Restore startup entry?'
            : 'Disable this startup entry?'}
      </h2>
      <p className="change-intro">
        {appPath
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
        <div>
          <dt>Value name</dt>
          <dd>{plan.valueName || '(Default)'}</dd>
        </div>
        <div>
          <dt>Value type</dt>
          <dd className="mono">{plan.valueType}</dd>
        </div>
        <div className="full-field">
          <dt>{appPath ? 'Exact original executable path' : 'Exact original command'}</dt>
          <dd className="code-field">{plan.originalValue}</dd>
        </div>
      </dl>
      {appPath && (
        <p className="change-intro">
          The registry key and {plan.preservedValues} other value(s), including any Path metadata,
          stay in place. Changed metadata or a newly populated default value blocks restore.
        </p>
      )}
      <div className="change-guarantee">
        <LockKeyhole size={18} />
        <p>
          {restore
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
          {appPath
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
            <p>State is checked against the original current-user Run or App Paths location.</p>
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
                      · {backup.scope === 'app_path' ? 'Application path' : 'Startup'} ·{' '}
                      {backup.valueName || '(Default)'}
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
