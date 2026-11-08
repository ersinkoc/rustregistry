import { useEffect, useRef, useState } from 'react';
import { ArchiveRestore, ShieldCheck, X } from 'lucide-react';
import type { ChangePlan } from './Changes';

export function MaintenanceConfirmation({
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
  const history = plan.scope !== 'mui_cache';
  const restore = plan.action === 'restore';
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
      aria-labelledby="maintenance-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <div className="detail-top">
        <span className="eyebrow">
          {history ? 'OPTIONAL PERSONAL HISTORY' : 'STALE APPLICATION CACHE'}
        </span>
        <button
          className="icon-button"
          aria-label="Cancel change"
          disabled={busy}
          onClick={onCancel}
        >
          <X size={19} />
        </button>
      </div>
      <h2 id="maintenance-title">
        {restore
          ? history
            ? 'Restore registry history?'
            : 'Restore application cache?'
          : history
            ? 'Clear optional registry history?'
            : 'Clear stale application cache?'}
      </h2>
      <p className="change-intro">
        {history
          ? 'This is personal history, not a registry error. Clearing this snapshot is an optional maintenance choice.'
          : 'Only recognized display-cache fields for a confirmed missing executable are included. Application registrations and default handlers remain intact.'}
      </p>
      <dl className="detail-fields">
        <div>
          <dt>Item</dt>
          <dd>{plan.name}</dd>
        </div>
        <div className="full-field">
          <dt>Registry path</dt>
          <dd className="code-field">{plan.registryPath}</dd>
        </div>
        <div className="full-field">
          <dt>Exact values covered by this backup</dt>
          <dd className="code-field" style={{ whiteSpace: 'pre-wrap' }}>
            {plan.originalValue}
          </dd>
        </div>
      </dl>
      <div className="notice info-notice">
        <ShieldCheck size={20} />
        <p>
          {history
            ? 'The backup retains this history for restoration. Other history stores, files and Explorer’s cached suggestions are not cleared. New or changed history blocks restoration.'
            : 'Windows may recreate display-cache values when an application runs again. Other cached applications, files, keys and permissions are preserved. A target that reappears blocks cleaning and restoration.'}
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
          {restore
            ? 'I have reviewed the original values and want to restore them without overwriting new data.'
            : 'I have reviewed these values and want to save a verified backup before clearing them.'}
        </span>
      </label>
      {expired && (
        <p role="alert">This review expired. Close it and review the current data again.</p>
      )}
      <div className="dialog-actions">
        <button className="secondary-button" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
        <button
          className="primary-button"
          disabled={busy || expired || !agreed}
          onClick={onConfirm}
        >
          {restore ? <ArchiveRestore size={16} /> : <ShieldCheck size={16} />}{' '}
          {busy
            ? 'Applying…'
            : restore
              ? history
                ? 'Restore registry history'
                : 'Restore cache values'
              : history
                ? 'Back up & clear history'
                : 'Back up & clear cache'}
        </button>
      </div>
    </dialog>
  );
}
