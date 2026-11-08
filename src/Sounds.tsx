import { useEffect, useRef, useState } from 'react';
import { ArchiveRestore, ShieldCheck, X } from 'lucide-react';
import type { ChangePlan } from './Changes';

export function SoundConfirmation({
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
  const expired = clock >= plan.expiresAt;
  const restore = plan.action === 'restore';
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
      aria-labelledby="sound-change-title"
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <div className="detail-top">
        <span className="eyebrow">CURRENT SOUND ASSIGNMENT</span>
        <button
          className="icon-button"
          aria-label="Cancel change"
          disabled={busy}
          onClick={onCancel}
        >
          <X size={19} />
        </button>
      </div>
      <h2 id="sound-change-title">
        {restore ? 'Restore sound assignment?' : 'Clear missing sound assignment?'}
      </h2>
      <p className="change-intro">
        {restore
          ? 'Restore the original file assignment only while the exact empty assignment, selected scheme and saved metadata still match.'
          : 'Replace only this missing current-event file assignment with an explicit empty assignment after a verified backup.'}
      </p>
      <dl className="detail-fields">
        <div>
          <dt>Sound event</dt>
          <dd>{plan.name}</dd>
        </div>
        <div>
          <dt>Registry view</dt>
          <dd>Shared · Current user</dd>
        </div>
        <div className="full-field">
          <dt>Registry path</dt>
          <dd className="code-field">{plan.registryPath}</dd>
        </div>
        <div className="full-field">
          <dt>Original sound file</dt>
          <dd className="code-field">{plan.originalValue}</dd>
        </div>
        <div className="full-field">
          <dt>Resolved file</dt>
          <dd className="code-field">{plan.resolvedFile}</dd>
        </div>
        <div className="full-field">
          <dt>{restore ? 'Required current assignment' : 'Replacement'}</dt>
          <dd>Empty REG_SZ (explicit unassigned sound)</dd>
        </div>
      </dl>
      <div className="notice info-notice">
        <ShieldCheck size={20} />
        <p>
          Saved/default/No Sounds schemes, event metadata, keys, audio files, permissions, devices
          and volume settings are preserved. No audio is played, decoded or deleted. Applications
          may cache sounds or implement their own fallback. Restoring an assignment does not recover
          a missing sound file. New files, changed assignments or scheme metadata block repair and
          restoration.
        </p>
      </div>
      <label className="confirmation-check">
        <input
          type="checkbox"
          checked={agreed}
          disabled={busy || expired}
          onChange={(e) => setAgreed(e.target.checked)}
        />
        <span>
          {restore
            ? 'I reviewed the exact original sound assignment and want to restore it without overwriting a new setting.'
            : 'I reviewed the missing file and want a verified backup before clearing only this current sound assignment.'}
        </span>
      </label>
      {expired && (
        <p role="alert" className="amber">
          This review expired. Cancel and review the current assignment again.
        </p>
      )}
      <div className="change-buttons">
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
              ? 'Restore sound assignment'
              : 'Back up & clear sound assignment'}
        </button>
      </div>
    </dialog>
  );
}
