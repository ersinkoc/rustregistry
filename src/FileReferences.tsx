import { useEffect, useRef, useState } from 'react';
import { ShieldCheck, ArchiveRestore, X } from 'lucide-react';
import type { ChangePlan } from './Changes';
import { viewLabel } from './model';

export function FileReferenceConfirmation({
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
  const font = plan.scope === 'font_reference';
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
      aria-labelledby="file-reference-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <div className="detail-top">
        <span className="eyebrow">
          {font ? 'PERSISTED FONT REFERENCE' : 'REGISTERED HELP FILE'}
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
      <h2 id="file-reference-title">
        {restore
          ? font
            ? 'Restore font reference?'
            : 'Restore help-file reference?'
          : font
            ? 'Remove missing font reference?'
            : 'Remove missing help-file reference?'}
      </h2>
      <p className="change-intro">
        {font
          ? 'Only the selected supported current-user mapping is covered. System-wide and matching machine font names remain read-only.'
          : 'Only the selected filename-to-directory mapping in the displayed machine architecture view is covered. Existing registry write rights are required.'}
      </p>
      <dl className="detail-fields">
        <div>
          <dt>Registered name</dt>
          <dd>{plan.valueName}</dd>
        </div>
        <div>
          <dt>Registry view</dt>
          <dd>{viewLabel(plan.registryView || 'shared')}</dd>
        </div>
        <div className="full-field">
          <dt>Registry path</dt>
          <dd className="code-field">{plan.registryPath}</dd>
        </div>
        <div className="full-field">
          <dt>{font ? 'Original font path' : 'Original help directory'}</dt>
          <dd className="code-field">{plan.originalValue}</dd>
        </div>
        <div className="full-field">
          <dt>Resolved file</dt>
          <dd className="code-field">{plan.resolvedFile}</dd>
        </div>
      </dl>
      <div className="notice info-notice">
        <ShieldCheck size={20} />
        <p>
          {font
            ? 'Font files, packaged registrations, linking/substitution settings, keys and permissions are preserved. No font is parsed, loaded, unloaded or installed, and no font-change message is sent. Active sessions may retain a previously loaded font.'
            : 'Documents, other registrations, search paths, security settings, keys and permissions are preserved. No help viewer, command or document is opened. Removing this mapping can affect later filename-based help lookup.'}{' '}
          A verified backup supports exact-value restore only while the target remains missing and
          no conflicting registration has appeared. Restoring a reference does not restore a missing
          file.
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
            ? 'I reviewed this exact registration and want to restore it without overwriting a new value.'
            : 'I reviewed the registered name, original value and resolved missing file, and want a verified backup before removing only this mapping.'}
        </span>
      </label>
      {expired && (
        <p role="alert" className="amber">
          This review expired. Cancel and review the current registration again.
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
              ? font
                ? 'Restore font mapping'
                : 'Restore help mapping'
              : font
                ? 'Back up & remove font reference'
                : 'Back up & remove help reference'}
        </button>
      </div>
    </dialog>
  );
}
