import { useEffect, useRef, useState } from 'react';
import { CheckCheck, ShieldCheck, TriangleAlert, X, Zap } from 'lucide-react';
import type { RegistryEntry } from './model';
import { categories, viewLabel } from './model';
import { canQuarantine, type ChangePlan } from './Changes';

export interface CleanPlan {
  token: string;
  mode: 'quick' | 'selected';
  expiresAt: number;
  items: ChangePlan[];
  skipped: { name: string; reason: string }[];
}
export interface CleanResult {
  completed: { backupId: string }[];
  failed: { name: string; reason: string } | null;
  notAttempted: number;
}

export function CleanPanel({
  entries,
  complete,
  busy,
  onReview,
  onScan,
}: {
  entries: RegistryEntry[];
  complete: boolean;
  busy: boolean;
  onReview: (mode: 'quick' | 'selected', ids: string[]) => void;
  onScan: () => void;
}) {
  const candidates = entries.filter(canQuarantine);
  const [selected, setSelected] = useState<string[]>([]);
  const [query, setQuery] = useState('');
  const available = candidates.filter(
    (entry) =>
      !query || `${entry.name} ${entry.keyPath}`.toLowerCase().includes(query.toLowerCase()),
  );
  const selectedIds = selected.filter((id) => candidates.some((entry) => entry.id === id));
  return (
    <>
      <div className="clean-hero panel">
        <div>
          <span className="eyebrow">PROTECTED REGISTRY CLEANING</span>
          <h2>Clear the leftovers. Keep a way back.</h2>
          <p>
            Only verified, supported entries with existing configuration access can be cleaned.
            Every change is reviewed, backed up, and checked again before it is applied.
          </p>
        </div>
        <ShieldCheck size={42} />
      </div>
      <div className="clean-modes">
        <section className="panel clean-mode">
          <Zap size={25} />
          <h2>Quick Clean</h2>
          <p>
            Review up to 100 eligible entries from your latest scan. Unverified entries are
            excluded. Service repairs require existing Windows configuration access.
          </p>
          <button
            className="primary-button"
            disabled={busy || !complete || !candidates.length}
            onClick={() => onReview('quick', [])}
          >
            <Zap size={16} />
            Review Quick Clean
          </button>
        </section>
        <section className="panel clean-mode">
          <CheckCheck size={25} />
          <h2>Clean selected</h2>
          <p>
            Choose the exact entries below. Each successful change gets its own backup and can be
            restored separately.
          </p>
          <button
            className="primary-button"
            disabled={busy || !complete || !selectedIds.length}
            onClick={() => onReview('selected', selectedIds)}
          >
            <ShieldCheck size={16} />
            Review selected ({selectedIds.length})
          </button>
        </section>
      </div>
      {!complete ? (
        <div className="panel empty-state">
          <h3>A completed scan comes first</h3>
          <p>
            Scan to find supported cleaning candidates. Stopped scans cannot be used for cleaning.
          </p>
          <button className="primary-button" disabled={busy} onClick={onScan}>
            Scan registry
          </button>
        </div>
      ) : (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>
                Eligible entries <span className="count-chip">{candidates.length}</span>
              </h2>
              <p>A review finding alone does not make an entry safe to clean.</p>
            </div>
            <button
              className="secondary-button"
              disabled={busy || (!available.length && !selectedIds.length)}
              onClick={() =>
                setSelected(
                  selectedIds.length ? [] : available.slice(0, 100).map((entry) => entry.id),
                )
              }
            >
              {selectedIds.length ? 'Clear selection' : 'Select visible (up to 100)'}
            </button>
          </div>
          {candidates.length ? (
            <>
              <div className="table-toolbar">
                <input
                  className="clean-search"
                  aria-label="Search cleaning candidates"
                  placeholder="Search eligible entries…"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </div>
              <div className="clean-candidates">
                {available.slice(0, 100).map((entry) => (
                  <label className="clean-candidate" key={entry.id}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${entry.name}`}
                      disabled={
                        busy || (!selectedIds.includes(entry.id) && selectedIds.length >= 100)
                      }
                      checked={selectedIds.includes(entry.id)}
                      onChange={(event) =>
                        setSelected(
                          event.target.checked
                            ? [...selectedIds, entry.id]
                            : selectedIds.filter((id) => id !== entry.id),
                        )
                      }
                    />
                    <span>
                      <strong>{entry.name}</strong>
                      <small>
                        {categories[entry.category].label} · {viewLabel(entry.view)}
                      </small>
                      <code>
                        {entry.hive}\{entry.keyPath}
                      </code>
                    </span>
                  </label>
                ))}
              </div>
              <p className="clean-footnote">
                Showing {Math.min(available.length, 100)} of {available.length} matching entries. A
                review is limited to 100 changes; rerun the scan afterward for remaining entries.
              </p>
            </>
          ) : (
            <div className="empty-state">
              <ShieldCheck size={32} />
              <h3>No eligible entries to clean</h3>
              <p>
                Other findings stay available in Scan results for inspection. Nothing is removed
                just to increase a cleaning count.
              </p>
            </div>
          )}
        </section>
      )}
      <div className="notice info-notice">
        <ShieldCheck size={18} />
        <p>
          Cleaning changes registry values only. It does not delete application files or promise a
          performance gain. If an entry fails its final checks, cleaning stops and earlier
          successful changes remain backed up.
        </p>
      </div>
    </>
  );
}

export function CleanConfirmation({
  plan,
  busy,
  onCancel,
  onConfirm,
}: {
  plan: CleanPlan;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [agreed, setAgreed] = useState(false);
  const [clock, setClock] = useState(Date.now());
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
      className="change-dialog clean-dialog"
      aria-labelledby="clean-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <div className="detail-top">
        <span className="eyebrow">REVIEW EVERY CHANGE</span>
        <button
          className="icon-button"
          aria-label="Cancel cleaning"
          disabled={busy}
          onClick={onCancel}
        >
          <X size={19} />
        </button>
      </div>
      <h2 id="clean-title">
        {plan.mode === 'quick' ? 'Review Quick Clean' : 'Review selected cleaning'}
      </h2>
      <p className="change-intro">
        {plan.items.length} changes are ready for review. Each entry receives its own verified
        backup. Cleaning stops at the first error; it is not one all-or-nothing operation.
      </p>
      <div className="clean-review-items">
        {plan.items.map((item) => (
          <details key={item.token}>
            <summary>
              <strong>{item.name}</strong>
              <span>
                {item.scope === 'type_library'
                  ? 'Disable missing type library mapping · win64'
                  : item.scope === 'registered_app'
                    ? 'Remove orphaned application registration'
                    : item.scope === 'shared_dll'
                      ? 'Remove missing zero-count DLL reference · 64 bit'
                      : item.scope === 'application'
                        ? 'Hide broken application suggestion · NoOpenWith'
                        : item.scope === 'service'
                          ? 'Disable stopped service · Manual → Disabled'
                          : item.scope === 'uninstall'
                            ? 'Hide orphaned listing · SystemComponent → 1'
                            : item.scope === 'association'
                              ? 'Remove Open with suggestion'
                              : item.scope === 'com'
                                ? 'Disable COM mapping'
                                : item.scope === 'app_path'
                                  ? 'Remove broken application path'
                                  : 'Disable startup value'}
              </span>
            </summary>
            <dl className="detail-fields">
              <div className="full-field">
                <dt>Registry path · {viewLabel(item.registryView || 'shared')}</dt>
                <dd className="code-field">{item.registryPath}</dd>
              </div>
              <div>
                <dt>Value name</dt>
                <dd>{item.valueName || '(Default)'}</dd>
              </div>
              <div>
                <dt>Type</dt>
                <dd>{item.valueType}</dd>
              </div>
              <div className="full-field">
                <dt>Original value</dt>
                <dd className="code-field">{item.originalValue}</dd>
              </div>
              {item.applicationCommand && (
                <div className="full-field">
                  <dt>Original open command · preserved, never executed</dt>
                  <dd className="code-field">{item.applicationCommand}</dd>
                </div>
              )}
              {item.serviceExecutable && (
                <div className="full-field">
                  <dt>Service executable · never executed</dt>
                  <dd className="code-field">{item.serviceExecutable}</dd>
                </div>
              )}
              {item.uninstallCommand && (
                <div className="full-field">
                  <dt>Uninstall command · never executed</dt>
                  <dd className="code-field">{item.uninstallCommand}</dd>
                </div>
              )}
            </dl>
          </details>
        ))}
      </div>
      {plan.skipped.map((item, index) => (
        <div className="notice info-notice" key={index}>
          <TriangleAlert size={16} />
          <p>
            <strong>Skipped: {item.name}</strong>
            <br />
            {item.reason}
          </p>
        </div>
      ))}
      <p className="change-intro">
        Keys, files, permissions, and default application selections are preserved. COM cleanup
        disables only the reviewed mapping; it never loads a DLL or runs a command. Restore is
        available in Backups & restore.
      </p>
      {plan.items.some((item) => item.scope === 'application') && (
        <p className="change-intro">
          Application suggestion repair adds NoOpenWith while preserving the original command and
          default selections. Explicit Open with lists may still show the application; recent-file
          Jump List tracking for unregistered file types is also limited.
        </p>
      )}
      {plan.items.some((item) => item.scope === 'shared_dll') && (
        <p className="change-intro">
          Shared DLL cleanup removes only confirmed missing zero-count references in the 64-bit
          machine view. Positive counters and files are preserved. Existing Windows write access is
          required, and restore is blocked if a new counter or file appears.
        </p>
      )}
      {plan.items.some((item) => item.scope === 'registered_app') && (
        <p className="change-intro">
          Application registration cleanup removes only current-user values with confirmed missing
          Capabilities and no machine counterpart. Default selections, UserChoice, other keys,
          commands, and files are preserved. New targets or registrations block repair and restore.
        </p>
      )}
      {plan.items.some((item) => item.scope === 'type_library') && (
        <p className="change-intro">
          Type library cleanup changes only confirmed missing, neutral win64 user mappings after a
          separate verified backup. Version, locale, win32 mappings, keys, metadata, and files are
          preserved. New files, machine counterparts, or changed registration details block repair
          and restore.
        </p>
      )}
      <label className="confirmation-check">
        <input
          type="checkbox"
          checked={agreed}
          disabled={busy || clock >= plan.expiresAt}
          onChange={(event) => setAgreed(event.target.checked)}
        />
        <span>I reviewed the listed changes and understand that each has its own backup.</span>
      </label>
      {clock >= plan.expiresAt && (
        <p role="alert" className="amber">
          This review expired. Cancel and review again.
        </p>
      )}
      <div className="change-buttons">
        <button className="secondary-button" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
        <button
          className="primary-button"
          disabled={!agreed || busy || !plan.items.length || clock >= plan.expiresAt}
          onClick={onConfirm}
        >
          <ShieldCheck size={16} />
          {busy ? 'Cleaning…' : `Back up & clean ${plan.items.length} entries`}
        </button>
      </div>
    </dialog>
  );
}
