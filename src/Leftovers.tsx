import { useEffect, useMemo, useRef, useState } from 'react';
import { ArchiveRestore, Boxes, Search, ShieldCheck, X } from 'lucide-react';
import type { RegistryEntry, ScanReport } from './model';
import { categories } from './model';
import { canQuarantine, type ChangePlan } from './Changes';
import { leftoverGroups, isSupportedType, leftoverActionName } from './leftover-groups';

export function LeftoversPage({
  report,
  busy,
  onScan,
  onReview,
  onReviewGroup,
}: {
  report: ScanReport | null;
  busy: boolean;
  onScan: () => void;
  onReview: (entry: RegistryEntry) => void;
  onReviewGroup: (ids: string[]) => void;
}) {
  const [query, setQuery] = useState('');
  const [availability, setAvailability] = useState('all');
  const [excluded, setExcluded] = useState<Record<string, string[]>>({});
  const byId = useMemo(() => new Map((report?.entries ?? []).map((e) => [e.id, e])), [report]);
  const groups = useMemo(() => leftoverGroups(report?.entries ?? []), [report]);
  const q = query.trim().toLocaleLowerCase();
  const actionIds = (entry: RegistryEntry) =>
    [...new Set([entry.id, ...(entry.leftoverEvidence?.relatedIds ?? [])])]
      .filter((id) => {
        const item = byId.get(id);
        return !!item && canQuarantine(item);
      })
      .slice(0, 10_000);
  const visible = groups.filter(
    (e) =>
      (availability === 'all' || actionIds(e).length > 0 === (availability === 'ready')) &&
      [
        e.name,
        e.keyPath,
        e.rawValue,
        e.leftoverEvidence?.directory,
        e.leftoverEvidence?.uninstallPath,
      ].some((s) => s?.toLocaleLowerCase().includes(q)),
  );
  const complete = !!report && !report.cancelled;
  return (
    <>
      <section className="panel clean-hero">
        <div>
          <span className="eyebrow">APPLICATION REMNANT DIAGNOSIS</span>
          <h2>Follow the evidence. Review the leftovers.</h2>
          <p>
            Groups match an exact missing installation directory across application and uninstall
            records, with missing application and uninstaller files. This suggests a removed
            application; it does not prove that every setting is disposable.
          </p>
        </div>
        <Boxes size={42} />
      </section>
      {!complete ? (
        <section className="panel empty-state">
          <h3>A completed scan comes first</h3>
          <p>Complete a fresh registry scan before reviewing correlated application leftovers.</p>
          <button className="primary-button" disabled={busy} onClick={onScan}>
            Scan registry
          </button>
        </section>
      ) : (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>
                Likely application leftovers <span className="count-chip">{groups.length}</span>
              </h2>
              <p>
                Each supported change gets its own verified backup. Keys, licenses, user settings,
                installer databases and files are preserved.
              </p>
            </div>
          </div>
          <label className="search-field">
            <Search size={16} />
            <input
              aria-label="Search application leftovers"
              placeholder="Search application, directory or registration"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          <label className="leftover-availability">
            Available actions
            <select
              aria-label="Filter leftover action availability"
              value={availability}
              onChange={(event) => setAvailability(event.target.value)}
            >
              <option value="all">All evidence groups</option>
              <option value="ready">Supported cleanup available</option>
              <option value="evidence">Evidence only</option>
            </select>
          </label>
          {!visible.length ? (
            <div className="empty-state">
              <h3>
                {groups.length
                  ? 'No matching leftover groups'
                  : 'No corroborated application leftovers'}
              </h3>
              <p>
                {groups.length
                  ? 'Try another application name or directory.'
                  : 'A missing file or similar product name alone is insufficient. Uncertain and protected records remain available in Scan results.'}
              </p>
            </div>
          ) : (
            visible.slice(0, 50).map((entry) => {
              const e = entry.leftoverEvidence!;
              const ids = actionIds(entry);
              const selectionKey = `${report.id}:${entry.id}`;
              const selected = ids.filter((id) => !excluded[selectionKey]?.includes(id));
              return (
                <article className="leftover-group" key={entry.id}>
                  <div className="panel-heading">
                    <div>
                      <h3>{e.applicationName}</h3>
                      <p>
                        {entry.publisher ?? 'Current-user application'} ·{' '}
                        {e.executable.split('\\').pop()}
                      </p>
                    </div>
                    <span className="status-badge review">Review evidence</span>
                  </div>
                  <dl className="detail-fields">
                    <div className="full-field">
                      <dt>
                        {isSupportedType(entry) ? 'File-type suggestion' : 'Registered search path'}
                      </dt>
                      <dd className="code-field">
                        {isSupportedType(entry)
                          ? `${entry.valueName} · ${entry.valueType} · ${entry.rawValue || '(empty)'}`
                          : entry.rawValue}
                      </dd>
                    </div>
                    <div className="full-field">
                      <dt>Matching installation directory</dt>
                      <dd className="code-field">{e.directory}</dd>
                    </div>
                    <div>
                      <dt>Application executable</dt>
                      <dd className="code-field">{e.executable}</dd>
                    </div>
                    <div>
                      <dt>Uninstaller executable</dt>
                      <dd className="code-field">{e.uninstaller}</dd>
                    </div>
                    <div className="full-field">
                      <dt>Correlated uninstall registration</dt>
                      <dd className="code-field">{e.uninstallPath}</dd>
                    </div>
                  </dl>
                  <details>
                    <summary>Why this group?</summary>
                    <p>{entry.assessment.explanation}</p>
                  </details>
                  <p>
                    {ids.length} supported cleanup actions. Each action is checked again against
                    live registry and file evidence.
                  </p>
                  {ids.length > 0 && (
                    <ul>
                      {ids.map((id) => {
                        const item = byId.get(id)!;
                        return (
                          <li key={id}>
                            <label>
                              <input
                                type="checkbox"
                                aria-label={`Select ${categories[item.category].label} cleanup for ${leftoverActionName(item)}`}
                                disabled={busy}
                                checked={selected.includes(id)}
                                onChange={(event) =>
                                  setExcluded((current) => ({
                                    ...current,
                                    [selectionKey]: event.target.checked
                                      ? (current[selectionKey] ?? []).filter(
                                          (value) => value !== id,
                                        )
                                      : [...(current[selectionKey] ?? []), id],
                                  }))
                                }
                              />{' '}
                              {categories[item.category].label}: {leftoverActionName(item)}
                            </label>
                            <button
                              className="secondary-button"
                              aria-label={`Review ${categories[item.category].label} action for ${leftoverActionName(item)}`}
                              disabled={busy}
                              onClick={() => onReview(item)}
                            >
                              Review action
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  <div className="change-buttons">
                    {canQuarantine(entry) && (
                      <button
                        className="secondary-button"
                        disabled={busy}
                        onClick={() => onReview(entry)}
                      >
                        {isSupportedType(entry)
                          ? 'Review file-type cleanup'
                          : 'Review search-path cleanup'}
                      </button>
                    )}
                    <button
                      className="primary-button"
                      aria-label={`Review cleanup for ${e.applicationName}`}
                      disabled={busy || !selected.length}
                      onClick={() => onReviewGroup(selected)}
                    >
                      <ShieldCheck size={16} /> Review group cleanup ({selected.length})
                    </button>
                  </div>
                </article>
              );
            })
          )}
          {visible.length > 50 && (
            <p className="clean-footnote">
              Showing the first 50 of {visible.length} matching groups. Narrow the search to review
              the rest.
            </p>
          )}
        </section>
      )}
    </>
  );
}

export function LeftoverConfirmation({
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
  const cleanedList = plan.supportingEvidence?.find(
    ([label]) => label === 'Search path after cleanup',
  );
  const restore = plan.action === 'restore';
  const typeHint = plan.supportingEvidence?.find(([label]) => label === 'File-type suggestion');
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
      aria-labelledby="leftover-title"
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <div className="detail-top">
        <span className="eyebrow">CORRELATED APPLICATION LEFTOVER</span>
        <button
          className="icon-button"
          aria-label="Cancel change"
          disabled={busy}
          onClick={onCancel}
        >
          <X size={19} />
        </button>
      </div>
      <h2 id="leftover-title">
        {typeHint
          ? restore
            ? 'Restore file-type suggestion?'
            : 'Remove leftover file-type suggestion?'
          : restore
            ? 'Restore application search path?'
            : cleanedList
              ? 'Clean application search-path list?'
              : 'Remove unused application search path?'}
      </h2>
      <p className="change-intro">
        {typeHint
          ? restore
            ? 'Restore only this exact empty SupportedTypes value while the key exists, the selected value is absent and all ownership and missing-target evidence still agrees.'
            : 'Remove only the selected empty SupportedTypes value after a verified backup. Other suggestions, the open command, icon metadata and default application selections stay intact. This can affect Open with suggestions; it does not completely unregister the application.'
          : restore
            ? 'Restore only the exact original search-path value while its key, missing-file evidence and correlated metadata still match.'
            : cleanedList
              ? 'Remove only the confirmed missing installation-directory segments from this Path list after a verified backup. Retained segments keep their exact text and order. The complete original value is backed up.'
              : 'Remove only the unused Path value from this current-user application registration after a verified backup. The uninstall registration remains intact.'}
      </p>
      <dl className="detail-fields">
        <div>
          <dt>Application</dt>
          <dd>{plan.name}</dd>
        </div>
        <div>
          <dt>Value</dt>
          <dd>{plan.valueName} · REG_SZ</dd>
        </div>
        <div className="full-field">
          <dt>Registry path</dt>
          <dd className="code-field">{plan.registryPath}</dd>
        </div>
        <div className="full-field">
          <dt>
            {typeHint
              ? 'Original file-type value'
              : cleanedList
                ? 'Original search-path list'
                : 'Original search directory'}
          </dt>
          <dd className="code-field">{plan.originalValue}</dd>
        </div>
        {(plan.supportingEvidence ?? []).map(([label, value]) => (
          <div className="full-field" key={label}>
            <dt>{label}</dt>
            <dd className="code-field">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="notice info-notice">
        <ShieldCheck size={20} />
        <p>
          Multiple matching missing references suggest a leftover, not proof of a complete
          uninstall. Settings, licenses, uninstall metadata, keys, files and permissions are
          preserved. No application or uninstaller is executed.{' '}
          {typeHint
            ? 'Sibling suggestion backups can be restored independently.'
            : 'Restore this search-path backup before an older executable-mapping backup.'}{' '}
          New mappings, files, ownership conflicts or changed evidence block cleanup and restore.
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
          {typeHint
            ? restore
              ? 'I reviewed the exact original suggestion and want to restore it without overwriting a current value.'
              : 'I reviewed the corroborated evidence and want a verified backup before removing only this file-type suggestion.'
            : restore
              ? 'I reviewed the exact search-path value and matching evidence and want to restore it only while the current value matches the backed-up cleaned state.'
              : cleanedList
                ? 'I reviewed the original and cleaned lists and want a verified backup before removing only the confirmed missing directory segments.'
                : 'I reviewed the correlated evidence and want a verified backup before removing only this unused search-path value.'}
        </span>
      </label>
      {expired && (
        <p role="alert" className="amber">
          This review expired. Cancel and review current evidence again.
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
            : typeHint
              ? restore
                ? 'Restore file-type suggestion'
                : 'Back up & remove suggestion'
              : restore
                ? 'Restore application search path'
                : cleanedList
                  ? 'Back up & clean path list'
                  : 'Back up & remove search path'}
        </button>
      </div>
    </dialog>
  );
}
