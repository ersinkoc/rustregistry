import { useEffect, useRef, useState } from 'react';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { ArchiveRestore, History, RotateCw, ShieldCheck, X } from 'lucide-react';
import type { ScanReport } from './model';
import type { CleanProgress } from './Clean';
import { pageRows } from './clean-selection';

export interface Operation {
  id: string;
  kind: 'clean' | 'restore' | 'undo';
  mode: string;
  sourceOperationId: string | null;
  createdAt: number;
  updatedAt: number;
  state: string;
  total: number;
  attempted: number;
  applied: number;
  alreadyOriginal: number;
  blocked: number;
  failed: number;
  notAttempted: number;
  canUndo: boolean;
}
interface Operations {
  operations: Operation[];
  warnings: string[];
  storagePath: string;
}
export interface UndoItem {
  backupId: string;
  name: string;
  registryPath: string;
  valueName: string;
  registryView: string;
  original: { kind: number; bytes: number[] } | null;
  state: string;
  reason: string;
}
function originalPreview(value: NonNullable<UndoItem['original']>): string {
  const bytes = Uint8Array.from(value.bytes);
  if ([1, 2, 7].includes(value.kind))
    return new TextDecoder('utf-16le').decode(bytes).replace(/\0+$/, '') || '(empty string)';
  if (value.kind === 4 && bytes.length === 4)
    return String(new DataView(bytes.buffer).getUint32(0, true));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(' ');
}
export interface UndoPlan {
  token: string;
  sourceOperationId: string | null;
  expiresAt: number;
  items: UndoItem[];
}
export interface UndoResult {
  operationId: string | null;
  restored: number;
  alreadyOriginal: number;
  blocked: UndoItem[];
  notAttempted: number;
  cancelled: boolean;
}
interface SavedScan {
  id: string;
  scanId: string;
  startedAt: number;
  durationMs: number;
  cancelled: boolean;
  entries: number;
  sections: number;
}
interface HistoryInventory {
  scans: SavedScan[];
  warnings: string[];
  storagePath: string;
  retainedScans: number;
}
export function asHistoricalReport(report: ScanReport): ScanReport {
  return {
    ...report,
    historical: true,
    entries: report.entries.map((entry) => ({ ...entry, historical: true })),
  };
}

export function RecoveryCenter({
  revision,
  busy,
  onReview,
}: {
  revision: number;
  busy: boolean;
  onReview: (id: string) => void;
}) {
  const [inventory, setInventory] = useState<Operations | null>(null);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [page, setPage] = useState(0);
  useEffect(() => {
    let active = true;
    if (isTauri())
      invoke<Operations>('list_operations')
        .then((result) => {
          if (active) {
            setInventory(result);
            setError('');
          }
        })
        .catch((cause) => {
          if (active) setError(String(cause));
        });
    return () => {
      active = false;
    };
  }, [revision, refresh]);
  const rows = pageRows(inventory?.operations ?? [], page);
  return (
    <>
      <div className="coverage-intro">
        <div className="coverage-symbol">
          <ShieldCheck size={28} />
        </div>
        <div>
          <h2>Every change has a history.</h2>
          <p>
            Durable intent and result checkpoints survive app restarts. Interrupted work is never
            resumed automatically. Review Undo to reconcile backups with the current registry.
          </p>
        </div>
      </div>
      {error && (
        <p role="alert" className="notice error-notice">
          {error}
        </p>
      )}
      {inventory?.warnings.map((w, i) => (
        <p role="alert" className="notice error-notice" key={i}>
          {w}
        </p>
      ))}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>
              Operation journal{' '}
              <span className="count-chip">{inventory?.operations.length ?? 0}</span>
            </h2>
            <p>
              Applied counts are durable checkpoints. An interrupted item may have committed before
              its result was recorded; Undo checks live state.
            </p>
          </div>
          <button
            className="secondary-button"
            disabled={busy}
            onClick={() => setRefresh((v) => v + 1)}
          >
            <RotateCw size={15} />
            Refresh operations
          </button>
        </div>
        {!rows.rows.length && (
          <div className="empty-state">
            <ArchiveRestore size={30} />
            <h3>No recorded operations yet</h3>
            <p>
              Existing backups remain available in Backups &amp; restore, including bulk restore.
            </p>
          </div>
        )}
        <div className="backup-list">
          {rows.rows.map((operation) => (
            <article className="backup-item" data-operation-id={operation.id} key={operation.id}>
              <span className="history-icon">
                <ArchiveRestore size={20} />
              </span>
              <div className="backup-description">
                <h3>
                  {operation.kind === 'clean'
                    ? 'Cleaning'
                    : operation.kind === 'undo'
                      ? 'Bulk Undo'
                      : 'Restore'}{' '}
                  · {operation.mode}
                </h3>
                <p>
                  <strong>{operation.state}</strong> · {operation.applied} applied ·{' '}
                  {operation.alreadyOriginal} already original ·{' '}
                  {operation.blocked + operation.failed} need attention · {operation.notAttempted}{' '}
                  not attempted
                </p>
                <small>
                  {new Date(operation.createdAt).toLocaleString('en-US')} · {operation.total}{' '}
                  planned entries
                </small>
                <code>{operation.id}</code>
                {operation.sourceOperationId && (
                  <p className="mono">Undo of {operation.sourceOperationId}</p>
                )}
              </div>
              {operation.canUndo && (
                <button
                  className="secondary-button"
                  disabled={busy}
                  onClick={() => onReview(operation.id)}
                >
                  Review Undo
                </button>
              )}
            </article>
          ))}
        </div>
        {rows.pages > 1 && (
          <div className="change-buttons">
            <button
              className="secondary-button"
              disabled={page === 0 || busy}
              onClick={() => setPage(rows.page - 1)}
            >
              Previous operations
            </button>
            <span>
              Page {rows.page + 1} of {rows.pages}
            </span>
            <button
              className="secondary-button"
              disabled={rows.page + 1 >= rows.pages || busy}
              onClick={() => setPage(rows.page + 1)}
            >
              Next operations
            </button>
          </div>
        )}
      </section>
      <p className="notice info-notice mono">
        {inventory?.storagePath ?? 'Available in the desktop app.'}
      </p>
    </>
  );
}
export function SavedHistory({
  revision,
  busy,
  onLoad,
}: {
  revision: number;
  busy: boolean;
  onLoad: (report: ScanReport) => void;
}) {
  const [inventory, setInventory] = useState<HistoryInventory | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    let active = true;
    if (isTauri())
      invoke<HistoryInventory>('list_scan_history')
        .then((result) => {
          if (active) setInventory(result);
        })
        .catch((cause) => {
          if (active) setError(String(cause));
        });
    return () => {
      active = false;
    };
  }, [revision]);
  async function load(id: string) {
    setLoading(true);
    try {
      const report = await invoke<ScanReport>('get_saved_scan', { id });
      onLoad(asHistoricalReport(report));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setLoading(false);
    }
  }
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>Saved scan history</h2>
          <p>
            The latest {inventory?.retainedScans ?? 20} scans are stored locally across restarts.
            Archives contain registry paths and commands. Saved reports are read-only; run a fresh
            scan to repair.
          </p>
        </div>
        <History size={20} />
      </div>
      {error && (
        <p role="alert" className="notice error-notice">
          {error}
        </p>
      )}
      {inventory?.warnings.map((warning, index) => (
        <p role="alert" className="notice error-notice" key={index}>
          {warning}
        </p>
      ))}
      {!inventory?.scans.length ? (
        <div className="empty-state">
          <h3>No saved scans yet</h3>
          <p>Your next registry scan will appear here.</p>
        </div>
      ) : (
        <div className="history-list">
          {inventory.scans.map((scan) => (
            <button
              className="history-item"
              key={scan.id}
              disabled={busy || loading}
              onClick={() => load(scan.id)}
            >
              <span className="history-icon">
                <History size={20} />
              </span>
              <span>
                <strong>
                  {new Date(scan.startedAt).toLocaleString('en-US')} ·{' '}
                  {scan.cancelled ? 'Stopped scan' : 'Registry scan'}
                </strong>
                <small>
                  {scan.entries.toLocaleString('en-US')} entries · {scan.sections} scanned sections
                  · {(scan.durationMs / 1000).toFixed(1)}s
                </small>
              </span>
              <span className="readonly-pill">Saved · read-only</span>
            </button>
          ))}
        </div>
      )}
      <p className="notice info-notice mono">
        {inventory?.storagePath ?? 'Available in the desktop app.'}
      </p>
    </section>
  );
}
export function UndoConfirmation({
  plan,
  busy,
  progress,
  stopRequested,
  onConfirm,
  onCancel,
  onStop,
}: {
  plan: UndoPlan;
  busy: boolean;
  progress: CleanProgress | null;
  stopRequested: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  onStop: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  const [page, setPage] = useState(0);
  const rows = pageRows(plan.items, page);
  const restorable = plan.items.filter((i) => i.state === 'restore_available').length;
  const original = plan.items.filter((i) => i.state === 'original_present').length;
  return (
    <dialog
      ref={dialog}
      className="change-dialog undo-dialog"
      aria-labelledby="undo-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <div className="dialog-heading">
        <div>
          <span className="eyebrow">BACKUP RECOVERY</span>
          <h2 id="undo-title">Review bulk Undo</h2>
        </div>
        <button
          className="icon-button"
          aria-label="Close Undo review"
          disabled={busy}
          onClick={onCancel}
        >
          <X size={20} />
        </button>
      </div>
      <p>
        Each original is checked again before restoration. Existing different values are never
        overwritten. No application or command is run.
      </p>
      <p>
        <strong>
          {restorable} restore available · {original} already original ·{' '}
          {plan.items.length - restorable - original} blocked
        </strong>
      </p>
      <div className="undo-review-list">
        {rows.rows.map((item) => (
          <article key={item.backupId}>
            <strong>{item.name}</strong>
            <p>
              {item.state.replaceAll('_', ' ')}
              {item.reason ? ` · ${item.reason}` : ''}
            </p>
            <code>{item.registryPath}</code>
            <p>
              {item.valueName || '(Default)'} · {item.registryView} view
            </p>
            {item.original && (
              <details>
                <summary>
                  Original value · registry type {item.original.kind} · {item.original.bytes.length}{' '}
                  bytes
                </summary>
                <pre className="code-field">{originalPreview(item.original)}</pre>
              </details>
            )}
          </article>
        ))}
      </div>
      {rows.pages > 1 && (
        <div className="change-buttons">
          <button
            className="secondary-button"
            disabled={page === 0 || busy}
            onClick={() => setPage(rows.page - 1)}
          >
            Previous Undo items
          </button>
          <span>
            {rows.page + 1} / {rows.pages}
          </span>
          <button
            className="secondary-button"
            disabled={rows.page + 1 >= rows.pages || busy}
            onClick={() => setPage(rows.page + 1)}
          >
            Next Undo items
          </button>
        </div>
      )}
      {progress && (
        <p role="status">
          Undo {progress.completed} / {progress.total} · {progress.current}
        </p>
      )}
      <div className="change-buttons">
        {busy ? (
          <button className="secondary-button" disabled={stopRequested} onClick={onStop}>
            {stopRequested ? 'Stopping Undo…' : 'Stop Undo'}
          </button>
        ) : (
          <>
            <button className="secondary-button" onClick={onCancel}>
              Cancel
            </button>
            <button
              className="primary-button"
              disabled={!restorable && !original}
              onClick={onConfirm}
            >
              Confirm bulk Undo
            </button>
          </>
        )}
      </div>
    </dialog>
  );
}
