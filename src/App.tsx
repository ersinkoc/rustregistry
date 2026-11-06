import { useEffect, useMemo, useRef, useState } from 'react';
import { Channel, invoke, isTauri } from '@tauri-apps/api/core';
import {
  Activity,
  ArchiveRestore,
  ArrowDownLeft,
  ArrowRight,
  ArrowUpRight,
  Boxes,
  Check,
  CheckCheck,
  ChevronLeft,
  ChevronRight,
  CircleCheck,
  CircleHelp,
  CirclePause,
  Clock3,
  Copy,
  FileSearch,
  FolderOpen,
  History,
  Info,
  LayoutDashboard,
  ListFilter,
  LockKeyhole,
  Monitor,
  Moon,
  Play,
  Radio,
  RotateCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Square,
  Sun,
  TerminalSquare,
  TriangleAlert,
  X,
  Zap,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import packageInfo from '../package.json';
import { BackupsPanel, canQuarantine, ChangeConfirmation } from './Changes';
import type { ChangePlan, ChangeResult } from './Changes';
import { CleanPanel, CleanConfirmation, type CleanPlan, type CleanResult } from './Clean';
import type { Category, EntryStatus, RegistryEntry, ScanProgress, ScanReport } from './model';
import {
  categories,
  countStatuses,
  filterEntries,
  formatDuration,
  formatNumber,
  formatTime,
  scopeLabel,
  statuses,
  viewLabel,
} from './model';

type Page = 'clean' | 'overview' | 'results' | 'coverage' | 'history' | 'backups' | 'about';
const pageNames: Record<Page, string> = {
  overview: 'Overview',
  clean: 'Clean registry',
  results: 'Scan results',
  coverage: 'Scan coverage',
  history: 'Session history',
  backups: 'Backups & restore',
  about: 'About RustRegistry',
};
const categoryIcons: Record<Category, LucideIcon> = {
  startup: Radio,
  app_paths: FolderOpen,
  uninstall: Boxes,
  file_associations: FileSearch,
  com: Boxes,
  services: SlidersHorizontal,
  shared_dlls: FileSearch,
};
const PAGE_SIZE = 25;

function StatusIcon({ status, size = 15 }: { status: EntryStatus; size?: number }) {
  const Icon = status === 'found' ? CircleCheck : status === 'review' ? TriangleAlert : CircleHelp;
  return <Icon size={size} />;
}

function RegistryArt({ scanning }: { scanning: boolean }) {
  return (
    <div className={`registry-art ${scanning ? 'is-scanning' : ''}`} aria-hidden="true">
      <div className="art-grid" />
      <svg viewBox="0 0 400 210" className="art-lines">
        <path d="M53 98H122V50H224M122 98V155H224M224 50H302M224 155H302" />
        <circle cx="122" cy="98" r="4" />
      </svg>
      <div className="art-root">
        <Boxes size={27} />
        <span>REGISTRY</span>
      </div>
      <div className="art-node node-user">
        <FolderOpen size={17} />
        <span>HKEY_CURRENT_USER</span>
        <span className="art-dot" />
      </div>
      <div className="art-node node-machine">
        <FolderOpen size={17} />
        <span>HKEY_LOCAL_MACHINE</span>
        <span className="art-dot" />
      </div>
      <div className="art-note">
        <ShieldCheck size={12} /> READ-ONLY ACCESS
      </div>
      <div className="art-orbit">
        <Check size={13} />
      </div>
    </div>
  );
}

function DetailDialog({
  entry,
  close,
  review,
  busy,
}: {
  entry: RegistryEntry;
  close: () => void;
  review: (entry: RegistryEntry) => void;
  busy: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [copyState, setCopyState] = useState('');
  const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => {
      dialog?.close();
      clearTimeout(copyTimer.current);
    };
  }, []);

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopyState('Copied');
    } catch {
      setCopyState('Could not copy. Select the text and copy it manually.');
    }
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopyState(''), 2500);
  };
  const fullPath = `${entry.hive}\\${entry.keyPath}`;
  return (
    <dialog ref={ref} className="detail-dialog" aria-labelledby="detail-title" onCancel={close}>
      <div className="detail-top">
        <span className="eyebrow">ENTRY DETAILS</span>
        <button className="icon-button" aria-label="Close details" onClick={close}>
          <X size={20} />
        </button>
      </div>
      <div className={`detail-symbol ${entry.assessment.status}`}>
        <StatusIcon status={entry.assessment.status} size={27} />
      </div>
      <h2 id="detail-title">{entry.name || '(Default)'}</h2>
      <span className={`status-badge ${entry.assessment.status}`}>
        <StatusIcon status={entry.assessment.status} />
        {statuses[entry.assessment.status].label}
      </span>
      <p className="detail-explanation">{entry.assessment.explanation}</p>
      <dl className="detail-fields">
        <div>
          <dt>Category</dt>
          <dd>{categories[entry.category].label}</dd>
        </div>
        <div>
          <dt>Registry view</dt>
          <dd>{viewLabel(entry.view)}</dd>
        </div>
        <div className="full-field">
          <dt>
            Registry path{' '}
            <button
              className="text-button"
              onClick={() => copy(fullPath)}
              aria-label="Copy registry path"
            >
              <Copy size={13} /> Copy
            </button>
          </dt>
          <dd className="code-field">{fullPath}</dd>
        </div>
        <div>
          <dt>Value name</dt>
          <dd>{entry.valueName || '(Default)'}</dd>
        </div>
        <div>
          <dt>Value type</dt>
          <dd className="mono">{entry.valueType}</dd>
        </div>
        <div className="full-field">
          <dt>Original value</dt>
          <dd className="code-field">
            {entry.rawValue || 'No target value, or the value could not be read as text.'}
          </dd>
        </div>
        <div className="full-field">
          <dt>
            {entry.category === 'file_associations' ? 'Suggested registration' : 'Resolved target'}
          </dt>
          <dd className="code-field">
            {entry.assessment.target || 'A reliable local target could not be resolved.'}
          </dd>
        </div>
        {entry.publisher && (
          <div>
            <dt>Publisher</dt>
            <dd>{entry.publisher}</dd>
          </div>
        )}
        {entry.version && (
          <div>
            <dt>Version</dt>
            <dd>{entry.version}</dd>
          </div>
        )}
        <div className="full-field">
          <dt>Diagnostic code</dt>
          <dd className="mono">{entry.assessment.code}</dd>
        </div>
      </dl>
      {canQuarantine(entry) && (
        <div className="remediation-card">
          <ShieldCheck size={19} />
          <h3>
            {entry.category === 'com'
              ? 'Protected COM DLL mapping repair'
              : entry.category === 'file_associations'
                ? 'Protected Open with repair'
                : entry.category === 'uninstall'
                  ? 'Protected uninstall listing repair'
                  : entry.category === 'app_paths'
                    ? 'Protected application path repair'
                    : 'Protected startup change'}
          </h3>
          <p>
            {entry.category === 'com'
              ? 'Review a backup before disabling this missing 64-bit DLL mapping. The class and threading metadata stay in place. No DLL is loaded or registered.'
              : entry.category === 'file_associations'
                ? 'Review a verified backup before removing this orphaned suggestion. Default applications and UserChoice stay untouched.'
                : entry.category === 'uninstall'
                  ? 'Review a full backup before hiding this orphaned listing. No installer or uninstaller will be executed.'
                  : entry.category === 'app_paths'
                    ? 'Review a backed-up repair of this broken default executable mapping. The key and other values are preserved.'
                    : 'This missing-target entry belongs to your startup list. Review its exact value before creating a backup and disabling it.'}
          </p>
          <button className="secondary-button" disabled={busy} onClick={() => review(entry)}>
            {busy
              ? 'Preparing review…'
              : entry.category !== 'startup'
                ? 'Review repair'
                : 'Review disable'}
          </button>
        </div>
      )}
      <div className="detail-footer">
        <LockKeyhole size={17} />
        <p>
          This entry was only read.
          <br />
          <span>Changes require explicit review and a verified backup.</span>
        </p>
      </div>
      <p className="copy-feedback" role="status">
        {entry.uninstallHidden && (
          <span>
            This entry is marked hidden/system component. Use a matching backup to review restoring
            visibility.
          </span>
        )}
        {copyState}
      </p>
    </dialog>
  );
}

export default function App() {
  const [page, setPage] = useState<Page>('overview');
  const [theme, setTheme] = useState<'dark' | 'light'>(() =>
    localStorage.getItem('rustregistry-theme') === 'light' ? 'light' : 'dark',
  );
  const [report, setReport] = useState<ScanReport | null>(null);
  const [history, setHistory] = useState<ScanReport[]>([]);
  const [scanning, setScanning] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [progress, setProgress] = useState<ScanProgress>({
    completed: 0,
    total: 21,
    entries: 0,
    current: '',
  });
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<Category | 'all'>('all');
  const [status, setStatus] = useState<EntryStatus | 'all'>('all');
  const [tablePage, setTablePage] = useState(0);
  const [selected, setSelected] = useState<RegistryEntry | null>(null);
  const [plan, setPlan] = useState<ChangePlan | null>(null);
  const [cleanPlan, setCleanPlan] = useState<CleanPlan | null>(null);
  const [changing, setChanging] = useState(false);
  const [success, setSuccess] = useState('');
  const [backupRevision, setBackupRevision] = useState(0);
  const scanLock = useRef(false);
  const desktop = isTauri();

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem('rustregistry-theme', theme);
  }, [theme]);

  const counts = useMemo(() => countStatuses(report?.entries ?? []), [report]);
  const filtered = useMemo(
    () => filterEntries(report?.entries ?? [], query, category, status),
    [report, query, category, status],
  );
  const maxPage = Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1);
  const currentPage = Math.min(tablePage, maxPage);
  const rows = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  const scopeIssues =
    report?.scopes.filter((scope) => !['complete', 'missing'].includes(scope.status)).length ?? 0;
  const progressPercent = Math.round((progress.completed / Math.max(1, progress.total)) * 100);

  const startScan = async () => {
    if (scanLock.current) return;
    if (!desktop) {
      setError(
        'Open the desktop application to scan the Windows registry. Browser preview cannot access the registry.',
      );
      return;
    }
    scanLock.current = true;
    setScanning(true);
    setStopping(false);
    setError('');
    setProgress({ completed: 0, total: 21, entries: 0, current: 'Connecting to the registry…' });
    const channel = new Channel<ScanProgress>();
    channel.onmessage = (value) => setProgress(value);
    try {
      const result = await invoke<ScanReport>('scan_registry', { onProgress: channel });
      setReport(result);
      setHistory((previous) => [result, ...previous].slice(0, 8));
      setTablePage(0);
    } catch (cause) {
      setError(`The scan could not be completed: ${String(cause)}`);
    } finally {
      scanLock.current = false;
      setScanning(false);
      setStopping(false);
    }
  };

  const stopScan = async () => {
    setStopping(true);
    try {
      await invoke('cancel_scan');
    } catch (cause) {
      setError(`Could not request cancellation: ${String(cause)}`);
      setStopping(false);
    }
  };

  const reviewChange = async (entry?: RegistryEntry, backupId?: string) => {
    if (scanning || changing) return;
    setChanging(true);
    setError('');
    setSuccess('');
    setSelected(null);
    try {
      const prepared = entry
        ? await invoke<ChangePlan>('prepare_quarantine', { entryId: entry.id })
        : await invoke<ChangePlan>('prepare_restore', { backupId });
      setPlan(prepared);
    } catch (cause) {
      setError(String(cause));
    } finally {
      setChanging(false);
    }
  };
  const cancelChange = async () => {
    try {
      await invoke('cancel_change');
    } catch (cause) {
      setError(String(cause));
    }
    setPlan(null);
    setCleanPlan(null);
  };
  const confirmChange = async () => {
    if (!plan || changing) return;
    setChanging(true);
    setError('');
    setSuccess('');
    let failure = '';
    try {
      const result = await invoke<ChangeResult>('apply_change', {
        token: plan.token,
        confirmed: true,
      });
      setSuccess(result.message);
      setPage('backups');
    } catch (cause) {
      failure = String(cause);
    } finally {
      setPlan(null);
      setBackupRevision((value) => value + 1);
      await startScan();
      if (failure) setError(failure);
      setChanging(false);
    }
  };

  const reviewClean = async (mode: 'quick' | 'selected', entryIds: string[]) => {
    if (scanning || changing || plan || cleanPlan) return;
    setChanging(true);
    setError('');
    setSuccess('');
    try {
      setCleanPlan(await invoke<CleanPlan>('prepare_clean', { mode, entryIds }));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setChanging(false);
    }
  };
  const confirmClean = async () => {
    if (!cleanPlan || changing) return;
    setChanging(true);
    setError('');
    setSuccess('');
    let failure = '';
    try {
      const result = await invoke<CleanResult>('apply_clean', {
        token: cleanPlan.token,
        confirmed: true,
      });
      setSuccess(
        `${result.completed.length} registry entries cleaned. Each completed change has its own backup.`,
      );
      if (result.failed)
        failure = `Cleaning stopped at ${result.failed.name}: ${result.failed.reason} ${result.notAttempted} remaining entries were not attempted.`;
      setPage('backups');
    } catch (cause) {
      failure = String(cause);
    } finally {
      setCleanPlan(null);
      setBackupRevision((value) => value + 1);
      await startScan();
      if (failure) setError(failure);
      setChanging(false);
    }
  };

  const chooseCategory = (next: Category | 'all') => {
    setCategory(next);
    setTablePage(0);
    setPage('results');
  };

  const scanButton = (
    <button
      className="primary-button"
      disabled={scanning || changing || Boolean(plan) || Boolean(cleanPlan)}
      onClick={startScan}
    >
      {scanning ? (
        <RotateCw className="spin" size={16} />
      ) : report ? (
        <RotateCw size={16} />
      ) : (
        <Play size={16} fill="currentColor" />
      )}
      {scanning ? 'Scanning…' : report ? 'Scan again' : 'Start scan'}
      {!scanning && <ArrowRight size={16} />}
    </button>
  );

  const resultsTable = (
    <section className="panel results-panel" aria-labelledby="results-title">
      <div className="panel-heading">
        <div>
          <h2 id="results-title">
            {page === 'overview' ? 'Registry entries' : 'Scan results'}
            <span className="count-chip">{report ? formatNumber(report.entries.length) : '—'}</span>
          </h2>
          <p>Real entries. Clear findings. Explore the reason behind every result.</p>
        </div>
        <ListFilter size={18} className="muted" />
      </div>
      <div className="table-toolbar">
        <label className="search-field">
          <Search size={16} />
          <input
            aria-label="Search entries"
            placeholder="Search name, path, or publisher…"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setTablePage(0);
            }}
          />
          {query && (
            <button
              aria-label="Clear search"
              onClick={() => {
                setQuery('');
                setTablePage(0);
              }}
            >
              <X size={14} />
            </button>
          )}
        </label>
        <select
          aria-label="Filter by category"
          value={category}
          onChange={(event) => {
            setCategory(event.target.value as Category | 'all');
            setTablePage(0);
          }}
        >
          <option value="all">All categories</option>
          {Object.entries(categories).map(([key, value]) => (
            <option key={key} value={key}>
              {value.label}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by status"
          value={status}
          onChange={(event) => {
            setStatus(event.target.value as EntryStatus | 'all');
            setTablePage(0);
          }}
        >
          <option value="all">All statuses</option>
          {Object.entries(statuses).map(([key, value]) => (
            <option key={key} value={key}>
              {value.label}
            </option>
          ))}
        </select>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Entry name</th>
              <th>Category</th>
              <th>Source</th>
              <th>Status</th>
              <th>
                <span className="sr-only">Details</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((entry) => {
              const Icon = categoryIcons[entry.category];
              return (
                <tr key={entry.id}>
                  <td>
                    <button className="entry-button" onClick={() => setSelected(entry)}>
                      <span className="entry-icon">
                        <Icon size={16} />
                      </span>
                      <span className="entry-name">
                        <strong>{entry.name || '(Default)'}</strong>
                        <span className="mono">{entry.assessment.target || entry.keyPath}</span>
                      </span>
                    </button>
                  </td>
                  <td className="category-cell">{categories[entry.category].short}</td>
                  <td>
                    <span className="source-label">{entry.hive}</span>
                    <span className="view-label">{viewLabel(entry.view)}</span>
                  </td>
                  <td>
                    <span className={`status-badge ${entry.assessment.status}`}>
                      <StatusIcon status={entry.assessment.status} />
                      {statuses[entry.assessment.status].short}
                    </span>
                  </td>
                  <td>
                    <button
                      className="icon-button row-open"
                      aria-label={`${entry.name} details`}
                      onClick={() => setSelected(entry)}
                    >
                      <ArrowUpRight size={17} />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon">
            {report ? <Search size={28} /> : <FileSearch size={30} />}
          </div>
          <h3>{report ? 'No entries match your filters' : 'Start with your first scan'}</h3>
          <p>
            {report
              ? 'Try a different search or clear your filters to see other entries.'
              : 'Your startup entries, application paths, uninstall records, Open with suggestions, and COM DLL mappings will appear here.'}
          </p>
          {report && (
            <button
              className="secondary-button"
              onClick={() => {
                setQuery('');
                setCategory('all');
                setStatus('all');
                setTablePage(0);
              }}
            >
              Clear filters
            </button>
          )}
        </div>
      )}
      <div className="table-footer">
        <span>
          {report
            ? `Showing ${filtered.length ? currentPage * PAGE_SIZE + 1 : 0}–${Math.min((currentPage + 1) * PAGE_SIZE, filtered.length)} of ${formatNumber(filtered.length)} entries`
            : 'No scan yet'}
          {scanning && report && ' · Previous scan'}
        </span>
        <div>
          <button
            className="icon-button"
            aria-label="Previous page"
            disabled={currentPage === 0}
            onClick={() => setTablePage(currentPage - 1)}
          >
            <ChevronLeft size={16} />
          </button>
          <span>
            {currentPage + 1} / {maxPage + 1}
          </span>
          <button
            className="icon-button"
            aria-label="Next page"
            disabled={currentPage >= maxPage}
            onClick={() => setTablePage(currentPage + 1)}
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
    </section>
  );

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a
          className="brand"
          href="#"
          onClick={(event) => {
            event.preventDefault();
            setPage('overview');
          }}
          aria-label="RustRegistry overview"
        >
          <span className="brand-mark">
            <i />
            <i />
            <i />
            <i />
          </span>
          <span>
            Rust<span className="brand-light">Registry</span>
            <small>WINDOWS REGISTRY EXPLORER</small>
          </span>
        </a>
        <div className="workspace-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {(
            [
              ['overview', LayoutDashboard],
              ['clean', Zap],
              ['results', FileSearch],
              ['coverage', SlidersHorizontal],
              ['history', History],
              ['backups', ArchiveRestore],
            ] as [Page, LucideIcon][]
          ).map(([key, Icon]) => (
            <button
              key={key}
              className={`nav-item ${page === key ? 'active' : ''}`}
              aria-current={page === key ? 'page' : undefined}
              onClick={() => setPage(key)}
            >
              <Icon size={18} />
              <span>{pageNames[key]}</span>
              {key === 'results' && report && (
                <span className="nav-count">{report.entries.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="safety-card">
            <div className="safety-icon">
              <ShieldCheck size={19} />
            </div>
            <strong>Explore with confidence.</strong>
            <p>
              Every scan is read-only.
              <br />
              You stay in control.
            </p>
            <span>
              <span className="live-dot" /> Backups before changes
            </span>
          </div>
          <button
            className={`nav-item ${page === 'about' ? 'active' : ''}`}
            onClick={() => setPage('about')}
          >
            <CircleHelp size={18} />
            <span>About RustRegistry</span>
            <ArrowUpRight size={14} />
          </button>
          <div className="sidebar-version">
            <span>v{packageInfo.version}</span>
            <span className="preview-pill">EARLY ACCESS</span>
          </div>
        </div>
      </aside>

      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <Monitor size={16} />
            <span>This computer</span>
            <ChevronRight size={14} />
            <strong>{pageNames[page]}</strong>
          </div>
          <div className="topbar-actions">
            <span className="readonly-pill">
              <LockKeyhole size={13} /> Protected changes
            </span>
            <span className="topbar-divider" />
            <button
              className="icon-button theme-toggle"
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            >
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            </button>
          </div>
        </header>

        <main className="main-content">
          <div className="page-heading">
            <div>
              <span className="eyebrow">REGISTRY HEALTH EXPLORER</span>
              <h1>{pageNames[page]}</h1>
              <p>
                {page === 'overview'
                  ? 'A clearer view of your Windows registry.'
                  : page === 'results'
                    ? 'Search your entries, filter findings, and understand every result.'
                    : page === 'coverage'
                      ? 'See exactly where we looked and what could be read.'
                      : page === 'backups'
                        ? 'Review local backups and restore without overwriting existing values.'
                        : page === 'history'
                          ? 'Your most recent scans from this session.'
                          : 'Built to help you understand your Windows registry.'}
              </p>
            </div>
            {page !== 'overview' && page !== 'about' && scanButton}
            {page === 'overview' && (
              <div className="platform-label">
                <span className="live-dot" />
                {desktop ? 'Windows x64 · Connected locally' : 'Browser preview'}
              </div>
            )}
          </div>

          {!desktop && (
            <div className="notice info-notice">
              <Monitor size={18} />
              <p>
                <strong>Desktop connection unavailable.</strong> Open the RustRegistry desktop app
                for live registry data. No sample data is shown in preview.
              </p>
            </div>
          )}
          {error && (
            <div className="notice error-notice" role="alert">
              <TriangleAlert size={18} />
              <p>{error}</p>
              <button
                className="icon-button"
                aria-label="Dismiss error"
                onClick={() => setError('')}
              >
                <X size={16} />
              </button>
            </div>
          )}

          {success && (
            <div className="notice success-notice" role="status">
              <ShieldCheck size={18} />
              <p>{success}</p>
              <button
                className="icon-button"
                aria-label="Dismiss success"
                onClick={() => setSuccess('')}
              >
                <X size={16} />
              </button>
            </div>
          )}
          {scanning && (
            <div className="scan-progress" role="status" aria-live="polite">
              <div className="progress-main">
                <span className="progress-spinner">
                  <RotateCw size={20} className="spin" />
                </span>
                <div>
                  <strong>{stopping ? 'Stopping scan…' : 'Reading registry…'}</strong>
                  <span className="mono">{progress.current}</span>
                </div>
                <span className="progress-count">{formatNumber(progress.entries)} entries</span>
                <button className="secondary-button" disabled={stopping} onClick={stopScan}>
                  <Square size={12} />
                  {stopping ? 'Please wait' : 'Stop'}
                </button>
              </div>
              <div
                className="progress-track"
                role="progressbar"
                aria-label="Scan progress"
                aria-valuenow={progressPercent}
                aria-valuemin={0}
                aria-valuemax={100}
              >
                <i style={{ width: `${progressPercent}%` }} />
              </div>
            </div>
          )}
          {report?.cancelled && !scanning && (
            <div className="notice info-notice">
              <CirclePause size={18} />
              <p>Scan stopped. These results only include the sections that could be read.</p>
            </div>
          )}

          {page === 'clean' && (
            <CleanPanel
              entries={report?.entries || []}
              complete={Boolean(report && !report.cancelled)}
              busy={scanning || changing || Boolean(plan) || Boolean(cleanPlan)}
              onReview={reviewClean}
              onScan={startScan}
            />
          )}

          {page === 'overview' && (
            <>
              <section className="hero">
                <div className="hero-content">
                  <div className="hero-kicker">
                    <span className="hero-kicker-icon">
                      <Activity size={13} />
                    </span>{' '}
                    MEET YOUR SYSTEM
                  </div>
                  <h2>
                    Every entry
                    <br />
                    tells a story.
                  </h2>
                  <p>
                    From startup entries to application paths,
                    <br className="wide-break" /> understand what makes your system tick.
                  </p>
                  <div className="hero-actions">
                    {scanButton}
                    <button
                      className="secondary-button"
                      disabled={scanning || changing}
                      onClick={() => {
                        setPage('clean');
                        if (!report) void startScan();
                      }}
                    >
                      <Zap size={16} />
                      Quick Clean
                    </button>
                    <span>
                      <ShieldCheck size={14} /> Scanning never changes entries
                    </span>
                  </div>
                </div>
                <RegistryArt scanning={scanning} />
              </section>

              <div className="stats-grid">
                <button
                  className="stat-card"
                  onClick={() => {
                    setStatus('all');
                    chooseCategory('all');
                  }}
                >
                  <span className="stat-label">
                    Entries scanned
                    <Boxes size={17} />
                  </span>
                  <strong>{report ? formatNumber(report.entries.length) : '—'}</strong>
                  <span className="stat-description">
                    {report
                      ? `${report.scopes.length} registry locations`
                      : 'Waiting for your first scan'}
                  </span>
                  <ArrowUpRight size={16} className="stat-arrow" />
                </button>
                <button
                  className="stat-card"
                  onClick={() => {
                    setStatus('review');
                    chooseCategory('all');
                  }}
                >
                  <span className="stat-label">
                    Suggested reviews
                    <TriangleAlert size={17} className="amber" />
                  </span>
                  <strong className={counts.review ? 'amber' : ''}>
                    {report ? formatNumber(counts.review) : '—'}
                  </strong>
                  <span className="stat-description">Entries with a missing local target</span>
                  <ArrowUpRight size={16} className="stat-arrow" />
                </button>
                <button className="stat-card" onClick={() => setPage('coverage')}>
                  <span className="stat-label">
                    Last scan
                    <Clock3 size={17} />
                  </span>
                  <strong className="time-stat">
                    {report ? formatTime(report.startedAt) : 'Not yet'}
                  </strong>
                  <span className="stat-description">
                    {report
                      ? `${formatDuration(report.durationMs)} elapsed${report.cancelled ? ' · Stopped' : ' · Read-only'}`
                      : 'Start whenever you’re ready'}
                  </span>
                  <ArrowUpRight size={16} className="stat-arrow" />
                </button>
              </div>

              <div className="section-caption">
                <h2>Scan categories</h2>
                <button className="text-button" onClick={() => setPage('coverage')}>
                  View coverage <ArrowRight size={14} />
                </button>
              </div>
              <div className="category-grid">
                {(Object.keys(categories) as Category[]).map((key) => {
                  const Icon = categoryIcons[key];
                  const count = report?.entries.filter((entry) => entry.category === key).length;
                  return (
                    <button className="category-card" key={key} onClick={() => chooseCategory(key)}>
                      <span className={`category-icon ${key}`}>
                        <Icon size={20} />
                      </span>
                      <span>
                        <strong>{categories[key].label}</strong>
                        <small>
                          {count === undefined
                            ? categories[key].description
                            : `${formatNumber(count)} entries scanned`}
                        </small>
                      </span>
                      <ChevronRight size={16} />
                    </button>
                  );
                })}
              </div>

              <div className="dashboard-bottom">
                {resultsTable}
                <aside className="insight-panel">
                  <div className="insight-heading">
                    <span className="insight-icon">
                      <Sparkles size={18} />
                    </span>
                    <span>GOOD TO KNOW</span>
                  </div>
                  <h3>
                    A finding isn’t
                    <br />
                    always a problem.
                  </h3>
                  <p>
                    A missing path may belong to a disconnected drive or an app you’ve already
                    uninstalled.
                  </p>
                  <div className="insight-line" />
                  <div className="legend">
                    <span className="found">
                      <CircleCheck size={15} /> Target found
                    </span>
                    <p>The local file or folder exists.</p>
                    <span className="review">
                      <TriangleAlert size={15} /> Review suggested
                    </span>
                    <p>The specified local target was not found.</p>
                    <span className="unknown">
                      <CircleHelp size={15} /> Unverified
                    </span>
                    <p>The target is unclear or inaccessible.</p>
                  </div>
                  <button className="text-button" onClick={() => setPage('about')}>
                    How it works <ArrowUpRight size={14} />
                  </button>
                </aside>
              </div>
            </>
          )}

          {page === 'results' && (
            <>
              <div className="result-summary">
                <span>
                  <span className="live-dot" />
                  {report ? `${formatNumber(report.entries.length)} entries` : 'Waiting for a scan'}
                </span>
                <button
                  className={status === 'found' ? 'selected' : ''}
                  onClick={() => {
                    setStatus(status === 'found' ? 'all' : 'found');
                    setTablePage(0);
                  }}
                >
                  <CircleCheck size={15} />
                  {counts.found} targets found
                </button>
                <button
                  className={status === 'review' ? 'selected' : ''}
                  onClick={() => {
                    setStatus(status === 'review' ? 'all' : 'review');
                    setTablePage(0);
                  }}
                >
                  <TriangleAlert size={15} />
                  {counts.review} to review
                </button>
                <button
                  className={status === 'unknown' ? 'selected' : ''}
                  onClick={() => {
                    setStatus(status === 'unknown' ? 'all' : 'unknown');
                    setTablePage(0);
                  }}
                >
                  <CircleHelp size={15} />
                  {counts.unknown} unverified
                </button>
              </div>
              {resultsTable}
            </>
          )}

          {page === 'coverage' && (
            <>
              <div className="coverage-intro">
                <div className="coverage-symbol">
                  <SlidersHorizontal size={28} />
                </div>
                <div>
                  <h2>Focused scope. Transparent results.</h2>
                  <p>
                    This release checks 21 locations, including separate 32-bit and 64-bit COM views
                    in both hives. File association Classes roots are shared and read once per hive.
                    Services use the shared system view. Other application locations use their
                    documented 32-bit, 64-bit, or shared views.
                  </p>
                </div>
              </div>
              {!report ? (
                <div className="panel empty-state">
                  <FileSearch size={32} className="muted" />
                  <h3>No coverage report yet</h3>
                  <p>Start a scan to see access status and entry counts for each location.</p>
                </div>
              ) : (
                <div className="scope-list">
                  {report.scopes.map((scope) => (
                    <details key={scope.id} className="scope-item">
                      <summary>
                        <span
                          className={`scope-dot ${scope.status === 'complete' ? 'found' : scope.status === 'missing' ? 'unknown' : 'review'}`}
                        />
                        <span className="scope-name">
                          <strong>{categories[scope.category].label}</strong>
                          <span className="mono">
                            {scope.hive} · {viewLabel(scope.view)} · {scope.keyPath}
                          </span>
                        </span>
                        <span className="scope-status">{scopeLabel(scope.status)}</span>
                        <span className="scope-count">{scope.entries} entries</span>
                        <ChevronRight size={16} />
                      </summary>
                      <div className="scope-notes">
                        {scope.notes.length ? (
                          scope.notes.map((note, i) => <p key={i}>{note}</p>)
                        ) : (
                          <p>
                            Entries in this location were read. Each location is limited to 10,000
                            entries.
                          </p>
                        )}
                      </div>
                    </details>
                  ))}
                </div>
              )}
              <div className="notice info-notice">
                <Info size={18} />
                <p>
                  An absent key may be normal. Inaccessible, limited, and incomplete locations are
                  reported separately. {report && `${scopeIssues} locations have additional notes.`}
                </p>
              </div>
            </>
          )}

          {page === 'history' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Scans in this session</h2>
                  <p>The last 8 scans are kept in memory and cleared when you close the app.</p>
                </div>
                <History size={19} className="muted" />
              </div>
              {history.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">
                    <History size={30} />
                  </div>
                  <h3>No scans yet</h3>
                  <p>Your first completed scan will appear here.</p>
                </div>
              ) : (
                <div className="history-list">
                  {history.map((item) => (
                    <button
                      key={item.id}
                      className="history-item"
                      onClick={() => {
                        setReport(item);
                        setCategory('all');
                        setStatus('all');
                        setQuery('');
                        setTablePage(0);
                        setPage('results');
                      }}
                    >
                      <span className="history-icon">
                        {item.cancelled ? <CirclePause size={20} /> : <CheckCheck size={20} />}
                      </span>
                      <span>
                        <strong>
                          {formatTime(item.startedAt)} ·{' '}
                          {item.cancelled ? 'Stopped scan' : 'Registry scan'}
                        </strong>
                        <small>
                          {formatNumber(item.entries.length)} entries ·{' '}
                          {formatDuration(item.durationMs)} · {item.scopes.length}/21 locations
                        </small>
                      </span>
                      <span className="readonly-pill">
                        <LockKeyhole size={12} />
                        Read-only
                      </span>
                      <ArrowUpRight size={18} />
                    </button>
                  ))}
                </div>
              )}
            </section>
          )}

          {page === 'backups' && (
            <BackupsPanel
              revision={backupRevision}
              busy={changing || scanning}
              onRestore={(id) => reviewChange(undefined, id)}
            />
          )}
          {page === 'about' && (
            <div className="about-grid">
              <section className="panel about-panel">
                <div className="about-logo">
                  <Boxes size={32} />
                </div>
                <span className="eyebrow">RUSTREGISTRY · V{packageInfo.version} · MIT LICENSE</span>
                <h2>
                  Understand first.
                  <br />
                  Decide with clarity.
                </h2>
                <p>
                  RustRegistry reads selected application records in the Windows registry and checks
                  their local target paths. Every finding comes with an explanation.
                </p>
                <div className="about-fact">
                  <ShieldCheck size={19} />
                  <span>
                    <strong>Read-only scanning</strong>Scans use KEY_READ. Separately reviewed
                    changes support missing-target HKCU Run values, guarded App Paths mappings, and
                    orphaned uninstall listing visibility, and orphaned Open with suggestions, with
                    verified backups and Windows transactions.
                  </span>
                </div>
                <div className="about-fact">
                  <Monitor size={19} />
                  <span>
                    <strong>Local by design</strong>Scan data is not sent anywhere. Results stay in
                    memory; confirmed changes keep their original values in your local backup
                    folder.
                  </span>
                </div>
                <div className="about-fact">
                  <TerminalSquare size={19} />
                  <span>
                    <strong>Rust + Tauri 2</strong>Scanning runs in the background, keeping the
                    interface responsive.
                  </span>
                </div>
              </section>
              <section className="panel about-panel">
                <span className="eyebrow">SCOPE & LIMITATIONS</span>
                <h3>Make sense of your results.</h3>
                <p>
                  “Target found” indicates that the file, folder, or suggested file-type
                  registration exists. It does not prove that the application works or that every
                  part of its registry entry is valid.
                </p>
                <ul className="limits-list">
                  <li>
                    <ArrowDownLeft size={17} />
                    Network and device paths are not accessed automatically.
                  </li>
                  <li>
                    <ArrowDownLeft size={17} />
                    Ambiguous commands and unresolved environment variables are marked as
                    unverified.
                  </li>
                  <li>
                    <ArrowDownLeft size={17} />
                    Uninstall scans check InstallLocation; repair also verifies local uninstall
                    executables.
                  </li>
                  <li>
                    <ArrowDownLeft size={17} />
                    File association checks cover Open with registration references only. Default
                    handlers and full system configuration are outside scan scope. COM checks cover
                    DLL, handler, and local-server mappings. Services and shared DLL references
                    remain read-only; 32-bit targets are inventoried without probing.
                  </li>
                  <li>
                    <ArrowDownLeft size={17} />
                    Administrator access is not requested. Unreadable locations appear in the
                    coverage report.
                  </li>
                </ul>
                <div className="about-callout">
                  <Info size={18} />
                  <p>
                    This release targets Windows x64. It does not assign a health score to the
                    entire registry or promise performance improvements.
                  </p>
                </div>
              </section>
            </div>
          )}

          <footer className="content-footer">
            <span>
              <ShieldCheck size={13} /> Runs on your computer. Your data stays yours.
            </span>
            <span>
              Built with Rust <span className="footer-dot">·</span> Windows x64
            </span>
          </footer>
        </main>
      </div>
      {selected && (
        <DetailDialog
          key={selected.id}
          entry={selected}
          close={() => setSelected(null)}
          review={(entry) => reviewChange(entry)}
          busy={scanning || changing}
        />
      )}
      {cleanPlan && (
        <CleanConfirmation
          plan={cleanPlan}
          busy={changing}
          onCancel={cancelChange}
          onConfirm={confirmClean}
        />
      )}
      {plan && (
        <ChangeConfirmation
          key={plan.token}
          plan={plan}
          busy={changing}
          onCancel={cancelChange}
          onConfirm={confirmChange}
        />
      )}
    </div>
  );
}
