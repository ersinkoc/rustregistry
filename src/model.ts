export type Category = 'startup' | 'app_paths' | 'uninstall';
export type EntryStatus = 'found' | 'review' | 'unknown';

export interface RegistryEntry {
  id: string;
  name: string;
  category: Category;
  hive: string;
  keyPath: string;
  view: string;
  valueName: string;
  valueType: string;
  rawValue: string;
  appPathRepairable?: boolean;
  uninstallRepairable?: boolean;
  uninstallHidden?: boolean;
  publisher: string | null;
  version: string | null;
  assessment: {
    status: EntryStatus;
    code: string;
    explanation: string;
    target: string | null;
  };
}

export interface ScanScope {
  id: string;
  category: Category;
  hive: string;
  keyPath: string;
  view: string;
  status: string;
  entries: number;
  notes: string[];
}

export interface ScanReport {
  id: string;
  startedAt: number;
  durationMs: number;
  cancelled: boolean;
  readOnly: boolean;
  architecture: string;
  entries: RegistryEntry[];
  scopes: ScanScope[];
}

export interface ScanProgress {
  completed: number;
  total: number;
  entries: number;
  current: string;
}

export const categories: Record<Category, { label: string; description: string; short: string }> = {
  startup: {
    label: 'Startup entries',
    description: 'Local targets of Run and RunOnce commands',
    short: 'Startup',
  },
  app_paths: {
    label: 'Application paths',
    description: 'Executables registered under App Paths',
    short: 'App path',
  },
  uninstall: {
    label: 'Uninstall records',
    description: 'Installation folders reported by applications',
    short: 'Uninstall',
  },
};

export const statuses: Record<EntryStatus, { label: string; short: string }> = {
  found: { label: 'Target found', short: 'Found' },
  review: { label: 'Review suggested', short: 'Review' },
  unknown: { label: 'Unverified', short: 'Unverified' },
};

export function filterEntries(
  entries: RegistryEntry[],
  query: string,
  category: Category | 'all',
  status: EntryStatus | 'all',
) {
  const needle = query.trim().toLocaleLowerCase('en-US');
  return entries.filter(
    (entry) =>
      (category === 'all' || entry.category === category) &&
      (status === 'all' || entry.assessment.status === status) &&
      (!needle ||
        [
          entry.name,
          entry.keyPath,
          entry.rawValue,
          entry.publisher ?? '',
          entry.assessment.target ?? '',
        ].some((text) => text.toLocaleLowerCase('en-US').includes(needle))),
  );
}

export function countStatuses(entries: RegistryEntry[]) {
  return entries.reduce(
    (counts, entry) => {
      counts[entry.assessment.status]++;
      return counts;
    },
    { found: 0, review: 0, unknown: 0 },
  );
}

export const formatNumber = (value: number) => new Intl.NumberFormat('en-US').format(value);
export const formatTime = (value: number) =>
  new Intl.DateTimeFormat('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(value);
export const formatDuration = (value: number) =>
  value < 1000
    ? `${value} ms`
    : `${(value / 1000).toLocaleString('en-US', { maximumFractionDigits: 2 })} s`;
export const viewLabel = (view: string) => (view === 'shared' ? 'Shared' : `${view} bit`);
export const scopeLabel = (status: string) =>
  ({
    complete: 'Complete',
    missing: 'Not present',
    access_denied: 'Access denied',
    error: 'Read error',
    partial: 'Partial read',
    limited: 'Limit reached',
    cancelled: 'Stopped',
  })[status] ?? status;
