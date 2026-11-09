export type BackupState = 'restore_available' | 'original_present' | 'conflict' | 'unverified';
export type BackupStateFilter = BackupState | 'all';
export interface SearchableBackup {
  id: string;
  name: string;
  registryPath: string;
  valueName: string;
  scope: string;
  state: BackupState;
  registryView?: string;
}

const scopeLabels: Record<string, string> = {
  application_leftover: 'Correlated application leftover',
  sound_event: 'Current sound assignment',
  startup: 'Startup',
  app_path: 'Application path',
  uninstall: 'Uninstall',
  association: 'File association',
  com: 'COM mapping',
  service: 'Service startup',
  application: 'Application suggestion',
  shared_dll: 'Shared DLL reference · 64 bit',
  registered_app: 'Application registration',
  type_library: 'Type library · win64',
  prog_id: 'COM ProgID mapping',
  interface: 'COM interface TypeLib reference',
  com_proxy: 'COM proxy reference',
  application_icon: 'Application icon reference',
  shell_menu: 'Context-menu visibility',
  com_redirection: 'COM class redirection',
  font_reference: 'Font reference',
  help_reference: 'Help-file reference',
  mui_cache: 'Application display cache',
  run_history: 'Run dialog registry history',
  typed_paths: 'Explorer typed-path registry history',
  com_conversion: 'COM conversion reference',
};
export function backupScopeLabel(scope: string, view?: string): string {
  if (scope === 'com') return `COM mapping · ${view || '64'} bit`;
  return scopeLabels[scope] || scope.replaceAll('_', ' ');
}

export function filterBackups<T extends SearchableBackup>(
  backups: readonly T[],
  query: string,
  state: BackupStateFilter,
): T[] {
  const search = query.trim().toLowerCase();
  return backups.filter((backup) => {
    if (state !== 'all' && backup.state !== state) return false;
    return (
      !search ||
      [
        backup.name,
        backup.id,
        backup.registryPath,
        backup.valueName,
        backup.scope,
        backupScopeLabel(backup.scope, backup.registryView),
      ].some((field) => field.toLowerCase().includes(search))
    );
  });
}
