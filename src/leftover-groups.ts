import type { RegistryEntry } from './model';
export function isSupportedType(entry: RegistryEntry) {
  return (
    entry.category === 'application_leftovers' &&
    /^Software\\Classes\\Applications\\[^\\]+\.exe\\SupportedTypes$/i.test(entry.keyPath)
  );
}
export function leftoverActionName(entry: RegistryEntry) {
  return isSupportedType(entry) || isUrlMetadata(entry)
    ? `${entry.name} (${entry.valueName})`
    : entry.name;
}
export function isUrlMetadata(entry: RegistryEntry) {
  return (
    entry.category === 'application_leftovers' &&
    /^Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\[^\\]+\.exe$/i.test(entry.keyPath) &&
    /^(SupportedProtocols|UseUrl)$/i.test(entry.valueName)
  );
}
export function leftoverGroups(entries: RegistryEntry[]): RegistryEntry[] {
  const groups = new Map<string, RegistryEntry>();
  for (const entry of entries) {
    const evidence = entry.leftoverEvidence;
    if (
      entry.category !== 'application_leftovers' ||
      !evidence ||
      entry.assessment.status !== 'review'
    )
      continue;
    const key = JSON.stringify(
      [evidence.executable, evidence.directory, evidence.uninstallPath].map((part) =>
        part.toLowerCase(),
      ),
    );
    const previous = groups.get(key);
    const chosen = previous?.leftoverRepairable ? previous : entry;
    groups.set(key, {
      ...chosen,
      leftoverEvidence: {
        ...chosen.leftoverEvidence!,
        relatedIds: [
          ...new Set([
            ...(previous?.leftoverEvidence?.relatedIds ?? []),
            ...evidence.relatedIds,
            entry.id,
          ]),
        ],
      },
    });
  }
  return [...groups.values()];
}
