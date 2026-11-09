import type { RegistryEntry } from './model';
export function isSupportedType(entry: RegistryEntry) {
  return (
    entry.category === 'application_leftovers' &&
    /^Software\\Classes\\Applications\\[^\\]+\.exe\\SupportedTypes$/i.test(entry.keyPath)
  );
}
export function leftoverActionName(entry: RegistryEntry) {
  return isSupportedType(entry) ? `${entry.name} (${entry.valueName})` : entry.name;
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
    const key = `${evidence.applicationPath.toLowerCase()}|${evidence.uninstallPath.toLowerCase()}`;
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
