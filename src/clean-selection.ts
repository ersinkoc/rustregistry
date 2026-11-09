import type { RegistryEntry } from './model';
export const MAX_CLEAN_ENTRIES = 10_000;
export const PAGE_SIZE = 50;
export function selectedCandidates(
  selected: readonly string[],
  candidates: readonly RegistryEntry[],
) {
  const ids = new Set(candidates.map((e) => e.id));
  return selected.filter((id) => ids.has(id));
}
export function pageRows<T>(rows: readonly T[], requested: number, size = PAGE_SIZE) {
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const page = Math.max(0, Math.min(requested, pages - 1));
  return {
    rows: rows.slice(page * size, (page + 1) * size),
    page,
    pages,
    start: rows.length ? page * size + 1 : 0,
    total: rows.length,
  };
}
