import { describe, expect, it } from 'vitest';
import { MAX_CLEAN_ENTRIES, pageRows, selectedCandidates } from './clean-selection';
import type { RegistryEntry } from './model';
describe('large cleaning and backup pages', () => {
  it('keeps 128 selections across pages and excludes stale selections without truncating at 100', () => {
    const entries = Array.from({ length: 128 }, (_, i) => ({ id: `${i}` }) as RegistryEntry);
    expect(MAX_CLEAN_ENTRIES).toBeGreaterThanOrEqual(128);
    expect(selectedCandidates([...entries.map((e) => e.id), 'stale'], entries)).toEqual(
      entries.map((e) => e.id),
    );
    const all = [
      ...pageRows(entries, 0).rows,
      ...pageRows(entries, 1).rows,
      ...pageRows(entries, 2).rows,
    ];
    expect(all).toEqual(entries);
  });
  it('exposes every backup beyond the former 1000-entry boundary and clamps filtered pages', () => {
    const rows = Array.from({ length: 1105 }, (_, i) => i);
    const last = pageRows(rows, 999);
    expect(last.page).toBe(22);
    expect(last.rows).toEqual([1100, 1101, 1102, 1103, 1104]);
    expect(pageRows([7], 22).rows).toEqual([7]);
    expect(pageRows([], 7)).toMatchObject({ page: 0, pages: 1, start: 0, total: 0, rows: [] });
  });
});
