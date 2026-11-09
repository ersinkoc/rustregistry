import { describe, expect, it } from 'vitest';
import { asHistoricalReport } from './Recovery';
import { canQuarantine } from './Changes';
import type { ScanReport } from './model';
describe('saved scan isolation', () => {
  it('marks report and every entry read-only without modifying the live report', () => {
    const live = {
      id: 'live',
      entries: [
        {
          id: 'owned',
          category: 'startup',
          hive: 'HKCU',
          view: 'shared',
          keyPath: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
          assessment: { status: 'review' },
        },
      ],
    } as ScanReport;
    const archived = asHistoricalReport(live);
    expect(archived.historical).toBe(true);
    expect(archived.entries[0].historical).toBe(true);
    expect(canQuarantine(archived.entries[0])).toBe(false);
    expect(live.historical).toBeUndefined();
    expect(live.entries[0].historical).toBeUndefined();
    expect(archived.entries).not.toBe(live.entries);
  });
});
