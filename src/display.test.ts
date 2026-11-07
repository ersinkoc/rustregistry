import { expect, it } from 'vitest';
import { initialDisplayScale } from './display';

it('defaults to a readable size on 4K at 100% without double-scaling Windows DPI', () => {
  expect(initialDisplayScale(null, 3840, 1)).toBe(150);
  expect(initialDisplayScale(null, 1920, 1)).toBe(100);
  expect(initialDisplayScale(null, 2560, 1.5)).toBe(100);
  expect(initialDisplayScale(null, 3072, 1.25)).toBe(100);
});
it('keeps a valid saved preference and recovers from unsupported stored values', () => {
  expect(initialDisplayScale('100', 3840, 1)).toBe(100);
  expect(initialDisplayScale('175', 1920, 1)).toBe(175);
  expect(initialDisplayScale('0', 3840, 1)).toBe(150);
  expect(initialDisplayScale('NaN', 1920, 1)).toBe(100);
});
