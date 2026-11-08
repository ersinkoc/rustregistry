import { expect } from '@playwright/test';
import { resolve } from 'node:path';
export async function verifyAppearance(page, cdp, output, checked, summary) {
  await page.getByRole('link', { name: 'RustRegistry overview', exact: true }).click();
  const initial = await page.locator('html').getAttribute('data-theme');
  expect(['dark', 'light']).toContain(initial);
  summary.appearanceStarts ??= [];
  summary.appearanceStarts.push(initial);
  if (initial === 'light') {
    await page.getByRole('button', { name: 'Switch to dark theme', exact: true }).click();
  }
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('rustregistry-theme'))).toBe('dark');
  await page.getByRole('button', { name: 'Switch to light theme', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  expect(await page.evaluate(() => localStorage.getItem('rustregistry-theme'))).toBe('light');
  await page.screenshot({ path: resolve(output, 'desktop-overview-light.png'), fullPage: true });
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 940,
    height: 700,
    deviceScaleFactor: 1,
    mobile: false,
  });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: resolve(output, 'desktop-compact-light.png'), fullPage: true });
  await page.getByRole('button', { name: 'Switch to dark theme', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('rustregistry-theme'))).toBe('dark');
  checked('Light/dark themes and the 940px minimum desktop layout render without page overflow');
}
