import { expect } from '@playwright/test';
import { resolve } from 'node:path';

export async function verifyDisplayScale(page, cdp, output, checked, summary) {
  const setScale = async (percent) => {
    await page.getByRole('combobox', { name: 'Interface size' }).selectOption(String(percent));
    await page.evaluate(
      (value) => window.__TAURI_INTERNALS__.invoke('set_display_scale', { percent: value }),
      percent,
    );
  };
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 3840,
    height: 2160,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await setScale(100);
  const base = await page.evaluate(() => ({
    ratio: devicePixelRatio,
    width: innerWidth,
    text: parseFloat(getComputedStyle(document.body).fontSize),
  }));
  await page.screenshot({ path: resolve(output, 'desktop-4k-100.png'), fullPage: true });
  await setScale(150);
  await page.waitForFunction((ratio) => devicePixelRatio > ratio * 1.35, base.ratio);
  const enlarged = await page.evaluate(() => ({
    ratio: devicePixelRatio,
    width: innerWidth,
    text: parseFloat(getComputedStyle(document.body).fontSize),
    overflow: document.documentElement.scrollWidth > innerWidth,
  }));
  expect(enlarged.overflow).toBe(false);
  expect(enlarged.text * enlarged.ratio).toBeGreaterThan(base.text * base.ratio * 1.35);
  await page.screenshot({ path: resolve(output, 'desktop-4k-150.png'), fullPage: true });
  await page.reload();
  await expect(page.getByRole('combobox', { name: 'Interface size' })).toHaveValue('150');
  expect(await page.evaluate(() => localStorage.getItem('rustregistry-ui-scale'))).toBe('150');
  for (const percent of [175, 200]) {
    await setScale(percent);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
  }
  const invalidRefused = await page.evaluate(async () => {
    try {
      await window.__TAURI_INTERNALS__.invoke('set_display_scale', { percent: 0 });
      return false;
    } catch (error) {
      return String(error).includes('Unsupported interface size');
    }
  });
  expect(invalidRefused).toBe(true);
  await setScale(100);
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 960,
    deviceScaleFactor: 1,
    mobile: false,
  });
  summary.displayScale = { base, enlarged };
  checked(
    '4K native zoom visibly enlarges text/controls, survives reload, rejects invalid sizes, and fits at 150–200%',
  );
}
