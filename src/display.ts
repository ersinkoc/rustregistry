export const displayScales = [100, 125, 150, 175, 200] as const;

export function initialDisplayScale(saved: string | null, screenWidth: number, pixelRatio: number) {
  const preferred = Number(saved);
  if (saved !== null && displayScales.some((scale) => scale === preferred)) return preferred;
  // Windows already scales a high-DPI desktop; add a default boost only at near-100% OS scaling.
  return screenWidth * pixelRatio >= 3000 && pixelRatio <= 1.1 ? 150 : 100;
}
