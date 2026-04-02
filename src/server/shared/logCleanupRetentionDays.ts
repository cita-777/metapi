export function normalizeLogCleanupRetentionDays(value: unknown, fallback = 30): number {
  const parsed = Number(value);
  if (Number.isFinite(parsed) && parsed >= 1) return Math.trunc(parsed);

  const fallbackParsed = Number(fallback);
  if (Number.isFinite(fallbackParsed) && fallbackParsed >= 1) return Math.trunc(fallbackParsed);

  return 30;
}
