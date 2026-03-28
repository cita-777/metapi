import { mergeAccountExtraConfig } from './accountExtraConfig.js';
import { formatLocalDate } from './localTimeService.js';

type TodayIncomeSnapshot = {
  day: string;
  baseline?: number;
  latest: number;
  updatedAt?: string;
};

type EstimateRewardInput = {
  day: string;
  successCount: number;
  parsedRewardCount: number;
  rewardSum: number;
  extraConfig?: string | Record<string, unknown> | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function parseObject(value: string | Record<string, unknown> | null | undefined): Record<string, unknown> {
  if (!value) return {};
  if (isRecord(value)) return value;
  if (typeof value !== 'string') return {};
  try {
    const parsed = JSON.parse(value);
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function toNonNegativeNumber(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  if (value < 0) return null;
  return value;
}

function normalizeSnapshot(raw: unknown): TodayIncomeSnapshot | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const day = typeof record.day === 'string' ? record.day.trim() : '';
  if (!day) return null;

  const latest = toNonNegativeNumber(record.latest);
  if (latest == null) return null;

  const baseline = toNonNegativeNumber(record.baseline);

  return {
    day,
    baseline: baseline ?? latest,
    latest,
    updatedAt: typeof record.updatedAt === 'string' ? record.updatedAt.trim() : undefined,
  };
}

function extractTodayIncomeSnapshot(extraConfig?: string | Record<string, unknown> | null): TodayIncomeSnapshot | null {
  const parsed = parseObject(extraConfig);
  return normalizeSnapshot(parsed.todayIncomeSnapshot);
}

export function getTodayIncomeDelta(
  extraConfig: string | Record<string, unknown> | null | undefined,
  day: string,
): number {
  if (!day) return 0;
  const snapshot = extractTodayIncomeSnapshot(extraConfig);
  if (!snapshot || snapshot.day !== day) return 0;

  const baseline = typeof snapshot.baseline === 'number' ? snapshot.baseline : snapshot.latest;
  const delta = snapshot.latest - baseline;
  if (!Number.isFinite(delta) || delta <= 0) return 0;
  return delta;
}

export function getTodayIncomeValue(
  extraConfig: string | Record<string, unknown> | null | undefined,
  day: string,
): number {
  if (!day) return 0;
  const snapshot = extractTodayIncomeSnapshot(extraConfig);
  if (!snapshot || snapshot.day !== day) return 0;
  return snapshot.latest;
}

export function updateTodayIncomeSnapshot(
  extraConfig: string | Record<string, unknown> | null | undefined,
  todayIncome: number,
  now = new Date(),
): string | null {
  const income = toNonNegativeNumber(todayIncome);
  if (income == null) {
    if (typeof extraConfig === 'string') return extraConfig || null;
    if (extraConfig == null) return null;
    return JSON.stringify(parseObject(extraConfig));
  }

  const day = formatLocalDate(now);
  const existing = extractTodayIncomeSnapshot(extraConfig);
  let baseline = income;
  let latest = income;

  if (existing && existing.day === day) {
    baseline = typeof existing.baseline === 'number' ? existing.baseline : existing.latest;
    if (income < baseline) baseline = income;
    latest = income;
  }

  return mergeAccountExtraConfig(extraConfig, {
    todayIncomeSnapshot: {
      day,
      baseline,
      latest,
      updatedAt: now.toISOString(),
    },
  });
}

export function estimateRewardWithTodayIncomeFallback(input: EstimateRewardInput): number {
  const rewardSum = Number.isFinite(input.rewardSum) && input.rewardSum > 0 ? input.rewardSum : 0;
  if (!Number.isFinite(input.successCount) || input.successCount <= 0) return rewardSum;

  const hasMissingReward = input.parsedRewardCount < input.successCount;
  if (!hasMissingReward && rewardSum > 0) return rewardSum;

  const incomeValue = getTodayIncomeValue(input.extraConfig, input.day);
  return incomeValue > rewardSum ? incomeValue : rewardSum;
}
