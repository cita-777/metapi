import { describe, expect, it } from 'vitest';
import {
  estimateRewardWithTodayIncomeFallback,
  getTodayIncomeDelta,
  getTodayIncomeValue,
  updateTodayIncomeSnapshot,
} from './todayIncomeRewardService.js';
import { formatLocalDate } from './localTimeService.js';

describe('today income reward service', () => {
  it('records latest income value for same-day snapshots', () => {
    const now = new Date('2026-02-25T08:00:00.000Z');
    const later = new Date('2026-02-25T10:00:00.000Z');
    const day = formatLocalDate(now);

    const first = updateTodayIncomeSnapshot(null, 12, now);
    expect(getTodayIncomeValue(first, day)).toBe(12);
    expect(getTodayIncomeDelta(first, day)).toBe(0);

    const second = updateTodayIncomeSnapshot(first, 15.5, later);
    expect(getTodayIncomeValue(second, day)).toBe(15.5);
    expect(getTodayIncomeDelta(second, day)).toBe(3.5);
  });

  it('resets baseline on day change', () => {
    const firstAt = new Date('2026-02-25T09:00:00.000Z');
    const secondAt = new Date('2026-02-26T09:00:00.000Z');
    const firstDay = formatLocalDate(firstAt);
    const secondDay = formatLocalDate(secondAt);
    const day1 = updateTodayIncomeSnapshot(null, 10, firstAt);
    const day2 = updateTodayIncomeSnapshot(day1, 4, secondAt);

    expect(getTodayIncomeValue(day2, firstDay)).toBe(0);
    expect(getTodayIncomeValue(day2, secondDay)).toBe(4);
    expect(getTodayIncomeDelta(day2, firstDay)).toBe(0);
    expect(getTodayIncomeDelta(day2, secondDay)).toBe(0);
  });

  it('falls back to today income value only when parsed rewards are missing', () => {
    const day = formatLocalDate(new Date('2026-02-25T08:00:00.000Z'));
    const extraConfig = updateTodayIncomeSnapshot(
      updateTodayIncomeSnapshot(null, 8, new Date('2026-02-25T08:00:00.000Z')),
      10.2,
      new Date('2026-02-25T12:00:00.000Z'),
    );

    const fallbackReward = estimateRewardWithTodayIncomeFallback({
      day,
      successCount: 1,
      parsedRewardCount: 0,
      rewardSum: 0,
      extraConfig,
    });
    expect(fallbackReward).toBeCloseTo(10.2, 6);

    const preferParsed = estimateRewardWithTodayIncomeFallback({
      day,
      successCount: 1,
      parsedRewardCount: 1,
      rewardSum: 1.5,
      extraConfig,
    });
    expect(preferParsed).toBe(1.5);
  });

  it('reads today income snapshots from parsed extraConfig objects', () => {
    const day = formatLocalDate(new Date('2026-02-25T08:00:00.000Z'));
    const extraConfig = {
      todayIncomeSnapshot: {
        day,
        baseline: 8,
        latest: 10.2,
        updatedAt: '2026-02-25T12:00:00.000Z',
      },
    };

    expect(getTodayIncomeValue(extraConfig, day)).toBeCloseTo(10.2, 6);
    expect(getTodayIncomeDelta(extraConfig, day)).toBeCloseTo(2.2, 6);
  });

  it('preserves missing extraConfig when income is invalid', () => {
    expect(updateTodayIncomeSnapshot(null, Number.NaN)).toBeNull();
    expect(updateTodayIncomeSnapshot(undefined, -1)).toBeNull();
    expect(updateTodayIncomeSnapshot('', Number.NaN)).toBeNull();
    expect(updateTodayIncomeSnapshot('{"demo":true}', Number.NaN)).toBe('{"demo":true}');
    expect(updateTodayIncomeSnapshot({ demo: true }, Number.NaN)).toBe('{"demo":true}');
  });
});
