import { describe, expect, it, vi } from 'vitest';
import {
  getSiteAnnouncementListSelectFields,
  isPostgresToastCorruptionError,
  loadRowsWithPostgresToastFallback,
} from './siteAnnouncementStore.js';

function toastError(message = 'missing chunk number 0 for toast value 396265 in pg_toast_54541') {
  return Object.assign(new Error(message), { code: 'XX001' });
}

describe('siteAnnouncementStore', () => {
  it('keeps raw upstream payload out of the list projection', () => {
    expect(Object.keys(getSiteAnnouncementListSelectFields())).not.toContain('rawPayload');
  });

  it('recognizes only the precise PostgreSQL missing-TOAST-chunk diagnostic', () => {
    expect(isPostgresToastCorruptionError(toastError())).toBe(true);
    expect(isPostgresToastCorruptionError({
      code: 'XX001',
      message: 'index corruption detected',
    })).toBe(false);
    expect(isPostgresToastCorruptionError({
      code: '23505',
      message: 'missing chunk number 0 for toast value 396265 in pg_toast_54541',
    })).toBe(false);
    expect(isPostgresToastCorruptionError({
      message: 'Failed query',
      cause: toastError(),
    })).toBe(true);
  });

  it('skips only rows that continue to raise TOAST corruption after fallback', async () => {
    const logger = { warn: vi.fn() };
    const loadAll = vi.fn().mockRejectedValue(new Error(
      'Failed query: missing chunk number 0 for toast value 396265 in pg_toast_54541',
    ));
    const loadIds = vi.fn().mockResolvedValue([1, 2, 3]);
    const loadOne = vi.fn(async (id: number) => {
      if (id === 2) throw toastError();
      return { id };
    });

    await expect(loadRowsWithPostgresToastFallback(loadAll, loadIds, loadOne, logger)).resolves.toEqual([
      { id: 1 },
      { id: 3 },
    ]);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('TOAST corruption'),
      { announcementIds: [2] },
    );
  });

  it('rethrows non-TOAST errors instead of hiding database failures', async () => {
    const failure = new Error('connection terminated unexpectedly');
    await expect(loadRowsWithPostgresToastFallback(
      vi.fn().mockRejectedValue(failure),
      vi.fn(),
      vi.fn(),
    )).rejects.toBe(failure);

    const rowFailure = new Error('permission denied for relation site_announcements');
    await expect(loadRowsWithPostgresToastFallback(
      vi.fn().mockRejectedValue(toastError()),
      vi.fn().mockResolvedValue([1]),
      vi.fn().mockRejectedValue(rowFailure),
    )).rejects.toBe(rowFailure);
  });
});
