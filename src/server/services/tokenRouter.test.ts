import { describe, expect, it } from 'vitest';
import { filterRecentlyFailedCandidates, isChannelRecentlyFailed, matchesModelPattern, parseRegexModelPattern } from './tokenRouter.js';

type Candidate = {
  channel: {
    failCount?: number | null;
    lastFailAt?: string | null;
  };
  id: string;
};

describe('filterRecentlyFailedCandidates', () => {
  it('rejects unsafe nested-quantifier regex route patterns', () => {
    expect(parseRegexModelPattern('re:(?=claude)')).toBeNull();
    expect(matchesModelPattern('claude-sonnet-4-6', 're:(?=claude)')).toBe(false);
  });

  it('uses a short default recent-failure window', () => {
    const nowMs = Date.now();
    expect(isChannelRecentlyFailed({
      failCount: 1,
      lastFailAt: new Date(nowMs - 20 * 1000).toISOString(),
    }, nowMs)).toBe(false);
  });

  it('expands the avoidance window with fibonacci-style backoff', () => {
    const nowMs = Date.now();
    expect(isChannelRecentlyFailed({
      failCount: 4,
      lastFailAt: new Date(nowMs - 40 * 1000).toISOString(),
    }, nowMs)).toBe(true);
    expect(isChannelRecentlyFailed({
      failCount: 4,
      lastFailAt: new Date(nowMs - 50 * 1000).toISOString(),
    }, nowMs)).toBe(false);
  });

  it('prefers healthy channels when at least one healthy channel exists', () => {
    const nowMs = Date.now();
    const candidates: Candidate[] = [
      {
        id: 'failed',
        channel: {
          failCount: 2,
          lastFailAt: new Date(nowMs - 30 * 1000).toISOString(),
        },
      },
      {
        id: 'healthy',
        channel: {
          failCount: 0,
          lastFailAt: null,
        },
      },
    ];

    const result = filterRecentlyFailedCandidates(candidates, nowMs, 600);
    expect(result.map((c) => c.id)).toEqual(['healthy']);
  });

  it('keeps all channels when all channels failed recently', () => {
    const nowMs = Date.now();
    const candidates: Candidate[] = [
      {
        id: 'a',
        channel: {
          failCount: 1,
          lastFailAt: new Date(nowMs - 20 * 1000).toISOString(),
        },
      },
      {
        id: 'b',
        channel: {
          failCount: 3,
          lastFailAt: new Date(nowMs - 40 * 1000).toISOString(),
        },
      },
    ];

    const result = filterRecentlyFailedCandidates(candidates, nowMs, 600);
    expect(result.map((c) => c.id).sort()).toEqual(['a', 'b']);
  });

  it('keeps candidates unchanged when avoidSec is omitted', () => {
    const nowMs = Date.now();
    const candidates: Candidate[] = [
      {
        id: 'recent-failure',
        channel: {
          failCount: 3,
          lastFailAt: new Date(nowMs - 5 * 1000).toISOString(),
        },
      },
      {
        id: 'healthy',
        channel: {
          failCount: 0,
          lastFailAt: null,
        },
      },
    ];

    const result = filterRecentlyFailedCandidates(candidates, nowMs);
    expect(result).toEqual(candidates);
  });

  it('does not penalize stale failures outside the avoidance window', () => {
    const nowMs = Date.now();
    const candidates: Candidate[] = [
      {
        id: 'stale-failure',
        channel: {
          failCount: 5,
          lastFailAt: new Date(nowMs - 20 * 60 * 1000).toISOString(),
        },
      },
      {
        id: 'healthy',
        channel: {
          failCount: 0,
          lastFailAt: null,
        },
      },
    ];

    const result = filterRecentlyFailedCandidates(candidates, nowMs, 600);
    expect(result.map((c) => c.id).sort()).toEqual(['healthy', 'stale-failure']);
  });
});
