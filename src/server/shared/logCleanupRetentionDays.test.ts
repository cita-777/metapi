import { describe, expect, it } from 'vitest';

import { normalizeLogCleanupRetentionDays } from './logCleanupRetentionDays.js';

describe('normalizeLogCleanupRetentionDays', () => {
  it('truncates positive numeric values', () => {
    expect(normalizeLogCleanupRetentionDays(14.9)).toBe(14);
  });

  it('falls back to the provided default for invalid values', () => {
    expect(normalizeLogCleanupRetentionDays('oops', 7)).toBe(7);
    expect(normalizeLogCleanupRetentionDays(-1, 7)).toBe(7);
  });
});
