import { describe, expect, it } from 'vitest';

describe('token route contract', () => {
  it('normalizes unknown route modes to pattern', async () => {
    const { normalizeTokenRouteMode } = await import('./tokenRouteContract.js');

    expect(normalizeTokenRouteMode('explicit_group')).toBe('explicit_group');
    expect(normalizeTokenRouteMode('pattern')).toBe('pattern');
    expect(normalizeTokenRouteMode('anything-else')).toBe('pattern');
    expect(normalizeTokenRouteMode(null)).toBe('pattern');
    expect(normalizeTokenRouteMode(undefined)).toBe('pattern');
  });
});
