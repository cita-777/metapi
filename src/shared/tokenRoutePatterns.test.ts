import { describe, expect, it } from 'vitest';

describe('token route pattern helpers', () => {
  it('treats bracket-prefixed literal model names as exact patterns', async () => {
    const {
      isExactTokenRouteModelPattern,
      matchesTokenRouteModelPattern,
    } = await import('./tokenRoutePatterns.js');
    expect(isExactTokenRouteModelPattern('[NV]deepseek-v3.1-terminus')).toBe(true);
    expect(matchesTokenRouteModelPattern('[NV]deepseek-v3.1-terminus', '[NV]deepseek-v3.1-terminus')).toBe(true);
    expect(matchesTokenRouteModelPattern('Ndeepseek-v3.1-terminus', '[NV]deepseek-v3.1-terminus')).toBe(false);
  });

  it('rejects unsafe nested-quantifier regex patterns', async () => {
    const {
      matchesTokenRouteModelPattern,
      parseTokenRouteRegexPattern,
    } = await import('./tokenRoutePatterns.js');

    expect(parseTokenRouteRegexPattern('re:(?=claude)').regex).toBeNull();
    expect(matchesTokenRouteModelPattern('claude-sonnet-4-6', 're:(?=claude)')).toBe(false);
  });

  it('rejects regex syntax that the lightweight parser does not implement', async () => {
    const {
      matchesTokenRouteModelPattern,
      parseTokenRouteRegexPattern,
    } = await import('./tokenRoutePatterns.js');

    expect(parseTokenRouteRegexPattern('re:^(?:gpt|claude)-5$').regex).toBeNull();
    expect(matchesTokenRouteModelPattern('gpt-5', 're:^(?:gpt|claude)-5$')).toBe(false);
    expect(parseTokenRouteRegexPattern('re:^gpt-\\s+$').regex).toBeNull();
    expect(matchesTokenRouteModelPattern('gpt-   ', 're:^gpt-\\s+$')).toBe(false);
  });

  it('supports exact, glob, and safe regex route matches', async () => {
    const { matchesTokenRouteModelPattern } = await import('./tokenRoutePatterns.js');

    expect(matchesTokenRouteModelPattern('gpt-4o-mini', 'gpt-4o-mini')).toBe(true);
    expect(matchesTokenRouteModelPattern('claude-sonnet-4-6', 'claude-*')).toBe(true);
    expect(matchesTokenRouteModelPattern('claude-sonnet-4-6', 're:^claude-(opus|sonnet)-4-6$')).toBe(true);
    expect(matchesTokenRouteModelPattern('gpt-4o-mini-2025', 're:^gpt-4o-mini-\\d+$')).toBe(true);
  });
});
