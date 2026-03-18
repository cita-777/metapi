import { describe, expect, it } from 'vitest';
import { isExactModelPattern } from './utils.js';

describe('isExactModelPattern', () => {
  it('treats bracket-prefixed literal model names as exact patterns', () => {
    expect(isExactModelPattern('[NV]deepseek-v3.1-terminus')).toBe(true);
  });
});
