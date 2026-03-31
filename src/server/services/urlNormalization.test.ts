import { describe, expect, it } from 'vitest';

import { stripTrailingSlashes } from './urlNormalization.js';

describe('stripTrailingSlashes', () => {
  it('removes trailing slashes without using regex behavior', () => {
    expect(stripTrailingSlashes('')).toBe('');
    expect(stripTrailingSlashes('https://api.example.com')).toBe('https://api.example.com');
    expect(stripTrailingSlashes('https://api.example.com///')).toBe('https://api.example.com');
    expect(stripTrailingSlashes('/api/v1///')).toBe('/api/v1');
    expect(stripTrailingSlashes('////')).toBe('');
  });
});
