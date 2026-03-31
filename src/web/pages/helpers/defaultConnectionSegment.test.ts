import { describe, expect, it } from 'vitest';
import { resolveInitialConnectionSegment } from './defaultConnectionSegment.js';

describe('defaultConnectionSegment', () => {
  it('maps management-style platforms to the session segment', () => {
    expect(resolveInitialConnectionSegment('new-api')).toBe('session');
    expect(resolveInitialConnectionSegment('one-api')).toBe('session');
    expect(resolveInitialConnectionSegment('anyrouter')).toBe('session');
    expect(resolveInitialConnectionSegment('veloera')).toBe('session');
    expect(resolveInitialConnectionSegment('one-hub')).toBe('session');
    expect(resolveInitialConnectionSegment('done-hub')).toBe('session');
    expect(resolveInitialConnectionSegment('sub2api')).toBe('session');
    expect(resolveInitialConnectionSegment('codex')).toBe('session');
  });

  it('maps API-key-only platforms to the apikey segment', () => {
    expect(resolveInitialConnectionSegment('openai')).toBe('apikey');
    expect(resolveInitialConnectionSegment('claude')).toBe('apikey');
    expect(resolveInitialConnectionSegment('gemini')).toBe('apikey');
    expect(resolveInitialConnectionSegment('cliproxyapi')).toBe('apikey');
  });

  it('falls back to the apikey segment for unknown platforms', () => {
    expect(resolveInitialConnectionSegment('')).toBe('apikey');
    expect(resolveInitialConnectionSegment('unknown-platform')).toBe('apikey');
  });
});
