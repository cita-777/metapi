import { describe, expect, it } from 'vitest';
import {
  resolveAntigravityProviderAction,
  shouldUseAntigravityStreamAction,
} from './antigravityRuntime.js';

describe('shouldUseAntigravityStreamAction', () => {
  it('returns true for Claude-family model names', () => {
    expect(shouldUseAntigravityStreamAction('claude')).toBe(true);
    expect(shouldUseAntigravityStreamAction('claude-2')).toBe(true);
    expect(shouldUseAntigravityStreamAction('claude-instant')).toBe(true);
    expect(shouldUseAntigravityStreamAction('CLAUDE-OPUS-4-1')).toBe(true);
  });

  it('returns false for models outside the Claude-family heuristic', () => {
    expect(shouldUseAntigravityStreamAction('gemini-2.5-pro')).toBe(false);
    expect(shouldUseAntigravityStreamAction('gpt-5')).toBe(false);
  });
});

describe('resolveAntigravityProviderAction', () => {
  it('routes Claude-family non-stream requests through streamGenerateContent', () => {
    expect(resolveAntigravityProviderAction('generateContent', false, 'claude-opus-4-1'))
      .toBe('streamGenerateContent');
  });
});
