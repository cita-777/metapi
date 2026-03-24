import { describe, expect, it } from 'vitest';

import {
  detectPlatformByUrlHint,
  normalizePlatformAlias,
} from './platformIdentity.js';

describe('platformIdentity', () => {
  it('normalizes shared platform aliases', () => {
    expect(normalizePlatformAlias('chatgpt-codex')).toBe('codex');
    expect(normalizePlatformAlias('anti-gravity')).toBe('antigravity');
    expect(normalizePlatformAlias('one api')).toBe('one-api');
    expect(normalizePlatformAlias('')).toBe('');
  });

  it('detects platform by well-known url hints', () => {
    expect(detectPlatformByUrlHint('https://api.openai.com/v1/models')).toBe('openai');
    expect(detectPlatformByUrlHint('https://chatgpt.com/backend-api/codex')).toBe('codex');
    expect(detectPlatformByUrlHint('https://api.anthropic.com/v1/messages')).toBe('claude');
    expect(detectPlatformByUrlHint('https://generativelanguage.googleapis.com/v1beta')).toBe('gemini');
    expect(detectPlatformByUrlHint('https://cloudcode-pa.googleapis.com')).toBe('gemini-cli');
    expect(detectPlatformByUrlHint('http://127.0.0.1:8317/v1/models')).toBe('cliproxyapi');
    expect(detectPlatformByUrlHint('https://evil.example.com/?next=https://api.openai.com/v1/models')).toBeUndefined();
  });
});
