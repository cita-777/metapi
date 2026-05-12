import { describe, expect, it, beforeEach } from 'vitest';
import {
  buildAccountModelContextLengthScope,
  buildEndpointModelContextLengthScope,
  setModelContextLength,
  setModelContextLengths,
  getModelContextLength,
  hasModelContextLength,
  clearModelContextLengthCache,
  extractContextLengthsFromPayload,
  getAllModelContextLengths,
} from './modelContextLengthCache.js';

describe('modelContextLengthCache', () => {
  const primaryAccountScope = buildAccountModelContextLengthScope(101);
  const secondaryAccountScope = buildAccountModelContextLengthScope(202);
  const endpointScope = buildEndpointModelContextLengthScope('https://api.example.com/v1');

  beforeEach(() => {
    clearModelContextLengthCache();
  });

  describe('setModelContextLength / getModelContextLength', () => {
    it('stores and retrieves context length for a model', () => {
      setModelContextLength('gpt-4o', 128000, primaryAccountScope);
      expect(getModelContextLength('gpt-4o', primaryAccountScope)).toBe(128000);
    });

    it('returns default 1_000_000 when model is not in cache', () => {
      expect(getModelContextLength('unknown-model', primaryAccountScope)).toBe(1_000_000);
    });

    it('normalizes model name case-insensitively', () => {
      setModelContextLength('GPT-4o', 128000, primaryAccountScope);
      expect(getModelContextLength('gpt-4o', primaryAccountScope)).toBe(128000);
      expect(getModelContextLength('GPT-4O', primaryAccountScope)).toBe(128000);
    });

    it('ignores invalid values', () => {
      setModelContextLength('', 128000, primaryAccountScope);
      expect(hasModelContextLength('', primaryAccountScope)).toBe(false);

      setModelContextLength('model-a', NaN, primaryAccountScope);
      expect(hasModelContextLength('model-a', primaryAccountScope)).toBe(false);

      setModelContextLength('model-b', -100, primaryAccountScope);
      expect(hasModelContextLength('model-b', primaryAccountScope)).toBe(false);

      setModelContextLength('model-c', 0, primaryAccountScope);
      expect(hasModelContextLength('model-c', primaryAccountScope)).toBe(false);
    });

    it('rejects whitespace-only model names after normalization', () => {
      setModelContextLength('   ', 128000, primaryAccountScope);
      expect(hasModelContextLength('   ', primaryAccountScope)).toBe(false);
    });

    it('rounds fractional values', () => {
      setModelContextLength('model', 128000.7, primaryAccountScope);
      expect(getModelContextLength('model', primaryAccountScope)).toBe(128001);
    });

    it('scopes entries per account to avoid cross-account overwrites', () => {
      setModelContextLength('gpt-4o', 128000, primaryAccountScope);
      setModelContextLength('gpt-4o', 200000, secondaryAccountScope);

      expect(getModelContextLength('gpt-4o', primaryAccountScope)).toBe(128000);
      expect(getModelContextLength('gpt-4o', secondaryAccountScope)).toBe(200000);
    });
  });

  describe('setModelContextLengths (bulk)', () => {
    it('stores multiple entries at once', () => {
      const entries = new Map([
        ['model-a', 128000],
        ['model-b', 200000],
        ['model-c', 1_000_000],
      ]);
      setModelContextLengths(entries, primaryAccountScope);

      expect(getModelContextLength('model-a', primaryAccountScope)).toBe(128000);
      expect(getModelContextLength('model-b', primaryAccountScope)).toBe(200000);
      expect(getModelContextLength('model-c', primaryAccountScope)).toBe(1_000_000);
    });

    it('ignores invalid entries in bulk', () => {
      const entries = new Map([
        ['valid-model', 128000],
        ['', 200000],
        ['nan-model', NaN],
        ['   ', 180000],
      ]);
      setModelContextLengths(entries, primaryAccountScope);

      expect(getModelContextLength('valid-model', primaryAccountScope)).toBe(128000);
      expect(hasModelContextLength('', primaryAccountScope)).toBe(false);
      expect(hasModelContextLength('nan-model', primaryAccountScope)).toBe(false);
      expect(hasModelContextLength('   ', primaryAccountScope)).toBe(false);
    });

    it('replaces previous values for the same source scope to clear stale metadata', () => {
      setModelContextLengths(new Map([
        ['model-a', 128000],
        ['model-b', 200000],
      ]), primaryAccountScope);

      setModelContextLengths(new Map([
        ['model-a', 256000],
      ]), primaryAccountScope);

      expect(getModelContextLength('model-a', primaryAccountScope)).toBe(256000);
      expect(getModelContextLength('model-b', primaryAccountScope)).toBe(1_000_000);
    });

    it('can use endpoint scopes when no account scope is available', () => {
      setModelContextLengths(new Map([
        ['model-a', 64000],
      ]), endpointScope);

      expect(getModelContextLength('model-a', endpointScope)).toBe(64000);
    });

    it('canonicalizes semantically equivalent endpoint urls to the same scope', () => {
      const canonicalScope = buildEndpointModelContextLengthScope('https://API.EXAMPLE.com:443/v1/');
      const equivalentScope = buildEndpointModelContextLengthScope(' https://api.example.com/v1 ');

      expect(canonicalScope).toBe(equivalentScope);
    });

    it('keeps distinct endpoint paths in separate scopes', () => {
      const rootScope = buildEndpointModelContextLengthScope('https://api.example.com');
      const versionedScope = buildEndpointModelContextLengthScope('https://api.example.com/v1/');

      expect(rootScope).not.toBe(versionedScope);
    });
  });

  describe('hasModelContextLength', () => {
    it('returns true only for cached models', () => {
      expect(hasModelContextLength('gpt-4o', primaryAccountScope)).toBe(false);
      setModelContextLength('gpt-4o', 128000, primaryAccountScope);
      expect(hasModelContextLength('gpt-4o', primaryAccountScope)).toBe(true);
    });
  });

  describe('clearModelContextLengthCache', () => {
    it('clears all entries', () => {
      setModelContextLength('model-a', 128000, primaryAccountScope);
      setModelContextLength('model-b', 200000, secondaryAccountScope);
      clearModelContextLengthCache();
      expect(hasModelContextLength('model-a', primaryAccountScope)).toBe(false);
      expect(hasModelContextLength('model-b', secondaryAccountScope)).toBe(false);
    });

    it('can clear a single source scope without affecting others', () => {
      setModelContextLength('model-a', 128000, primaryAccountScope);
      setModelContextLength('model-a', 256000, secondaryAccountScope);

      clearModelContextLengthCache(primaryAccountScope);

      expect(hasModelContextLength('model-a', primaryAccountScope)).toBe(false);
      expect(getModelContextLength('model-a', secondaryAccountScope)).toBe(256000);
    });
  });

  describe('extractContextLengthsFromPayload', () => {
    it('extracts context_length from OpenAI-compatible payload', () => {
      const payload = {
        data: [
          { id: 'gpt-4o', context_length: 128000 },
          { id: 'claude-3', context_length: 200000 },
        ],
      };
      const result = extractContextLengthsFromPayload(payload);
      expect(result.size).toBe(2);
      expect(result.get('gpt-4o')).toBe(128000);
      expect(result.get('claude-3')).toBe(200000);
    });

    it('extracts contextLength (camelCase)', () => {
      const payload = {
        data: [
          { id: 'model-a', contextLength: 256000 },
        ],
      };
      const result = extractContextLengthsFromPayload(payload);
      expect(result.get('model-a')).toBe(256000);
    });

    it('extracts max_context_length', () => {
      const payload = {
        data: [
          { id: 'model-b', max_context_length: 512000 },
        ],
      };
      const result = extractContextLengthsFromPayload(payload);
      expect(result.get('model-b')).toBe(512000);
    });

    it('extracts context_window', () => {
      const payload = {
        data: [
          { id: 'model-c', context_window: 1_000_000 },
        ],
      };
      const result = extractContextLengthsFromPayload(payload);
      expect(result.get('model-c')).toBe(1_000_000);
    });

    it('parses string values as numbers', () => {
      const payload = {
        data: [
          { id: 'model-str', context_length: '128000' },
        ],
      };
      const result = extractContextLengthsFromPayload(payload);
      expect(result.get('model-str')).toBe(128000);
    });

    it('returns empty map for payload without data array', () => {
      expect(extractContextLengthsFromPayload(null).size).toBe(0);
      expect(extractContextLengthsFromPayload({}).size).toBe(0);
      expect(extractContextLengthsFromPayload({ data: 'not-array' }).size).toBe(0);
    });

    it('returns empty map when no items have context_length', () => {
      const payload = {
        data: [
          { id: 'model-a' },
          { id: 'model-b' },
        ],
      };
      const result = extractContextLengthsFromPayload(payload);
      expect(result.size).toBe(0);
    });

    it('skips items without id', () => {
      const payload = {
        data: [
          { context_length: 128000 },
          { id: '', context_length: 200000 },
          { id: 'valid', context_length: 300000 },
        ],
      };
      const result = extractContextLengthsFromPayload(payload);
      expect(result.size).toBe(1);
      expect(result.get('valid')).toBe(300000);
    });

    it('skips zero or negative context_length', () => {
      const payload = {
        data: [
          { id: 'zero', context_length: 0 },
          { id: 'negative', context_length: -100 },
        ],
      };
      const result = extractContextLengthsFromPayload(payload);
      expect(result.size).toBe(0);
    });
  });

  describe('getAllModelContextLengths', () => {
    it('returns all cached entries', () => {
      setModelContextLength('a', 100, primaryAccountScope);
      setModelContextLength('b', 200, primaryAccountScope);
      const all = getAllModelContextLengths(primaryAccountScope);
      expect(all.size).toBe(2);
      expect(all.get('a')).toBe(100);
      expect(all.get('b')).toBe(200);
    });
  });
});
