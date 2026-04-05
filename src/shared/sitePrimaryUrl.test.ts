import { describe, expect, it } from 'vitest';

import { analyzePrimarySiteUrl } from './sitePrimaryUrl.js';

describe('sitePrimaryUrl', () => {
  it('returns unchanged for empty, nullish, and invalid inputs', () => {
    expect(analyzePrimarySiteUrl('')).toMatchObject({
      canonicalUrl: '',
      persistedUrl: '',
      action: 'unchanged',
      matchedPath: '',
    });
    expect(analyzePrimarySiteUrl(null as unknown as string)).toMatchObject({
      canonicalUrl: '',
      persistedUrl: '',
      action: 'unchanged',
      matchedPath: '',
    });
    expect(analyzePrimarySiteUrl(undefined as unknown as string)).toMatchObject({
      canonicalUrl: '',
      persistedUrl: '',
      action: 'unchanged',
      matchedPath: '',
    });
    expect(analyzePrimarySiteUrl(' not a valid url/// ')).toMatchObject({
      canonicalUrl: 'not a valid url',
      persistedUrl: 'not a valid url',
      action: 'unchanged',
      matchedPath: '',
    });
  });

  it('returns unchanged for root-only urls', () => {
    expect(analyzePrimarySiteUrl('https://example.com/')).toMatchObject({
      canonicalUrl: 'https://example.com',
      persistedUrl: 'https://example.com',
      action: 'unchanged',
      matchedPath: '/',
    });
  });

  it('auto-strips known non-api request suffixes to the host root', () => {
    expect(analyzePrimarySiteUrl('https://api.openai.com/v1/messages?trace=1#frag')).toMatchObject({
      canonicalUrl: 'https://api.openai.com/v1/messages',
      persistedUrl: 'https://api.openai.com',
      action: 'auto_strip_known_api_suffix',
      matchedPath: '/v1/messages',
    });
  });

  it('preserves api-prefixed paths and marks them as warnings', () => {
    expect(analyzePrimarySiteUrl('api.example.com/api/v1/models')).toMatchObject({
      canonicalUrl: 'https://api.example.com/api/v1/models',
      persistedUrl: 'https://api.example.com/api/v1/models',
      action: 'preserve_api_path',
      matchedPath: '/api/v1/models',
    });
  });

  it('preserves known semantic paths without warnings', () => {
    expect(analyzePrimarySiteUrl('https://chatgpt.com/backend-api/codex/')).toMatchObject({
      canonicalUrl: 'https://chatgpt.com/backend-api/codex',
      persistedUrl: 'https://chatgpt.com/backend-api/codex',
      action: 'preserve_semantic_path',
      matchedPath: '/backend-api/codex',
    });
  });

  it('preserves unknown non-api paths and marks them as warnings', () => {
    expect(analyzePrimarySiteUrl('https://gateway.example.com/custom-base')).toMatchObject({
      canonicalUrl: 'https://gateway.example.com/custom-base',
      persistedUrl: 'https://gateway.example.com/custom-base',
      action: 'preserve_unknown_path',
      matchedPath: '/custom-base',
    });
  });
});
