import { describe, expect, it, vi } from 'vitest';

import { listModelsSurface } from './modelsSurface.js';
import {
  buildAccountModelContextLengthScope,
  clearModelContextLengthCache,
  setModelContextLength,
} from '../../services/modelContextLengthCache.js';

describe('listModelsSurface', () => {
  it('returns OpenAI list shape and hides models without a resolvable channel', async () => {
    clearModelContextLengthCache();
    setModelContextLength('routable-model', 128000, buildAccountModelContextLengthScope(11));

    const result = await listModelsSurface({
      downstreamPolicy: { type: 'all' },
      responseFormat: 'openai',
      tokenRouter: {
        getAvailableModels: vi.fn().mockResolvedValue(['routable-model', 'orphan-model']),
        explainSelection: vi.fn(async (modelName: string) => (
          modelName === 'routable-model'
            ? { selectedChannelId: 11, selectedAccountId: 11 }
            : { selectedChannelId: null }
        )),
      },
      refreshModelsAndRebuildRoutes: vi.fn(),
      isModelAllowed: vi.fn().mockResolvedValue(true),
      now: () => new Date('2026-03-19T00:00:00.000Z'),
    });

    expect(result).toEqual({
      object: 'list',
      data: [
        {
          id: 'routable-model',
          object: 'model',
          created: 1773878400,
          owned_by: 'metapi',
          context_length: 128000,
        },
      ],
    });
  });

  it('returns Claude list shape when requested', async () => {
    clearModelContextLengthCache();
    setModelContextLength('claude-opus-4-6', 200000, buildAccountModelContextLengthScope(22));

    const result = await listModelsSurface({
      downstreamPolicy: { type: 'all' },
      responseFormat: 'claude',
      tokenRouter: {
        getAvailableModels: vi.fn().mockResolvedValue(['claude-opus-4-6']),
        explainSelection: vi.fn().mockResolvedValue({ selectedChannelId: 22, selectedAccountId: 22 }),
      },
      refreshModelsAndRebuildRoutes: vi.fn(),
      isModelAllowed: vi.fn().mockResolvedValue(true),
      now: () => new Date('2026-03-19T00:00:00.000Z'),
    });

    expect(result).toEqual({
      data: [
        {
          id: 'claude-opus-4-6',
          type: 'model',
          display_name: 'claude-opus-4-6',
          created_at: '2026-03-19T00:00:00.000Z',
          context_length: 200000,
        },
      ],
      first_id: 'claude-opus-4-6',
      last_id: 'claude-opus-4-6',
      has_more: false,
    });
  });

  it('uses the most conservative context length across eligible routing candidates', async () => {
    clearModelContextLengthCache();
    setModelContextLength('shared-model', 200000, buildAccountModelContextLengthScope(41));
    setModelContextLength('shared-model', 128000, buildAccountModelContextLengthScope(42));

    const result = await listModelsSurface({
      downstreamPolicy: { type: 'all' },
      responseFormat: 'openai',
      tokenRouter: {
        getAvailableModels: vi.fn().mockResolvedValue(['shared-model']),
        explainSelection: vi.fn().mockResolvedValue({
          selectedChannelId: 4101,
          selectedAccountId: 41,
          candidates: [
            { accountId: 41, eligible: true },
            { accountId: 42, eligible: true },
          ],
        }),
      },
      refreshModelsAndRebuildRoutes: vi.fn(),
      isModelAllowed: vi.fn().mockResolvedValue(true),
      now: () => new Date('2026-03-19T00:00:00.000Z'),
    });

    expect(result).toEqual({
      object: 'list',
      data: [
        {
          id: 'shared-model',
          object: 'model',
          created: 1773878400,
          owned_by: 'metapi',
          context_length: 128000,
        },
      ],
    });
  });

  it('applies downstream policy filtering before selection checks and refreshes once when the first read is empty', async () => {
    clearModelContextLengthCache();
    setModelContextLength('allowed-model', 64000, buildAccountModelContextLengthScope(33));

    const getAvailableModels = vi.fn()
      .mockResolvedValueOnce(['blocked-model'])
      .mockResolvedValueOnce(['allowed-model']);
    const refreshModelsAndRebuildRoutes = vi.fn().mockResolvedValue(undefined);
    const isModelAllowed = vi.fn()
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);
    const explainSelection = vi.fn().mockResolvedValue({ selectedChannelId: 33, selectedAccountId: 33 });

    const result = await listModelsSurface({
      downstreamPolicy: { type: 'whitelist' },
      responseFormat: 'openai',
      tokenRouter: {
        getAvailableModels,
        explainSelection,
      },
      refreshModelsAndRebuildRoutes,
      isModelAllowed,
      now: () => new Date('2026-03-19T00:00:00.000Z'),
    });

    expect(refreshModelsAndRebuildRoutes).toHaveBeenCalledTimes(1);
    expect(result).toEqual({
      object: 'list',
      data: [
        {
          id: 'allowed-model',
          object: 'model',
          created: 1773878400,
          owned_by: 'metapi',
          context_length: 64000,
        },
      ],
    });
  });
});
