import { describe, expect, it } from 'vitest';

import { applyOpenAiServiceTierPolicy } from './serviceTierPolicy.js';

describe('applyOpenAiServiceTierPolicy', () => {
  it('normalizes fast to priority, leaves absent tiers alone, and drops unknown or non-string tiers', () => {
    expect(applyOpenAiServiceTierPolicy({
      body: { model: 'gpt-5' },
    })).toMatchObject({
      ok: true,
      body: { model: 'gpt-5' },
      action: 'pass',
    });

    expect(applyOpenAiServiceTierPolicy({
      body: { model: 'gpt-5', service_tier: ' fast ' },
    })).toMatchObject({
      ok: true,
      body: { model: 'gpt-5', service_tier: 'priority' },
      action: 'pass',
    });

    expect(applyOpenAiServiceTierPolicy({
      body: { model: 'gpt-5', service_tier: 'turbo' },
    })).toMatchObject({
      ok: true,
      body: { model: 'gpt-5' },
      action: 'filter',
    });

    expect(applyOpenAiServiceTierPolicy({
      body: { model: 'gpt-5', service_tier: 123 },
    })).toMatchObject({
      ok: true,
      body: { model: 'gpt-5' },
      action: 'filter',
    });
  });

  it('applies pass, filter and block rules by tier, model, platform and account type', () => {
    const rules = [
      {
        action: 'filter',
        tiers: ['flex'],
        platforms: ['sub2api'],
      },
      {
        action: 'block',
        tiers: ['priority'],
        models: ['gpt-5'],
        platforms: ['openai'],
        accountTypes: ['free'],
      },
    ];

    expect(applyOpenAiServiceTierPolicy({
      body: { model: 'gpt-5', service_tier: 'flex' },
      context: { sitePlatform: 'sub2api', requestedModel: 'gpt-5' },
      rules,
    })).toMatchObject({
      ok: true,
      body: { model: 'gpt-5' },
      serviceTier: 'flex',
      action: 'filter',
    });

    const blocked = applyOpenAiServiceTierPolicy({
      body: { model: 'gpt-5', service_tier: 'fast' },
      context: {
        sitePlatform: 'openai',
        requestedModel: 'gpt-5',
        accountType: 'free',
      },
      rules,
    });

    expect(blocked.ok).toBe(false);
    if (!blocked.ok) {
      expect(blocked.statusCode).toBe(400);
      expect(blocked.payload.error.message).toContain('priority');
    }
  });
});
