import { describe, expect, it } from 'vitest';
import { getAllBrandNames, getBlockedBrandRules, isModelBlockedByBrand } from './brandMatcher.js';

describe('brandMatcher', () => {
  it('exposes newly supported provider and platform brands', () => {
    const brands = getAllBrandNames();

    expect(brands).toContain('OpenRouter');
    expect(brands).toContain('OrcaRouter');
    expect(brands).toContain('Groq');
    expect(brands).toContain('DeepInfra');
    expect(brands).toContain('Fireworks');
    expect(brands).toContain('Together AI');
    expect(brands).toContain('AI21 Labs');
    expect(brands).toContain('百川智能');
    expect(brands).toContain('Amazon Nova');
    expect(brands).toContain('百炼');
    expect(brands).toContain('Arcee');
    expect(brands).toContain('Xiaomi MiMo');
    expect(brands).toContain('LongCat');
  });

  it('deduplicates blocked brands and ignores unknown entries', () => {
    expect(getBlockedBrandRules(['OpenRouter', 'OpenRouter', 'Unknown Brand'])).toEqual(['OpenRouter']);
  });

  it('canonicalizes blocked brand names before filtering', () => {
    expect(getBlockedBrandRules([' openrouter ', 'OPENROUTER', 'together   ai'])).toEqual([
      'OpenRouter',
      'Together AI',
    ]);
  });

  it('uses the shared frontend detection result for global brand blocking', () => {
    const providerRules = getBlockedBrandRules(['OpenRouter', 'Groq', '百炼', 'LongCat']);
    expect(isModelBlockedByBrand('openrouter/openrouter-auto', providerRules)).toBe(true);
    expect(isModelBlockedByBrand('groq/compound-beta', providerRules)).toBe(true);
    expect(isModelBlockedByBrand('dashscope/wanx2.1-t2i-turbo', providerRules)).toBe(true);
    expect(isModelBlockedByBrand('LongCat-Flash-Lite', providerRules)).toBe(true);

    const vendorRules = getBlockedBrandRules(['Anthropic', 'Meta', 'Google', 'OpenAI', 'Arcee', 'Xiaomi MiMo']);
    expect(isModelBlockedByBrand('openrouter/anthropic/claude-3-7-sonnet', vendorRules)).toBe(true);
    expect(isModelBlockedByBrand('deepinfra/meta-llama/llama-3.3-70b-instruct', vendorRules)).toBe(true);
    expect(isModelBlockedByBrand('vertexai/google/gemini-2.5-pro', vendorRules)).toBe(true);
    expect(isModelBlockedByBrand('azureai/gpt-4o', vendorRules)).toBe(true);
    expect(isModelBlockedByBrand('arcee-ai/trinity-mini', vendorRules)).toBe(true);
    expect(isModelBlockedByBrand('xiaomi/mimo-v2-pro', vendorRules)).toBe(true);
  });
});
