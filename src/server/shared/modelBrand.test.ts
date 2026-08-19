import { describe, expect, it } from 'vitest';
import { getBrand, getMatchingBrandNames } from './modelBrand.js';

describe('modelBrand matching helpers', () => {
  it('returns all matched provider and vendor brands while preserving display priority', () => {
    expect(getMatchingBrandNames('openrouter/anthropic/claude-3-7-sonnet')).toEqual(['Anthropic', 'OpenRouter']);
    expect(getMatchingBrandNames('deepinfra/meta-llama/llama-3.3-70b-instruct')).toEqual(['Meta', 'DeepInfra']);
    expect(getMatchingBrandNames('azureai/gpt-4o')).toEqual(['OpenAI', 'Azure AI']);
    expect(getMatchingBrandNames('bedrock/us.amazon.nova-pro-v1:0')).toEqual(['Amazon Nova', 'AWS Bedrock']);

    expect(getBrand('openrouter/anthropic/claude-3-7-sonnet')?.name).toBe('Anthropic');
    expect(getBrand('deepinfra/meta-llama/llama-3.3-70b-instruct')?.name).toBe('Meta');

    expect(getBrand('orcarouter/auto')?.name).toBe('OrcaRouter');
  });
});
