import { describe, expect, it } from 'vitest';
import { getBrand } from './BrandIcon.js';

describe('getBrand', () => {
  it('detects simple prefixed model names', () => {
    expect(getBrand('claude-opus-4-6')?.name).toBe('Anthropic');
    expect(getBrand('gpt-4o-mini')?.name).toBe('OpenAI');
  });

  it('detects brand for regex and wrapped model patterns', () => {
    expect(getBrand('re:^claude-(opus|sonnet)-4-5$')?.name).toBe('Anthropic');
    expect(getBrand('[Summer] gpt-5.2-codex')?.name).toBe('OpenAI');
  });

  it('detects brand from namespaced model paths', () => {
    expect(getBrand('openrouter/anthropic/claude-3-7-sonnet')?.name).toBe('Anthropic');
    expect(getBrand('openrouter/google/gemini-2.5-pro')?.name).toBe('Google');
  });

  it('detects issue #38 existing-brand additions', () => {
    expect(getBrand('google/shieldgemma-9b')).toMatchObject({ name: 'Google', icon: expect.any(String) });
    expect(getBrand('PaLM-2')).toMatchObject({ name: 'Google', icon: expect.any(String) });
    expect(getBrand('imagen3-fast')).toMatchObject({ name: 'Google', icon: expect.any(String) });
    expect(getBrand('veo3-pro')).toMatchObject({ name: 'Google', icon: expect.any(String) });
    expect(getBrand('davinci-002')).toMatchObject({ name: 'OpenAI', icon: expect.any(String) });
    expect(getBrand('babbage-002')).toMatchObject({ name: 'OpenAI', icon: expect.any(String) });
    expect(getBrand('codex-mini-2025-05-16')).toMatchObject({ name: 'OpenAI', icon: expect.any(String) });
    expect(getBrand('ds-chat')).toMatchObject({ name: 'DeepSeek', icon: expect.any(String) });
    expect(getBrand('tongyi-deepresearch-30b-a3b')).toMatchObject({ name: '通义千问', icon: expect.any(String) });
    expect(getBrand('microsoft/kosmos-2')).toMatchObject({ name: 'Microsoft', icon: expect.any(String) });
    expect(getBrand('phi4')).toMatchObject({ name: 'Microsoft', icon: expect.any(String) });
    expect(getBrand('stablediffusion3.5-l')).toMatchObject({ name: 'Stability', icon: expect.any(String) });
    expect(getBrand('sd3-medium')).toMatchObject({ name: 'Stability', icon: expect.any(String) });
    expect(getBrand('tencent-hunyuanvideo-hd')).toMatchObject({ name: '腾讯混元', icon: expect.any(String) });
    expect(getBrand('mini2.1')).toMatchObject({ name: 'MiniMax', icon: expect.any(String) });
    expect(getBrand('stepfun-ai/step3')).toMatchObject({ name: '阶跃星辰', icon: expect.any(String) });
  });

  it('detects issue #38 newly added brands with registered icons', () => {
    expect(getBrand('nvidia/vila')).toMatchObject({ name: 'NVIDIA', icon: expect.any(String) });
    expect(getBrand('ibm/granite-3.3-8b-instruct')).toMatchObject({ name: 'IBM', icon: expect.any(String) });
    expect(getBrand('BAAI/bge-m3')).toMatchObject({ name: 'BAAI', icon: expect.any(String) });
    expect(getBrand('bytedance/seed-oss-36b-instruct')).toMatchObject({ name: 'ByteDance', icon: expect.any(String) });
    expect(getBrand('internlm/internlm2_5-7b-chat')).toMatchObject({ name: 'InternLM', icon: expect.any(String) });
    expect(getBrand('mj_turbo')).toMatchObject({ name: 'Midjourney', icon: expect.any(String) });
    expect(getBrand('deepl-zh-en')).toMatchObject({ name: 'DeepL', icon: expect.any(String) });
    expect(getBrand('jina-embeddings-v3')).toMatchObject({ name: 'Jina AI', icon: expect.any(String) });
  });

  it('detects new provider and platform brands with lobe-hub icons', () => {
    expect(getBrand('openrouter/openrouter-auto')).toMatchObject({ name: 'OpenRouter', icon: expect.any(String) });
    expect(getBrand('orcarouter/auto')).toMatchObject({ name: 'OrcaRouter', icon: expect.any(String) });
    expect(getBrand('groq/compound-beta')).toMatchObject({ name: 'Groq', icon: expect.any(String) });
    expect(getBrand('deepinfra/deepinfra-chat')).toMatchObject({ name: 'DeepInfra', icon: expect.any(String) });
    expect(getBrand('fireworks-ai/firefunction-v2')).toMatchObject({ name: 'Fireworks', icon: expect.any(String) });
    expect(getBrand('together/together-chat')).toMatchObject({ name: 'Together AI', icon: expect.any(String) });
    expect(getBrand('replicate/recraft-v3')).toMatchObject({ name: 'Replicate', icon: expect.any(String) });
    expect(getBrand('cerebras/cerebras-chat')).toMatchObject({ name: 'Cerebras', icon: expect.any(String) });
    expect(getBrand('jamba-1.5-mini')).toMatchObject({ name: 'AI21 Labs', icon: expect.any(String) });
    expect(getBrand('baichuan-m1-14b-instruct')).toMatchObject({ name: '百川智能', icon: expect.any(String) });
    expect(getBrand('sensenova/sensenova-v6')).toMatchObject({ name: 'SenseNova', icon: expect.any(String) });
    expect(getBrand('bedrock/us.amazon.nova-pro-v1:0')).toMatchObject({ name: 'Amazon Nova', icon: expect.any(String) });
    expect(getBrand('amazon/nova-premier-v1')).toMatchObject({ name: 'Amazon Nova', icon: expect.any(String) });
    expect(getBrand('dashscope/wanx2.1-t2i-turbo')).toMatchObject({ name: '百炼', icon: expect.any(String) });
  });

  it('recognizes user-reported uncategorized brands when current lobe-hub icons exist', () => {
    expect(getBrand('relace/relace-search')).toMatchObject({ name: 'Relace', icon: expect.any(String) });
    expect(getBrand('xiaomi/mimo-v2-pro')).toMatchObject({ name: 'Xiaomi MiMo', icon: expect.any(String) });
    expect(getBrand('arcee-ai/trinity-mini')).toMatchObject({ name: 'Arcee', icon: expect.any(String) });
    expect(getBrand('aion-labs/aion-2.0')).toMatchObject({ name: 'AionLabs', icon: expect.any(String) });
    expect(getBrand('allenai/olmo-3-32b-think')).toMatchObject({ name: 'AI2', icon: expect.any(String) });
    expect(getBrand('deepcogito/cogito-v2.1-671b')).toMatchObject({ name: 'DeepCogito', icon: expect.any(String) });
    expect(getBrand('essentialai/rnj-1-instruct')).toMatchObject({ name: 'Essential AI', icon: expect.any(String) });
    expect(getBrand('inflection/inflection-3-pi')).toMatchObject({ name: 'Inflection', icon: expect.any(String) });
    expect(getBrand('liquid/lfm-2-24b-a2b')).toMatchObject({ name: 'Liquid AI', icon: expect.any(String) });
    expect(getBrand('LongCat-Flash-Lite')).toMatchObject({ name: 'LongCat', icon: expect.any(String) });
    expect(getBrand('morph/morph-v3-fast')).toMatchObject({ name: 'Morph', icon: expect.any(String) });
    expect(getBrand('nousresearch/hermes-4-70b')).toMatchObject({ name: 'Nous Research', icon: expect.any(String) });
    expect(getBrand('inception/mercury')).toMatchObject({ name: 'Inception', icon: expect.any(String) });
    expect(getBrand('upstage/solar-pro-3')).toMatchObject({ name: 'Upstage', icon: expect.any(String) });
    expect(getBrand('2zai')).toMatchObject({ name: 'Z.ai', icon: expect.any(String) });
  });

  it('prefers intrinsic model vendors over upstream hosting platforms', () => {
    expect(getBrand('openrouter/anthropic/claude-3-7-sonnet')?.name).toBe('Anthropic');
    expect(getBrand('deepinfra/meta-llama/llama-3.3-70b-instruct')?.name).toBe('Meta');
    expect(getBrand('vertexai/google/gemini-2.5-pro')?.name).toBe('Google');
    expect(getBrand('azureai/gpt-4o')?.name).toBe('OpenAI');
  });

  it('returns null for unknown model names', () => {
    expect(getBrand('totally-unknown-model')).toBeNull();
  });

  it('does not misclassify GPTQ llama variants as OpenAI', () => {
    expect(getBrand('TheBloke/Llama-2-7B-GPTQ')?.name).toBe('Meta');
  });
});
