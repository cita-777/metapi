import { describe, expect, it } from 'vitest';

import {
  detectSiteInitializationPreset,
  getSiteInitializationPreset,
  listSiteInitializationPresets,
} from './siteInitializationPresets.js';

describe('siteInitializationPresets', () => {
  it('exposes vendor presets with recommended API-key-first initialization', () => {
    const presetIds = listSiteInitializationPresets().map((preset) => preset.id);
    expect(presetIds).toEqual(expect.arrayContaining([
      'codingplan-openai',
      'codingplan-claude',
      'zhipu-coding-plan-openai',
      'zhipu-coding-plan-claude',
      'deepseek-openai',
      'deepseek-claude',
      'moonshot-openai',
      'moonshot-claude',
      'minimax-openai',
      'minimax-claude',
      'modelscope-openai',
      'modelscope-claude',
      'doubao-coding-openai',
    ]));

    const openaiPreset = getSiteInitializationPreset('codingplan-openai');
    expect(openaiPreset).toMatchObject({
      id: 'codingplan-openai',
      platform: 'openai',
      defaultUrl: 'https://coding.dashscope.aliyuncs.com/v1',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(openaiPreset?.recommendedModels).toEqual(expect.arrayContaining(['qwen3-coder-plus', 'qwen3.5-plus']));

    const claudePreset = getSiteInitializationPreset('codingplan-claude');
    expect(claudePreset).toMatchObject({
      id: 'codingplan-claude',
      platform: 'claude',
      defaultUrl: 'https://coding.dashscope.aliyuncs.com/apps/anthropic',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(claudePreset?.recommendedModels).toEqual(expect.arrayContaining(['qwen3-coder-next', 'glm-5']));

    const zhipuOpenAiPreset = getSiteInitializationPreset('zhipu-coding-plan-openai');
    expect(zhipuOpenAiPreset).toMatchObject({
      id: 'zhipu-coding-plan-openai',
      platform: 'openai',
      defaultUrl: 'https://open.bigmodel.cn/api/coding/paas/v4',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(zhipuOpenAiPreset?.recommendedModels).toEqual(['glm-4.7', 'glm-4.6', 'glm-4.5', 'glm-4.5-air']);

    const zhipuClaudePreset = getSiteInitializationPreset('zhipu-coding-plan-claude');
    expect(zhipuClaudePreset).toMatchObject({
      id: 'zhipu-coding-plan-claude',
      platform: 'claude',
      defaultUrl: 'https://open.bigmodel.cn/api/anthropic',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(zhipuClaudePreset?.recommendedModels).toEqual(['glm-4.7', 'glm-4.6', 'glm-4.5', 'glm-4.5-air']);

    const deepseekPreset = getSiteInitializationPreset('deepseek-openai');
    expect(deepseekPreset).toMatchObject({
      id: 'deepseek-openai',
      platform: 'openai',
      defaultUrl: 'https://api.deepseek.com/v1',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(deepseekPreset?.recommendedModels).toEqual(['deepseek-chat', 'deepseek-reasoner']);

    const moonshotPreset = getSiteInitializationPreset('moonshot-openai');
    expect(moonshotPreset).toMatchObject({
      id: 'moonshot-openai',
      platform: 'openai',
      defaultUrl: 'https://api.moonshot.cn/v1',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(moonshotPreset?.recommendedModels).toEqual(['kimi-k2.5', 'kimi-k2', 'kimi-k2-thinking']);

    const minimaxPreset = getSiteInitializationPreset('minimax-claude');
    expect(minimaxPreset).toMatchObject({
      id: 'minimax-claude',
      platform: 'claude',
      defaultUrl: 'https://api.minimaxi.com/anthropic',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(minimaxPreset?.recommendedModels).toEqual(['MiniMax-M2.7', 'MiniMax-M2.5', 'MiniMax-M2.1']);

    const modelscopePreset = getSiteInitializationPreset('modelscope-openai');
    expect(modelscopePreset).toMatchObject({
      id: 'modelscope-openai',
      platform: 'openai',
      defaultUrl: 'https://api-inference.modelscope.cn/v1',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(modelscopePreset?.recommendedModels).toEqual([
      'Qwen/Qwen3-32B',
      'Qwen/Qwen2.5-Coder-32B-Instruct',
      'deepseek-ai/DeepSeek-V3.2',
    ]);

    const doubaoPreset = getSiteInitializationPreset('doubao-coding-openai');
    expect(doubaoPreset).toMatchObject({
      id: 'doubao-coding-openai',
      platform: 'openai',
      defaultUrl: 'https://ark.cn-beijing.volces.com/api/coding/v3',
      initialSegment: 'apikey',
      recommendedSkipModelFetch: true,
    });
    expect(doubaoPreset?.recommendedModels).toEqual([
      'ark-code-latest',
      'doubao-seed-2.0-code',
      'doubao-seed-2.0-pro',
    ]);
  });

  it('detects Aliyun CodingPlan endpoints by URL', () => {
    expect(detectSiteInitializationPreset('https://coding.dashscope.aliyuncs.com/v1')).toMatchObject({
      id: 'codingplan-openai',
      platform: 'openai',
    });
    expect(detectSiteInitializationPreset('https://coding.dashscope.aliyuncs.com/apps/anthropic')).toMatchObject({
      id: 'codingplan-claude',
      platform: 'claude',
    });
    expect(detectSiteInitializationPreset('https://api.openai.com/v1')).toBeNull();
  });

  it('detects Zhipu Coding Plan OpenAI endpoints by URL but keeps Claude-compatible entry manual-only', () => {
    expect(detectSiteInitializationPreset('https://open.bigmodel.cn/api/coding/paas/v4')).toMatchObject({
      id: 'zhipu-coding-plan-openai',
      platform: 'openai',
    });
    expect(detectSiteInitializationPreset('https://open.bigmodel.cn/api/coding/paas/v4/')).toMatchObject({
      id: 'zhipu-coding-plan-openai',
      platform: 'openai',
    });
    expect(detectSiteInitializationPreset('https://open.bigmodel.cn/api/anthropic')).toBeNull();
  });

  it('detects vendor-specific OpenAI and Claude endpoints by URL', () => {
    expect(detectSiteInitializationPreset('https://api.deepseek.com/v1')).toMatchObject({
      id: 'deepseek-openai',
      platform: 'openai',
    });
    expect(detectSiteInitializationPreset('https://api.deepseek.com/anthropic')).toMatchObject({
      id: 'deepseek-claude',
      platform: 'claude',
    });

    expect(detectSiteInitializationPreset('https://api.moonshot.cn/v1/')).toMatchObject({
      id: 'moonshot-openai',
      platform: 'openai',
    });
    expect(detectSiteInitializationPreset('https://api.moonshot.cn/anthropic')).toMatchObject({
      id: 'moonshot-claude',
      platform: 'claude',
    });

    expect(detectSiteInitializationPreset('https://api.minimaxi.com/v1')).toMatchObject({
      id: 'minimax-openai',
      platform: 'openai',
    });
    expect(detectSiteInitializationPreset('https://api.minimaxi.com/anthropic')).toMatchObject({
      id: 'minimax-claude',
      platform: 'claude',
    });

    expect(detectSiteInitializationPreset('https://api-inference.modelscope.cn/v1')).toMatchObject({
      id: 'modelscope-openai',
      platform: 'openai',
    });
    expect(detectSiteInitializationPreset('https://api-inference.modelscope.cn')).toMatchObject({
      id: 'modelscope-claude',
      platform: 'claude',
    });

    expect(detectSiteInitializationPreset('https://ark.cn-beijing.volces.com/api/coding/v3')).toMatchObject({
      id: 'doubao-coding-openai',
      platform: 'openai',
    });
  });
});
