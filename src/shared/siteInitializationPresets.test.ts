import { describe, expect, it } from 'vitest';

import {
  detectSiteInitializationPreset,
  getSiteInitializationPreset,
  listSiteInitializationPresets,
} from './siteInitializationPresets.js';

describe('siteInitializationPresets', () => {
  it('exposes CodingPlan presets with recommended API-key-first initialization', () => {
    const presetIds = listSiteInitializationPresets().map((preset) => preset.id);
    expect(presetIds).toEqual(expect.arrayContaining([
      'codingplan-openai',
      'codingplan-claude',
      'zhipu-coding-plan-openai',
      'zhipu-coding-plan-claude',
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
});
