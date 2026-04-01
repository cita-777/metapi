function normalizeUrlCandidate(url) {
  return typeof url === 'string' ? url.trim() : '';
}

function parseUrlCandidate(url) {
  const normalized = normalizeUrlCandidate(url);
  if (!normalized) return null;

  const candidates = normalized.includes('://')
    ? [normalized]
    : [`https://${normalized}`];

  for (const candidate of candidates) {
    try {
      return new URL(candidate);
    } catch {}
  }
  return null;
}

function normalizePathname(pathname) {
  let normalized = typeof pathname === 'string' ? pathname.trim() : '';
  if (!normalized.startsWith('/')) normalized = `/${normalized}`;
  while (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return normalized;
}

function matchesHostAndPaths(url, hostname, paths) {
  const parsed = parseUrlCandidate(url);
  if (!parsed) return false;
  return parsed.hostname === hostname && paths.includes(normalizePathname(parsed.pathname));
}

const CODINGPLAN_RECOMMENDED_MODELS = Object.freeze([
  'qwen3-coder-plus',
  'qwen3-coder-next',
  'qwen3.5-plus',
  'glm-5',
]);

const ZHIPU_CODING_PLAN_RECOMMENDED_MODELS = Object.freeze([
  'glm-4.7',
  'glm-4.6',
  'glm-4.5',
  'glm-4.5-air',
]);

const DEEPSEEK_RECOMMENDED_MODELS = Object.freeze([
  'deepseek-chat',
  'deepseek-reasoner',
]);

const MOONSHOT_RECOMMENDED_MODELS = Object.freeze([
  'kimi-k2.5',
  'kimi-k2',
  'kimi-k2-thinking',
]);

const MINIMAX_RECOMMENDED_MODELS = Object.freeze([
  'MiniMax-M2.7',
  'MiniMax-M2.5',
  'MiniMax-M2.1',
]);

const MODELSCOPE_RECOMMENDED_MODELS = Object.freeze([
  'Qwen/Qwen3-32B',
  'Qwen/Qwen2.5-Coder-32B-Instruct',
  'deepseek-ai/DeepSeek-V3.2',
]);

const DOUBAO_CODING_RECOMMENDED_MODELS = Object.freeze([
  'ark-code-latest',
  'doubao-seed-2.0-code',
  'doubao-seed-2.0-pro',
]);

const SITE_INITIALIZATION_PRESETS = Object.freeze([
  Object.freeze({
    id: 'codingplan-openai',
    label: '阿里云 CodingPlan / OpenAI',
    providerLabel: '阿里云 CodingPlan',
    description: '适合阿里云 CodingPlan 的 OpenAI 兼容入口，建议先添加 API Key，再补入推荐模型完成初始化。',
    platform: 'openai',
    defaultUrl: 'https://coding.dashscope.aliyuncs.com/v1',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: CODINGPLAN_RECOMMENDED_MODELS,
    docsUrl: 'https://help.aliyun.com/zh/model-studio/coding-plan-faq',
    matches(url) {
      return matchesHostAndPaths(url, 'coding.dashscope.aliyuncs.com', ['/v1']);
    },
  }),
  Object.freeze({
    id: 'codingplan-claude',
    label: '阿里云 CodingPlan / Claude',
    providerLabel: '阿里云 CodingPlan',
    description: '适合阿里云 CodingPlan 的 Claude 兼容入口，建议先添加 API Key，再补入推荐模型完成初始化。',
    platform: 'claude',
    defaultUrl: 'https://coding.dashscope.aliyuncs.com/apps/anthropic',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: CODINGPLAN_RECOMMENDED_MODELS,
    docsUrl: 'https://help.aliyun.com/zh/model-studio/coding-plan-faq',
    matches(url) {
      return matchesHostAndPaths(url, 'coding.dashscope.aliyuncs.com', ['/apps/anthropic']);
    },
  }),
  Object.freeze({
    id: 'zhipu-coding-plan-openai',
    label: '智谱 Coding Plan / OpenAI',
    providerLabel: '智谱 Coding Plan',
    description: '适合智谱 Coding Plan 的 OpenAI 兼容入口，建议先添加 API Key，再补入常用 GLM 编程模型。',
    platform: 'openai',
    defaultUrl: 'https://open.bigmodel.cn/api/coding/paas/v4',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: ZHIPU_CODING_PLAN_RECOMMENDED_MODELS,
    docsUrl: 'https://docs.bigmodel.cn/cn/coding-plan/faq',
    matches(url) {
      return matchesHostAndPaths(url, 'open.bigmodel.cn', ['/api/coding/paas/v4']);
    },
  }),
  Object.freeze({
    id: 'zhipu-coding-plan-claude',
    label: '智谱 Coding Plan / Claude',
    providerLabel: '智谱 Coding Plan',
    description: '适合智谱 Coding Plan 的 Claude 兼容入口。由于该地址也可作为通用兼容入口，这里默认只提供手动预设，不按 URL 强制自动识别。',
    platform: 'claude',
    defaultUrl: 'https://open.bigmodel.cn/api/anthropic',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: ZHIPU_CODING_PLAN_RECOMMENDED_MODELS,
    docsUrl: 'https://docs.bigmodel.cn/cn/coding-plan/faq',
    matches() {
      return false;
    },
  }),
  Object.freeze({
    id: 'deepseek-openai',
    label: 'DeepSeek / OpenAI',
    providerLabel: 'DeepSeek',
    description: '适合 DeepSeek 官方 OpenAI 兼容入口，建议直接添加 API Key，并优先补入官方常用编程模型。',
    platform: 'openai',
    defaultUrl: 'https://api.deepseek.com/v1',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: DEEPSEEK_RECOMMENDED_MODELS,
    docsUrl: 'https://api-docs.deepseek.com/',
    matches(url) {
      return matchesHostAndPaths(url, 'api.deepseek.com', ['/', '/v1']);
    },
  }),
  Object.freeze({
    id: 'deepseek-claude',
    label: 'DeepSeek / Claude',
    providerLabel: 'DeepSeek',
    description: '适合 DeepSeek 官方 Anthropic 兼容入口，便于 Claude Code 一类工具直接接入。',
    platform: 'claude',
    defaultUrl: 'https://api.deepseek.com/anthropic',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: DEEPSEEK_RECOMMENDED_MODELS,
    docsUrl: 'https://api-docs.deepseek.com/guides/anthropic_api',
    matches(url) {
      return matchesHostAndPaths(url, 'api.deepseek.com', ['/anthropic']);
    },
  }),
  Object.freeze({
    id: 'moonshot-openai',
    label: 'Moonshot(Kimi) / OpenAI',
    providerLabel: 'Moonshot / Kimi',
    description: '适合 Moonshot 官方 OpenAI 兼容入口，推荐优先使用 Kimi 系列编程与 Agent 模型。',
    platform: 'openai',
    defaultUrl: 'https://api.moonshot.cn/v1',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: MOONSHOT_RECOMMENDED_MODELS,
    docsUrl: 'https://platform.moonshot.cn/',
    matches(url) {
      return matchesHostAndPaths(url, 'api.moonshot.cn', ['/', '/v1']);
    },
  }),
  Object.freeze({
    id: 'moonshot-claude',
    label: 'Moonshot(Kimi) / Claude',
    providerLabel: 'Moonshot / Kimi',
    description: '适合 Moonshot 官方 Anthropic 兼容入口，便于 Claude Code 与同类工具接入 Kimi。',
    platform: 'claude',
    defaultUrl: 'https://api.moonshot.cn/anthropic',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: MOONSHOT_RECOMMENDED_MODELS,
    docsUrl: 'https://platform.moonshot.cn/blog/posts/kimi-k2-0905',
    matches(url) {
      return matchesHostAndPaths(url, 'api.moonshot.cn', ['/anthropic']);
    },
  }),
  Object.freeze({
    id: 'minimax-openai',
    label: 'MiniMax / OpenAI',
    providerLabel: 'MiniMax',
    description: '适合 MiniMax 官方 OpenAI 兼容入口，建议直接添加 API Key 后补入常用 M2 编程模型。',
    platform: 'openai',
    defaultUrl: 'https://api.minimaxi.com/v1',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: MINIMAX_RECOMMENDED_MODELS,
    docsUrl: 'https://platform.minimaxi.com/docs/api-reference/api-overview',
    matches(url) {
      return matchesHostAndPaths(url, 'api.minimaxi.com', ['/', '/v1']);
    },
  }),
  Object.freeze({
    id: 'minimax-claude',
    label: 'MiniMax / Claude',
    providerLabel: 'MiniMax',
    description: '适合 MiniMax 官方 Anthropic 兼容入口，适配 Claude Code 等编程工具场景。',
    platform: 'claude',
    defaultUrl: 'https://api.minimaxi.com/anthropic',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: MINIMAX_RECOMMENDED_MODELS,
    docsUrl: 'https://platform.minimaxi.com/docs/api-reference/text-anthropic-api',
    matches(url) {
      return matchesHostAndPaths(url, 'api.minimaxi.com', ['/anthropic']);
    },
  }),
  Object.freeze({
    id: 'modelscope-openai',
    label: 'ModelScope / OpenAI',
    providerLabel: 'ModelScope',
    description: '适合 ModelScope API-Inference 的 OpenAI 兼容入口，适合直接接入常用开源编程模型。',
    platform: 'openai',
    defaultUrl: 'https://api-inference.modelscope.cn/v1',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: MODELSCOPE_RECOMMENDED_MODELS,
    docsUrl: 'https://www.modelscope.cn/docs/model-service/API-Inference/intro',
    matches(url) {
      return matchesHostAndPaths(url, 'api-inference.modelscope.cn', ['/v1']);
    },
  }),
  Object.freeze({
    id: 'modelscope-claude',
    label: 'ModelScope / Claude',
    providerLabel: 'ModelScope',
    description: '适合 ModelScope API-Inference 的 Claude 兼容入口，便于接入 Claude Code 一类工具。',
    platform: 'claude',
    defaultUrl: 'https://api-inference.modelscope.cn',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: MODELSCOPE_RECOMMENDED_MODELS,
    docsUrl: 'https://www.modelscope.cn/docs/model-service/API-Inference/intro',
    matches(url) {
      return matchesHostAndPaths(url, 'api-inference.modelscope.cn', ['/']);
    },
  }),
  Object.freeze({
    id: 'doubao-coding-openai',
    label: '豆包 Coding Plan / OpenAI',
    providerLabel: '豆包 Coding Plan',
    description: '适合火山方舟 Coding Plan 的 OpenAI 兼容入口，推荐优先使用 ark-code 与豆包编程模型。',
    platform: 'openai',
    defaultUrl: 'https://ark.cn-beijing.volces.com/api/coding/v3',
    initialSegment: 'apikey',
    recommendedSkipModelFetch: true,
    recommendedModels: DOUBAO_CODING_RECOMMENDED_MODELS,
    docsUrl: 'https://www.volcengine.com/docs/82379/2205646?lang=zh',
    matches(url) {
      return matchesHostAndPaths(url, 'ark.cn-beijing.volces.com', ['/api/coding/v3']);
    },
  }),
]);

function clonePreset(preset) {
  if (!preset) return null;
  return {
    ...preset,
    recommendedModels: [...preset.recommendedModels],
  };
}

export function listSiteInitializationPresets() {
  return SITE_INITIALIZATION_PRESETS.map((preset) => clonePreset(preset));
}

export function getSiteInitializationPreset(id) {
  const normalizedId = typeof id === 'string' ? id.trim() : '';
  if (!normalizedId) return null;
  return clonePreset(SITE_INITIALIZATION_PRESETS.find((preset) => preset.id === normalizedId) || null);
}

export function detectSiteInitializationPreset(url, platform) {
  const normalizedPlatform = typeof platform === 'string' ? platform.trim().toLowerCase() : '';
  for (const preset of SITE_INITIALIZATION_PRESETS) {
    if (normalizedPlatform && preset.platform !== normalizedPlatform) continue;
    if (preset.matches(url)) return clonePreset(preset);
  }
  return null;
}
