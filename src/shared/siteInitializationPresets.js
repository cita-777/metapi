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
      const parsed = parseUrlCandidate(url);
      if (!parsed) return false;
      return parsed.hostname === 'coding.dashscope.aliyuncs.com'
        && normalizePathname(parsed.pathname) === '/v1';
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
      const parsed = parseUrlCandidate(url);
      if (!parsed) return false;
      const pathname = normalizePathname(parsed.pathname);
      return parsed.hostname === 'coding.dashscope.aliyuncs.com'
        && (pathname === '/apps/anthropic' || pathname.startsWith('/apps/anthropic/'));
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
      const parsed = parseUrlCandidate(url);
      if (!parsed) return false;
      return parsed.hostname === 'open.bigmodel.cn'
        && normalizePathname(parsed.pathname) === '/api/coding/paas/v4';
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
