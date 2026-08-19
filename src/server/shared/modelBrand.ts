export interface BrandMatchContext {
  raw: string;
  cleaned: string;
  segments: string[];
  candidates: string[];
}

export interface BrandInfo {
  name: string;
  icon: string;
  color: string;
}

export type BrandMatchMode = 'includes' | 'startsWith' | 'segment' | 'boundary';

type BrandRule = {
  keyword: string;
  mode: BrandMatchMode;
};

type BrandDefinition = BrandInfo & {
  rules: BrandRule[];
};

const BRAND_DEFINITIONS: BrandDefinition[] = [
  {
    name: 'OpenAI',
    icon: 'openai',
    color: 'linear-gradient(135deg, #10a37f, #1a7f5a)',
    rules: [
      { keyword: 'gpt', mode: 'startsWith' },
      { keyword: 'chatgpt', mode: 'startsWith' },
      { keyword: 'dall-e', mode: 'startsWith' },
      { keyword: 'whisper', mode: 'startsWith' },
      { keyword: 'text-embedding', mode: 'startsWith' },
      { keyword: 'text-moderation', mode: 'startsWith' },
      { keyword: 'davinci', mode: 'startsWith' },
      { keyword: 'babbage', mode: 'startsWith' },
      { keyword: 'codex-mini', mode: 'startsWith' },
      { keyword: 'o1', mode: 'startsWith' },
      { keyword: 'o3', mode: 'startsWith' },
      { keyword: 'o4', mode: 'startsWith' },
      { keyword: 'tts', mode: 'startsWith' },
    ],
  },
  {
    name: 'Anthropic',
    icon: 'claude-color',
    color: 'linear-gradient(135deg, #d4a574, #c4956a)',
    rules: [
      { keyword: 'claude', mode: 'includes' },
    ],
  },
  {
    name: 'Google',
    icon: 'gemini-color',
    color: 'linear-gradient(135deg, #4285f4, #34a853)',
    rules: [
      { keyword: 'gemini', mode: 'includes' },
      { keyword: 'gemma', mode: 'includes' },
      { keyword: 'google/', mode: 'includes' },
      { keyword: 'palm', mode: 'includes' },
      { keyword: 'paligemma', mode: 'includes' },
      { keyword: 'shieldgemma', mode: 'includes' },
      { keyword: 'recurrentgemma', mode: 'includes' },
      { keyword: 'deplot', mode: 'includes' },
      { keyword: 'codegemma', mode: 'includes' },
      { keyword: 'imagen', mode: 'includes' },
      { keyword: 'learnlm', mode: 'includes' },
      { keyword: 'aqa', mode: 'includes' },
      { keyword: 'veo', mode: 'startsWith' },
      { keyword: 'google/', mode: 'startsWith' },
    ],
  },
  {
    name: 'DeepSeek',
    icon: 'deepseek-color',
    color: 'linear-gradient(135deg, #4d6bfe, #44a3ec)',
    rules: [
      { keyword: 'deepseek', mode: 'includes' },
      { keyword: 'ds-chat', mode: 'segment' },
    ],
  },
  {
    name: '通义千问',
    icon: 'qwen-color',
    color: 'linear-gradient(135deg, #615cf7, #9b8afb)',
    rules: [
      { keyword: 'qwen', mode: 'includes' },
      { keyword: 'qwq', mode: 'includes' },
      { keyword: 'tongyi', mode: 'includes' },
    ],
  },
  {
    name: '智谱 AI',
    icon: 'zhipu-color',
    color: 'linear-gradient(135deg, #3b6cf5, #6366f1)',
    rules: [
      { keyword: 'glm', mode: 'includes' },
      { keyword: 'chatglm', mode: 'includes' },
      { keyword: 'codegeex', mode: 'includes' },
      { keyword: 'cogview', mode: 'includes' },
      { keyword: 'cogvideo', mode: 'includes' },
    ],
  },
  {
    name: 'Meta',
    icon: 'meta-color',
    color: 'linear-gradient(135deg, #0668E1, #1877f2)',
    rules: [
      { keyword: 'llama', mode: 'includes' },
      { keyword: 'code-llama', mode: 'includes' },
      { keyword: 'codellama', mode: 'includes' },
    ],
  },
  {
    name: 'Mistral',
    icon: 'mistral-color',
    color: 'linear-gradient(135deg, #f7d046, #f2a900)',
    rules: [
      { keyword: 'mistral', mode: 'includes' },
      { keyword: 'mixtral', mode: 'includes' },
      { keyword: 'codestral', mode: 'includes' },
      { keyword: 'pixtral', mode: 'includes' },
      { keyword: 'ministral', mode: 'includes' },
      { keyword: 'voxtral', mode: 'includes' },
      { keyword: 'magistral', mode: 'includes' },
    ],
  },
  {
    name: 'Moonshot',
    icon: 'moonshot',
    color: 'linear-gradient(135deg, #000000, #333333)',
    rules: [
      { keyword: 'moonshot', mode: 'includes' },
      { keyword: 'kimi', mode: 'includes' },
    ],
  },
  {
    name: '零一万物',
    icon: 'yi-color',
    color: 'linear-gradient(135deg, #1d4ed8, #3b82f6)',
    rules: [
      { keyword: 'yi-', mode: 'startsWith' },
      { keyword: 'yi', mode: 'boundary' },
    ],
  },
  {
    name: '文心一言',
    icon: 'wenxin-color',
    color: 'linear-gradient(135deg, #2932e1, #4468f2)',
    rules: [
      { keyword: 'ernie', mode: 'includes' },
      { keyword: 'eb-', mode: 'includes' },
    ],
  },
  {
    name: '讯飞星火',
    icon: 'spark-color',
    color: 'linear-gradient(135deg, #0070f3, #00d4ff)',
    rules: [
      { keyword: 'spark', mode: 'includes' },
      { keyword: 'generalv', mode: 'includes' },
    ],
  },
  {
    name: '腾讯混元',
    icon: 'hunyuan-color',
    color: 'linear-gradient(135deg, #00b7ff, #0052d9)',
    rules: [
      { keyword: 'hunyuan', mode: 'includes' },
      { keyword: 'tencent-hunyuan', mode: 'includes' },
    ],
  },
  {
    name: '豆包',
    icon: 'doubao-color',
    color: 'linear-gradient(135deg, #3b5bdb, #7048e8)',
    rules: [
      { keyword: 'doubao', mode: 'includes' },
    ],
  },
  {
    name: 'MiniMax',
    icon: 'minimax-color',
    color: 'linear-gradient(135deg, #6366f1, #818cf8)',
    rules: [
      { keyword: 'minimax', mode: 'includes' },
      { keyword: 'abab', mode: 'includes' },
      { keyword: 'mini2.1', mode: 'segment' },
    ],
  },
  {
    name: 'Cohere',
    icon: 'cohere-color',
    color: 'linear-gradient(135deg, #39594d, #5ba77f)',
    rules: [
      { keyword: 'command', mode: 'includes' },
      { keyword: 'c4ai-', mode: 'includes' },
      { keyword: 'aya', mode: 'includes' },
      { keyword: 'embed-', mode: 'startsWith' },
    ],
  },
  {
    name: 'Microsoft',
    icon: 'microsoft-color',
    color: 'linear-gradient(135deg, #00bcf2, #0078d4)',
    rules: [
      { keyword: 'microsoft/', mode: 'includes' },
      { keyword: 'phi-', mode: 'includes' },
      { keyword: 'kosmos', mode: 'includes' },
      { keyword: 'phi4', mode: 'segment' },
    ],
  },
  {
    name: 'xAI',
    icon: 'xai',
    color: 'linear-gradient(135deg, #111, #444)',
    rules: [
      { keyword: 'grok', mode: 'includes' },
    ],
  },
  {
    name: '阶跃星辰',
    icon: 'stepfun-color',
    color: 'linear-gradient(135deg, #0066ff, #3399ff)',
    rules: [
      { keyword: 'stepfun', mode: 'includes' },
      { keyword: 'step-', mode: 'startsWith' },
      { keyword: 'step3', mode: 'startsWith' },
    ],
  },
  {
    name: '百川智能',
    icon: 'baichuan-color',
    color: 'linear-gradient(135deg, #0f766e, #14b8a6)',
    rules: [
      { keyword: 'baichuan', mode: 'includes' },
    ],
  },
  {
    name: 'AI21 Labs',
    icon: 'ai21-brand-color',
    color: 'linear-gradient(135deg, #7c3aed, #a855f7)',
    rules: [
      { keyword: 'ai21', mode: 'includes' },
      { keyword: 'jamba', mode: 'startsWith' },
      { keyword: 'jamba', mode: 'includes' },
    ],
  },
  {
    name: 'AI2',
    icon: 'ai2-color',
    color: 'linear-gradient(135deg, #0f766e, #14b8a6)',
    rules: [
      { keyword: 'allenai', mode: 'includes' },
      { keyword: 'olmo', mode: 'includes' },
    ],
  },
  {
    name: 'Amazon Nova',
    icon: 'nova',
    color: 'linear-gradient(135deg, #f59e0b, #f97316)',
    rules: [
      { keyword: 'amazon/nova', mode: 'startsWith' },
      { keyword: 'amazon.nova', mode: 'includes' },
      { keyword: 'us.amazon.nova', mode: 'includes' },
      { keyword: 'nova-', mode: 'startsWith' },
      { keyword: 'nova-lite', mode: 'startsWith' },
      { keyword: 'nova-pro', mode: 'startsWith' },
      { keyword: 'nova-micro', mode: 'startsWith' },
      { keyword: 'nova-canvas', mode: 'startsWith' },
      { keyword: 'nova-reel', mode: 'startsWith' },
    ],
  },
  {
    name: 'Stability',
    icon: 'stability-color',
    color: 'linear-gradient(135deg, #8b5cf6, #a855f7)',
    rules: [
      { keyword: 'flux', mode: 'includes' },
      { keyword: 'stablediffusion', mode: 'includes' },
      { keyword: 'stable-diffusion', mode: 'includes' },
      { keyword: 'sdxl', mode: 'includes' },
      { keyword: 'sd3', mode: 'startsWith' },
    ],
  },
  {
    name: 'NVIDIA',
    icon: 'nvidia-color',
    color: 'linear-gradient(135deg, #76b900, #4a8c0b)',
    rules: [
      { keyword: 'nvidia/', mode: 'includes' },
      { keyword: 'nvclip', mode: 'includes' },
      { keyword: 'nemotron', mode: 'includes' },
      { keyword: 'nemoretriever', mode: 'includes' },
      { keyword: 'neva', mode: 'includes' },
      { keyword: 'riva-translate', mode: 'includes' },
      { keyword: 'cosmos', mode: 'includes' },
      { keyword: 'nv-', mode: 'startsWith' },
    ],
  },
  {
    name: 'IBM',
    icon: 'ibm',
    color: 'linear-gradient(135deg, #0f62fe, #4589ff)',
    rules: [
      { keyword: 'ibm/', mode: 'includes' },
      { keyword: 'granite', mode: 'includes' },
    ],
  },
  {
    name: 'BAAI',
    icon: 'baai',
    color: 'linear-gradient(135deg, #111827, #374151)',
    rules: [
      { keyword: 'baai/', mode: 'includes' },
      { keyword: 'bge-', mode: 'includes' },
    ],
  },
  {
    name: 'ByteDance',
    icon: 'bytedance-color',
    color: 'linear-gradient(135deg, #325ab4, #0f66ff)',
    rules: [
      { keyword: 'bytedance', mode: 'includes' },
      { keyword: 'seed-oss', mode: 'includes' },
      { keyword: 'kolors', mode: 'includes' },
      { keyword: 'kwai', mode: 'includes' },
      { keyword: 'kwaipilot', mode: 'includes' },
      { keyword: 'wan-', mode: 'startsWith' },
      { keyword: 'kat-', mode: 'startsWith' },
    ],
  },
  {
    name: 'InternLM',
    icon: 'internlm-color',
    color: 'linear-gradient(135deg, #1b3882, #4063c5)',
    rules: [
      { keyword: 'internlm', mode: 'includes' },
    ],
  },
  {
    name: 'Midjourney',
    icon: 'midjourney',
    color: 'linear-gradient(135deg, #4c6ef5, #748ffc)',
    rules: [
      { keyword: 'midjourney', mode: 'includes' },
      { keyword: 'mj_', mode: 'startsWith' },
    ],
  },
  {
    name: 'DeepL',
    icon: 'deepl-color',
    color: 'linear-gradient(135deg, #0f2b46, #21476f)',
    rules: [
      { keyword: 'deepl-', mode: 'startsWith' },
      { keyword: 'deepl/', mode: 'includes' },
    ],
  },
  {
    name: 'Jina AI',
    icon: 'jina',
    color: 'linear-gradient(135deg, #111827, #4b5563)',
    rules: [
      { keyword: 'jina', mode: 'includes' },
    ],
  },
  {
    name: 'Relace',
    icon: 'relace',
    color: 'linear-gradient(135deg, #7c3aed, #6366f1)',
    rules: [
      { keyword: 'relace', mode: 'includes' },
    ],
  },
  {
    name: 'Arcee',
    icon: 'arcee-color',
    color: 'linear-gradient(135deg, #2563eb, #60a5fa)',
    rules: [
      { keyword: 'arcee-ai', mode: 'includes' },
      { keyword: 'arcee', mode: 'includes' },
    ],
  },
  {
    name: 'AionLabs',
    icon: 'aionlabs-color',
    color: 'linear-gradient(135deg, #0f766e, #14b8a6)',
    rules: [
      { keyword: 'aion-labs', mode: 'includes' },
      { keyword: 'aionlabs', mode: 'includes' },
    ],
  },
  {
    name: 'DeepCogito',
    icon: 'deepcogito-color',
    color: 'linear-gradient(135deg, #2563eb, #7c3aed)',
    rules: [
      { keyword: 'deepcogito', mode: 'includes' },
    ],
  },
  {
    name: 'Essential AI',
    icon: 'essentialai-color',
    color: 'linear-gradient(135deg, #0f172a, #334155)',
    rules: [
      { keyword: 'essentialai', mode: 'includes' },
    ],
  },
  {
    name: 'Inception',
    icon: 'inception',
    color: 'linear-gradient(135deg, #7c3aed, #ec4899)',
    rules: [
      { keyword: 'inception', mode: 'includes' },
    ],
  },
  {
    name: 'Inflection',
    icon: 'inflection',
    color: 'linear-gradient(135deg, #1d4ed8, #2563eb)',
    rules: [
      { keyword: 'inflection', mode: 'includes' },
    ],
  },
  {
    name: 'Liquid AI',
    icon: 'liquid',
    color: 'linear-gradient(135deg, #0f172a, #475569)',
    rules: [
      { keyword: 'liquid', mode: 'includes' },
      { keyword: 'lfm-', mode: 'startsWith' },
    ],
  },
  {
    name: 'LongCat',
    icon: 'longcat-color',
    color: 'linear-gradient(135deg, #f97316, #fb7185)',
    rules: [
      { keyword: 'longcat', mode: 'includes' },
    ],
  },
  {
    name: 'Morph',
    icon: 'morph-color',
    color: 'linear-gradient(135deg, #4f46e5, #8b5cf6)',
    rules: [
      { keyword: 'morph/', mode: 'includes' },
      { keyword: 'morph-', mode: 'startsWith' },
    ],
  },
  {
    name: 'Nous Research',
    icon: 'nousresearch',
    color: 'linear-gradient(135deg, #111827, #4b5563)',
    rules: [
      { keyword: 'nousresearch', mode: 'includes' },
    ],
  },
  {
    name: 'Upstage',
    icon: 'upstage-color',
    color: 'linear-gradient(135deg, #2563eb, #14b8a6)',
    rules: [
      { keyword: 'upstage', mode: 'includes' },
    ],
  },
  {
    name: 'Xiaomi MiMo',
    icon: 'xiaomimimo',
    color: 'linear-gradient(135deg, #f97316, #fb923c)',
    rules: [
      { keyword: 'xiaomi/mimo', mode: 'includes' },
      { keyword: 'xiaomimimo', mode: 'includes' },
      { keyword: 'mimo-v', mode: 'startsWith' },
    ],
  },
  {
    name: 'Z.ai',
    icon: 'zai',
    color: 'linear-gradient(135deg, #0f172a, #2563eb)',
    rules: [
      { keyword: '2zai', mode: 'startsWith' },
      { keyword: 'z-ai', mode: 'startsWith' },
    ],
  },
  {
    name: 'SenseNova',
    icon: 'sensenova-brand-color',
    color: 'linear-gradient(135deg, #f59e0b, #f97316)',
    rules: [
      { keyword: 'sensenova', mode: 'includes' },
    ],
  },
  {
    name: 'Perplexity',
    icon: 'perplexity-color',
    color: 'linear-gradient(135deg, #0f766e, #14b8a6)',
    rules: [
      { keyword: 'perplexity', mode: 'includes' },
      { keyword: 'pplx-', mode: 'startsWith' },
    ],
  },
  {
    name: 'OpenRouter',
    icon: 'openrouter',
    color: 'linear-gradient(135deg, #7c3aed, #2563eb)',
    rules: [
      { keyword: 'openrouter', mode: 'includes' },
      { keyword: 'openrouter-', mode: 'startsWith' },
    ],
  },
  {
    name: 'OrcaRouter',
    icon: 'orcarouter',
    color: 'linear-gradient(135deg, #0ea5e9, #2563eb)',
    rules: [
      { keyword: 'orcarouter', mode: 'includes' },
      { keyword: 'orcarouter/', mode: 'startsWith' },
    ],
  },
  {
    name: 'Groq',
    icon: 'groq',
    color: 'linear-gradient(135deg, #111827, #374151)',
    rules: [
      { keyword: 'groq', mode: 'includes' },
    ],
  },
  {
    name: 'Fireworks',
    icon: 'fireworks-color',
    color: 'linear-gradient(135deg, #fb7185, #f97316)',
    rules: [
      { keyword: 'fireworks-ai', mode: 'includes' },
      { keyword: 'fireworks', mode: 'includes' },
    ],
  },
  {
    name: 'DeepInfra',
    icon: 'deepinfra-color',
    color: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
    rules: [
      { keyword: 'deepinfra', mode: 'includes' },
    ],
  },
  {
    name: 'Together AI',
    icon: 'together-brand-color',
    color: 'linear-gradient(135deg, #7c3aed, #ec4899)',
    rules: [
      { keyword: 'together.ai', mode: 'includes' },
      { keyword: 'together', mode: 'includes' },
    ],
  },
  {
    name: 'Replicate',
    icon: 'replicate-brand',
    color: 'linear-gradient(135deg, #111827, #6366f1)',
    rules: [
      { keyword: 'replicate', mode: 'includes' },
    ],
  },
  {
    name: 'SambaNova',
    icon: 'sambanova-color',
    color: 'linear-gradient(135deg, #2563eb, #06b6d4)',
    rules: [
      { keyword: 'sambanova', mode: 'includes' },
    ],
  },
  {
    name: 'Cerebras',
    icon: 'cerebras-brand-color',
    color: 'linear-gradient(135deg, #0f766e, #65a30d)',
    rules: [
      { keyword: 'cerebras', mode: 'includes' },
    ],
  },
  {
    name: 'Ollama',
    icon: 'ollama',
    color: 'linear-gradient(135deg, #1f2937, #4b5563)',
    rules: [
      { keyword: 'ollama', mode: 'includes' },
    ],
  },
  {
    name: 'ModelScope',
    icon: 'modelscope-color',
    color: 'linear-gradient(135deg, #2563eb, #60a5fa)',
    rules: [
      { keyword: 'modelscope', mode: 'includes' },
    ],
  },
  {
    name: 'SiliconCloud',
    icon: 'siliconcloud-color',
    color: 'linear-gradient(135deg, #0ea5e9, #22d3ee)',
    rules: [
      { keyword: 'siliconcloud', mode: 'includes' },
      { keyword: 'siliconflow', mode: 'includes' },
    ],
  },
  {
    name: 'Azure AI',
    icon: 'azureai-color',
    color: 'linear-gradient(135deg, #0284c7, #2563eb)',
    rules: [
      { keyword: 'azureai', mode: 'includes' },
      { keyword: 'azure-openai', mode: 'includes' },
      { keyword: 'azure/openai', mode: 'includes' },
    ],
  },
  {
    name: 'AWS Bedrock',
    icon: 'bedrock-color',
    color: 'linear-gradient(135deg, #f59e0b, #f97316)',
    rules: [
      { keyword: 'bedrock', mode: 'includes' },
    ],
  },
  {
    name: 'Vertex AI',
    icon: 'vertexai-color',
    color: 'linear-gradient(135deg, #2563eb, #6366f1)',
    rules: [
      { keyword: 'vertexai', mode: 'includes' },
    ],
  },
  {
    name: 'Google Cloud',
    icon: 'googlecloud-brand-color',
    color: 'linear-gradient(135deg, #4285f4, #34a853)',
    rules: [
      { keyword: 'googlecloud', mode: 'includes' },
      { keyword: 'google-cloud', mode: 'includes' },
    ],
  },
  {
    name: '百度智能云',
    icon: 'baiducloud-color',
    color: 'linear-gradient(135deg, #2563eb, #38bdf8)',
    rules: [
      { keyword: 'baiducloud', mode: 'includes' },
      { keyword: 'qianfan', mode: 'includes' },
    ],
  },
  {
    name: '百炼',
    icon: 'bailian-color',
    color: 'linear-gradient(135deg, #7c3aed, #2563eb)',
    rules: [
      { keyword: 'bailian', mode: 'includes' },
      { keyword: 'dashscope', mode: 'includes' },
    ],
  },
  {
    name: '阿里云',
    icon: 'alibabacloud-color',
    color: 'linear-gradient(135deg, #f97316, #fb923c)',
    rules: [
      { keyword: 'alibabacloud', mode: 'includes' },
    ],
  },
  {
    name: '火山引擎',
    icon: 'volcengine-color',
    color: 'linear-gradient(135deg, #325ab4, #0f66ff)',
    rules: [
      { keyword: 'volcengine', mode: 'includes' },
    ],
  },
  {
    name: '七牛云',
    icon: 'qiniu-color',
    color: 'linear-gradient(135deg, #06b6d4, #0891b2)',
    rules: [
      { keyword: 'qiniu', mode: 'includes' },
    ],
  },
];

function normalizeInput(value: string): string {
  return String(value || '').trim().toLowerCase();
}

export function stripCommonWrappers(value: string): string {
  return value
    .replace(/^(?:\[[^\]]+\]|【[^】]+】)\s*/g, '')
    .replace(/^re:\s*/g, '')
    .replace(/^\^+/, '')
    .replace(/\$+$/, '')
    .trim();
}

export function collectBrandCandidates(modelName: string): string[] {
  const queue: string[] = [];
  const seen = new Set<string>();
  const push = (value: string) => {
    const normalized = normalizeInput(value);
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    queue.push(normalized);
  };

  push(modelName);

  for (let index = 0; index < queue.length; index += 1) {
    const candidate = queue[index]!;
    const cleaned = stripCommonWrappers(candidate);
    push(cleaned);

    if (cleaned.includes('/')) {
      for (const part of cleaned.split('/')) push(part);
    }
    if (cleaned.includes(':')) {
      for (const part of cleaned.split(':')) push(part);
    }
    if (cleaned.includes(',')) {
      for (const part of cleaned.split(',')) push(part);
    }
  }

  return queue;
}

function buildMatchContext(modelName: string): BrandMatchContext {
  const candidates = collectBrandCandidates(modelName);
  const raw = candidates[0] || normalizeInput(modelName);
  const cleaned = stripCommonWrappers(raw);
  const segments = Array.from(new Set(
    candidates
      .flatMap((candidate) => candidate.split(/[/:,\s]+/g))
      .map((segment) => segment.trim())
      .filter(Boolean),
  ));

  return {
    raw,
    cleaned,
    segments,
    candidates,
  };
}

function matchesRule(context: BrandMatchContext, rule: BrandRule): boolean {
  switch (rule.mode) {
    case 'includes':
      return context.raw.includes(rule.keyword)
        || context.cleaned.includes(rule.keyword)
        || context.candidates.some((candidate) => candidate.includes(rule.keyword));
    case 'startsWith':
      return context.raw.startsWith(rule.keyword)
        || context.cleaned.startsWith(rule.keyword)
        || context.segments.some((segment) => segment.startsWith(rule.keyword))
        || context.candidates.some((candidate) => candidate.startsWith(rule.keyword));
    case 'segment':
      return context.segments.includes(rule.keyword);
    case 'boundary': {
      const pattern = new RegExp(`(^|[/:_\\-\\s])${escapeRegExp(rule.keyword)}(?=$|[/:_\\-\\s])`);
      return pattern.test(context.raw)
        || pattern.test(context.cleaned)
        || context.candidates.some((candidate) => pattern.test(candidate));
    }
    default:
      return false;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const BRAND_FALLBACK_BOUNDARY_RULES = BRAND_DEFINITIONS.map((brand) => ({
  brand,
  boundaryRegex: new RegExp(`(^|[^a-z0-9])${escapeRegExp(brand.name.toLowerCase())}(?=$|[^a-z0-9])`),
}));

export function getAllBrands(): BrandInfo[] {
  return BRAND_DEFINITIONS.map(({ name, icon, color }) => ({ name, icon, color }));
}

export function getAllBrandNames(): string[] {
  return BRAND_DEFINITIONS.map((brand) => brand.name);
}

function toBrandInfo(brand: BrandDefinition): BrandInfo {
  return {
    name: brand.name,
    icon: brand.icon,
    color: brand.color,
  };
}

export function getMatchingBrands(modelName: string): BrandInfo[] {
  const context = buildMatchContext(modelName);
  const matches: BrandInfo[] = [];
  const seen = new Set<string>();

  const add = (brand: BrandDefinition) => {
    if (seen.has(brand.name)) return;
    seen.add(brand.name);
    matches.push(toBrandInfo(brand));
  };

  for (const definition of BRAND_DEFINITIONS) {
    if (definition.rules.some((rule) => matchesRule(context, rule))) {
      add(definition);
    }
  }

  for (const candidate of context.candidates) {
    for (const rule of BRAND_FALLBACK_BOUNDARY_RULES) {
      if (rule.boundaryRegex.test(candidate)) {
        add(rule.brand);
      }
    }
  }

  return matches;
}

export function getMatchingBrandNames(modelName: string): string[] {
  return getMatchingBrands(modelName).map((brand) => brand.name);
}

export function getBrand(modelName: string): BrandInfo | null {
  return getMatchingBrands(modelName)[0] || null;
}
