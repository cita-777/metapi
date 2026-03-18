type GeminiRecord = Record<string, unknown>;
import {
  geminiThinkingConfigToReasoning,
  resolveGeminiThinkingConfigFromRequest,
} from './convert.js';

function isRecord(value: unknown): value is GeminiRecord {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function cloneJsonValue<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => cloneJsonValue(item)) as T;
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, cloneJsonValue(item)]),
    ) as T;
  }
  return value;
}

function cloneContents(value: unknown): unknown[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value
    .filter((item) => isRecord(item))
    .map((item) => {
      const next: GeminiRecord = { ...item };
      if (Array.isArray(item.parts)) {
        next.parts = item.parts.map((part) => (isRecord(part) ? cloneJsonValue(part) : part));
      }
      return next;
    });
}

function cloneThinkingConfig(value: unknown): GeminiRecord | undefined {
  if (!isRecord(value)) return undefined;

  const next: GeminiRecord = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'thinkingLevel') {
      const normalizedLevel = typeof item === 'string' ? item.trim().toLowerCase() : '';
      if (normalizedLevel === 'minimal') {
        next.thinkingLevel = 'low';
        continue;
      }
      if (normalizedLevel) {
        next.thinkingLevel = normalizedLevel;
        continue;
      }
    }

    if (key === 'thinkingBudget') {
      const numeric = typeof item === 'number' ? item : Number(item);
      if (Number.isFinite(numeric)) {
        next.thinkingBudget = Math.max(0, Math.trunc(numeric));
        continue;
      }
    }

    next[key] = cloneJsonValue(item);
  }

  return Object.keys(next).length > 0 ? next : undefined;
}

function cloneGenerationConfig(value: unknown): GeminiRecord | undefined {
  if (!isRecord(value)) return undefined;
  const allowedKeys = [
    'stopSequences',
    'responseModalities',
    'responseMimeType',
    'responseSchema',
    'candidateCount',
    'maxOutputTokens',
    'temperature',
    'topP',
    'topK',
    'presencePenalty',
    'frequencyPenalty',
    'seed',
    'responseLogprobs',
    'logprobs',
    'thinkingConfig',
    'imageConfig',
  ];
  const next: GeminiRecord = {};
  for (const key of allowedKeys) {
    if (value[key] === undefined) continue;
    if (key === 'thinkingConfig') {
      next[key] = cloneThinkingConfig(value[key]) ?? cloneJsonValue(value[key]);
      continue;
    }
    next[key] = cloneJsonValue(value[key]);
  }
  return Object.keys(next).length > 0 ? next : undefined;
}

function cloneTools(value: unknown): unknown[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value
    .filter((item) => isRecord(item))
    .map((item) => {
      const next: GeminiRecord = {};
      if (item.functionDeclarations !== undefined) next.functionDeclarations = cloneJsonValue(item.functionDeclarations);
      if (item.googleSearch !== undefined) next.googleSearch = cloneJsonValue(item.googleSearch);
      if (item.urlContext !== undefined) next.urlContext = cloneJsonValue(item.urlContext);
      if (item.codeExecution !== undefined) next.codeExecution = cloneJsonValue(item.codeExecution);
      return Object.keys(next).length > 0 ? next : cloneJsonValue(item);
    });
}

function hasMeaningfulThinkingConfig(value: unknown): boolean {
  return isRecord(value) && geminiThinkingConfigToReasoning(value) !== null;
}

function sanitizeThinkingConfig(value: unknown): GeminiRecord | undefined {
  if (!isRecord(value)) return undefined;

  const next = cloneJsonValue(value);
  const normalizedReasoning = geminiThinkingConfigToReasoning(next);
  if (normalizedReasoning) {
    return next;
  }

  if ('thinkingLevel' in next) {
    delete next.thinkingLevel;
  }

  if ('thinkingBudget' in next) {
    const numeric = typeof next.thinkingBudget === 'number' ? next.thinkingBudget : Number(next.thinkingBudget);
    if (Number.isFinite(numeric)) {
      next.thinkingBudget = Math.max(0, Math.trunc(numeric));
    } else {
      delete next.thinkingBudget;
    }
  }

  return Object.keys(next).length > 0 ? next : undefined;
}

function mergeThinkingConfig(
  currentValue: unknown,
  derivedThinkingConfig: GeminiRecord | null,
): GeminiRecord | undefined {
  const currentThinkingConfig = sanitizeThinkingConfig(currentValue);

  if (!derivedThinkingConfig) {
    return currentThinkingConfig;
  }

  if (!hasMeaningfulThinkingConfig(currentThinkingConfig)) {
    return {
      ...(currentThinkingConfig ?? {}),
      ...cloneJsonValue(derivedThinkingConfig),
    };
  }

  return currentThinkingConfig;
}

export type GeminiGenerateContentRequest = GeminiRecord;

export const geminiGenerateContentInbound = {
  normalizeRequest(body: unknown, modelName = ''): GeminiGenerateContentRequest {
    if (!isRecord(body)) return {};

    const next: GeminiGenerateContentRequest = {};
    if (body.contents !== undefined) next.contents = cloneContents(body.contents) ?? cloneJsonValue(body.contents);
    if (body.systemInstruction !== undefined) next.systemInstruction = cloneJsonValue(body.systemInstruction);
    if (body.cachedContent !== undefined) next.cachedContent = cloneJsonValue(body.cachedContent);
    if (body.safetySettings !== undefined) next.safetySettings = cloneJsonValue(body.safetySettings);
    if (body.generationConfig !== undefined) {
      next.generationConfig = cloneGenerationConfig(body.generationConfig) ?? cloneJsonValue(body.generationConfig);
    }
    if (body.tools !== undefined) next.tools = cloneTools(body.tools) ?? cloneJsonValue(body.tools);
    if (body.toolConfig !== undefined) next.toolConfig = cloneJsonValue(body.toolConfig);

    const derivedThinkingConfig = resolveGeminiThinkingConfigFromRequest(
      modelName || (typeof body.model === 'string' ? body.model : ''),
      body,
    );
    if (derivedThinkingConfig) {
      const generationConfig = isRecord(next.generationConfig)
        ? { ...next.generationConfig }
        : {};
      const thinkingConfig = mergeThinkingConfig(
        generationConfig.thinkingConfig,
        derivedThinkingConfig,
      );
      if (thinkingConfig) {
        generationConfig.thinkingConfig = thinkingConfig;
      }
      next.generationConfig = generationConfig;
    }

    // Only forward fields that Gemini API supports. Unknown fields
    // (e.g. requestId, frequency_penalty) cause upstream 400 errors.
    const allowedPassthroughKeys = new Set([
      'contents',
      'systemInstruction',
      'cachedContent',
      'safetySettings',
      'generationConfig',
      'tools',
      'toolConfig',
      'labels',
      'model',
    ]);

    for (const [key, value] of Object.entries(body)) {
      if (!allowedPassthroughKeys.has(key)) continue;
      if (next[key] !== undefined) continue;
      next[key] = cloneJsonValue(value);
    }

    return next;
  },
};
