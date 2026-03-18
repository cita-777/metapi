import { config } from '../../config.js';
import { pullSseDataEvents } from '../../services/proxyUsageParser.js';

type FailureResult = {
  status: number;
  reason: string;
};

type UsageSummary = {
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
};

function normalizeKeywords(values: string[]): string[] {
  return values
    .map((item) => (typeof item === 'string' ? item.trim() : ''))
    .filter((item) => item.length > 0)
    .map((item) => item.toLowerCase());
}

function toNonNegativeInt(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.trunc(n));
}

function hasNonEmptyString(value: unknown): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function hasToolCallLike(value: unknown): boolean {
  if (!value) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (isRecord(value)) return Object.keys(value).length > 0;
  return false;
}

function hasCompletionContentFromChoice(choice: any): boolean {
  if (hasNonEmptyString(choice?.text)) return true;
  if (hasNonEmptyString(choice?.completion)) return true;
  if (hasNonEmptyString(choice?.output_text)) return true;

  const message = choice?.message;
  if (hasNonEmptyString(message?.content)) return true;
  if (Array.isArray(message?.content)) {
    for (const part of message.content) {
      if (hasNonEmptyString(part?.text) || hasNonEmptyString(part?.output_text) || hasNonEmptyString(part?.content)) {
        return true;
      }
    }
  }

  if (hasNonEmptyString(message?.refusal)) return true;
  if (hasToolCallLike(message?.tool_calls)) return true;
  if (hasToolCallLike(message?.toolCalls)) return true;
  if (hasToolCallLike(message?.function_call)) return true;
  if (hasToolCallLike(message?.functionCall)) return true;

  if (hasToolCallLike(choice?.tool_calls)) return true;
  if (hasToolCallLike(choice?.toolCalls)) return true;
  if (hasToolCallLike(choice?.function_call)) return true;
  if (hasToolCallLike(choice?.functionCall)) return true;

  const delta = choice?.delta;
  if (hasNonEmptyString(delta?.content)) return true;
  if (hasNonEmptyString(delta?.refusal)) return true;
  if (hasToolCallLike(delta?.tool_calls)) return true;
  if (hasToolCallLike(delta?.toolCalls)) return true;
  if (hasToolCallLike(delta?.function_call)) return true;
  if (hasToolCallLike(delta?.functionCall)) return true;

  return false;
}

function hasCompletionContentFromPayload(payload: unknown): boolean {
  if (!payload || typeof payload !== 'object') return false;
  const obj: any = payload;

  if (Array.isArray(obj?.choices)) {
    for (const choice of obj.choices) {
      if (hasCompletionContentFromChoice(choice)) return true;
    }
    if (hasCompletionContentFromChoice(obj)) return true;
  }

  if (hasNonEmptyString(obj?.output_text)) return true;
  if (hasNonEmptyString(obj?.outputText)) return true;

  if (Array.isArray(obj?.output)) {
    for (const item of obj.output) {
      if (!isRecord(item)) continue;
      const type = String((item as any).type || '').toLowerCase();
      if (type.includes('function_call') || type.includes('tool_call')) return true;

      if (hasNonEmptyString((item as any).text) || hasNonEmptyString((item as any).output_text)) return true;

      if (Array.isArray((item as any).content)) {
        for (const part of (item as any).content) {
          if (hasNonEmptyString((part as any)?.text) || hasNonEmptyString((part as any)?.output_text) || hasNonEmptyString((part as any)?.content)) {
            return true;
          }
          const partType = String((part as any)?.type || '').toLowerCase();
          if (partType.includes('function_call') || partType.includes('tool_call')) return true;
        }
      }

      if (hasToolCallLike((item as any).tool_calls) || hasToolCallLike((item as any).toolCalls)) return true;
      if (hasToolCallLike((item as any).function_call) || hasToolCallLike((item as any).functionCall)) return true;
    }
  }

  if (Array.isArray(obj?.content)) {
    for (const part of obj.content) {
      if (hasNonEmptyString((part as any)?.text) || hasNonEmptyString((part as any)?.output_text) || hasNonEmptyString((part as any)?.content)) {
        return true;
      }
      const partType = String((part as any)?.type || '').toLowerCase();
      if (partType.includes('function_call') || partType.includes('tool_call')) return true;
    }
  }

  if (hasNonEmptyString(obj?.delta)) return true;
  if (hasNonEmptyString(obj?.text)) return true;
  if (hasToolCallLike(obj?.tool_calls) || hasToolCallLike(obj?.toolCalls)) return true;
  if (hasToolCallLike(obj?.function_call) || hasToolCallLike(obj?.functionCall)) return true;

  return false;
}

function detectHasUpstreamOutput(rawText: string): boolean {
  const text = typeof rawText === 'string' ? rawText : '';
  const trimmed = text.trim();
  if (!trimmed) return false;

  try {
    const parsed = JSON.parse(trimmed);
    return hasCompletionContentFromPayload(parsed);
  } catch {
    // Important: don't trim before SSE parsing, otherwise `data: [DONE]\n\n` can be lost.
    const pulled = pullSseDataEvents(text);
    if (pulled.events.length > 0) {
      for (const event of pulled.events) {
        const payload = event.trim();
        if (!payload || payload === '[DONE]') continue;
        try {
          const parsedEvent = JSON.parse(payload);
          if (hasCompletionContentFromPayload(parsedEvent)) return true;
        } catch {
          // Non-JSON payload still counts as upstream output.
          return true;
        }
      }
      // SSE payloads exist but none contain output.
      return false;
    }

    // Looks like SSE but contains no non-DONE payloads.
    if (text.includes('data:')) return false;

    // Not JSON and not SSE: assume it's plain text output.
    return true;
  }
}

export function detectProxyFailure(input: {
  rawText: string;
  usage?: UsageSummary | null;
  // Backward-compatible fields (older call sites)
  completionTokens?: number;
  totalTokens?: number;
}): FailureResult | null {
  const rawText = typeof input.rawText === 'string' ? input.rawText : '';
  const keywords = normalizeKeywords(config.proxyErrorKeywords || []);
  if (keywords.length > 0) {
    const normalizedText = rawText.toLowerCase();
    const matched = keywords.find((keyword) => normalizedText.includes(keyword));
    if (matched) {
      return {
        status: 502,
        reason: `Upstream response matched failure keyword: ${matched}`,
      };
    }
  }

  if (config.proxyEmptyContentFailEnabled) {
    const completionTokens = toNonNegativeInt(input.usage?.completionTokens ?? input.completionTokens);
    const hasOutput = detectHasUpstreamOutput(rawText);

    if (!hasOutput && completionTokens <= 0) {
      return {
        status: 502,
        reason: 'Upstream returned empty content',
      };
    }
  }

  return null;
}
