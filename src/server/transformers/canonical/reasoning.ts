import type { TransformerMetadata } from '../shared/normalized.js';
import type {
  CanonicalReasoningEffort,
  CanonicalReasoningRequest,
} from './types.js';

type CanonicalReasoningNormalizationInput = {
  include?: unknown;
  reasoning?: unknown;
  reasoning_effort?: unknown;
  reasoning_budget?: unknown;
  reasoning_summary?: unknown;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toFiniteInteger(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return undefined;
    const parsed = Number(trimmed);
    if (Number.isFinite(parsed)) return Math.trunc(parsed);
  }
  return undefined;
}

function normalizeReasoningEffort(value: unknown): CanonicalReasoningEffort | undefined {
  const effort = asTrimmedString(value).toLowerCase();
  switch (effort) {
    case 'none':
    case 'low':
    case 'medium':
    case 'high':
    case 'max':
      return effort;
    default:
      return undefined;
  }
}

function normalizeIncludeEntries(value: unknown): string[] {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (typeof item === 'string' ? item.trim() : ''))
    .filter((item) => item.length > 0);
}

export function normalizeCanonicalReasoningRequest(
  input: CanonicalReasoningNormalizationInput,
): {
  reasoning?: CanonicalReasoningRequest;
  metadata?: Pick<TransformerMetadata, 'include'>;
} {
  const rawReasoning = isRecord(input.reasoning) ? input.reasoning : {};
  const include = normalizeIncludeEntries(input.include);
  const filteredInclude = include.filter((item) => item !== 'reasoning.encrypted_content');

  const effort = normalizeReasoningEffort(rawReasoning.effort ?? input.reasoning_effort);
  const budgetTokens = toFiniteInteger(rawReasoning.budget_tokens ?? rawReasoning.budgetTokens ?? input.reasoning_budget);
  const summary = asTrimmedString(rawReasoning.summary ?? input.reasoning_summary) || undefined;
  const includeEncryptedContent = include.includes('reasoning.encrypted_content') || undefined;

  const reasoning: CanonicalReasoningRequest | undefined = (
    effort
    || budgetTokens !== undefined
    || summary
    || includeEncryptedContent
  )
    ? {
      ...(effort ? { effort } : {}),
      ...(budgetTokens !== undefined ? { budgetTokens } : {}),
      ...(summary ? { summary } : {}),
      ...(includeEncryptedContent ? { includeEncryptedContent } : {}),
    }
    : undefined;

  const metadata = filteredInclude.length > 0
    ? { include: filteredInclude }
    : undefined;

  return {
    ...(reasoning ? { reasoning } : {}),
    ...(metadata ? { metadata } : {}),
  };
}
