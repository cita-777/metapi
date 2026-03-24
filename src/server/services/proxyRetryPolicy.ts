const MODEL_UNSUPPORTED_PATTERNS: RegExp[] = [
  /当前\s*api\s*不支持所选模型/i,
  /不支持所选模型/i,
  /不支持.*模型/i,
  /模型.*不支持/i,
  /unsupported\s+model/i,
  /model\s+not\s+supported/i,
  /does\s+not\s+support(?:\s+the)?\s+model/i,
  /model.*does\s+not\s+exist/i,
  /no\s+such\s+model/i,
  /unknown\s+model/i,
  /invalid\s+model/i,
  /model[_\s-]?not[_\s-]?found/i,
  /you\s+do\s+not\s+have\s+access\s+to\s+the\s+model/i,
];

export const RETRYABLE_TIMEOUT_PATTERNS: RegExp[] = [
  /(request timed out|connection timed out|read timeout|\btimed out\b)/i,
];

const RETRYABLE_CHANNEL_LOCAL_PATTERNS: RegExp[] = [
  /unsupported\s+legacy\s+protocol/i,
  /please\s+use\s+\/v1\/responses/i,
  /please\s+use\s+\/v1\/messages/i,
  /please\s+use\s+\/v1\/chat\/completions/i,
  /does\s+not\s+allow\s+\/v1\/[a-z0-9/_:-]+\s+dispatch/i,
  /unsupported\s+endpoint/i,
  /unsupported\s+path/i,
  /unknown\s+endpoint/i,
  /unrecognized\s+request\s+url/i,
  /no\s+route\s+matched/i,
  /invalid\s+api\s+key/i,
  /invalid\s+access\s+token/i,
  /forbidden/i,
  /rate\s+limit/i,
  /quota/i,
  /bad\s+gateway/i,
  /gateway\s+time-?out/i,
  /service\s+unavailable/i,
  /cpu\s+overloaded/i,
  ...RETRYABLE_TIMEOUT_PATTERNS,
];

const NON_RETRYABLE_REQUEST_PATTERNS: RegExp[] = [
  /invalid\s+request\s+body/i,
  /validation/i,
  /missing\s+required/i,
  /required\s+parameter/i,
  /unknown\s+parameter/i,
  /unrecognized\s+(field|key|parameter)/i,
  /malformed/i,
  /invalid\s+json/i,
  /cannot\s+parse/i,
  /unsupported\s+media\s+type/i,
];

function isModelUnsupportedErrorMessage(rawMessage?: string | null): boolean {
  const text = (rawMessage || '').trim();
  if (!text) return false;
  return MODEL_UNSUPPORTED_PATTERNS.some((pattern) => pattern.test(text));
}

function matchesAnyPattern(patterns: RegExp[], rawMessage?: string | null): boolean {
  const text = (rawMessage || '').trim();
  if (!text) return false;
  return patterns.some((pattern) => pattern.test(text));
}

export function shouldRetryProxyRequest(status: number, upstreamErrorText?: string | null): boolean {
  if (status >= 500) return true;
  if (status === 408 || status === 409 || status === 425 || status === 429) return true;
  if (status === 401 || status === 403) return true;
  if (isModelUnsupportedErrorMessage(upstreamErrorText)) return true;
  if (matchesAnyPattern(NON_RETRYABLE_REQUEST_PATTERNS, upstreamErrorText)) return false;
  if (matchesAnyPattern(RETRYABLE_CHANNEL_LOCAL_PATTERNS, upstreamErrorText)) return true;
  if (status === 400 || status === 404 || status === 422) return false;
  return false;
}
