import { config } from '../../config.js';

type FailureResult = {
  status: number;
  reason: string;
};

function normalizeKeywords(values: string[]): string[] {
  return values
    .map((item) => (typeof item === 'string' ? item.trim() : ''))
    .filter((item) => item.length > 0)
    .map((item) => item.toLowerCase());
}

export function detectProxyFailure(input: {
  rawText: string;
  totalTokens: number;
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

  if (config.proxyEmptyContentFailEnabled && input.totalTokens <= 0) {
    return {
      status: 502,
      reason: 'Upstream returned empty content',
    };
  }

  return null;
}
