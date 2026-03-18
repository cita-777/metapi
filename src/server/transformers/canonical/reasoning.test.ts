import { describe, expect, it } from 'vitest';

import { normalizeCanonicalReasoningRequest } from './reasoning.js';

describe('canonical reasoning helpers', () => {
  it('normalizes reasoning config and keeps non-reasoning include entries in metadata', () => {
    const normalized = normalizeCanonicalReasoningRequest({
      include: [' reasoning.encrypted_content ', '', 'message.input_image.image_url'],
      reasoning: {
        effort: 'high',
      },
      reasoning_budget: '2048',
      reasoning_summary: 'detailed',
    });

    expect(normalized.reasoning).toEqual({
      effort: 'high',
      budgetTokens: 2048,
      summary: 'detailed',
      includeEncryptedContent: true,
    });
    expect(normalized.metadata).toEqual({
      include: ['message.input_image.image_url'],
    });
  });

  it('returns undefined when no reasoning hints are present', () => {
    expect(normalizeCanonicalReasoningRequest({})).toEqual({});
  });
});
