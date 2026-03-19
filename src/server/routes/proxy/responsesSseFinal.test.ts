import { describe, expect, it } from 'vitest';

import { collectResponsesFinalPayloadFromSse } from './responsesSseFinal.js';

describe('collectResponsesFinalPayloadFromSse', () => {
  it('treats event:error payloads as upstream failures', async () => {
    const upstream = {
      async text() {
        return [
          'event: error',
          'data: {"error":{"message":"quota exceeded"},"type":"error"}',
          '',
          'data: [DONE]',
          '',
        ].join('\n');
      },
    };

    await expect(collectResponsesFinalPayloadFromSse(upstream, 'gpt-5.4'))
      .rejects
      .toThrow('quota exceeded');
  });
});
