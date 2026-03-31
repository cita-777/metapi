import { zstdCompressSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { Response } from 'undici';

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

  it('prefers aggregated stream content when response.completed only carries an empty output array', async () => {
    const upstream = {
      async text() {
        return [
          'event: response.created',
          'data: {"type":"response.created","response":{"id":"resp_empty_completed","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}',
          '',
          'event: response.output_item.added',
          'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_empty_completed","type":"message","role":"assistant","status":"in_progress","content":[]}}',
          '',
          'event: response.output_text.delta',
          'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_empty_completed","delta":"pong"}',
          '',
          'event: response.completed',
          'data: {"type":"response.completed","response":{"id":"resp_empty_completed","model":"gpt-5.4","status":"completed","output":[],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}',
          '',
          'data: [DONE]',
          '',
        ].join('\n');
      },
    };

    await expect(collectResponsesFinalPayloadFromSse(upstream, 'gpt-5.4'))
      .resolves
      .toMatchObject({
        payload: {
          id: 'resp_empty_completed',
          status: 'completed',
          output: [
            {
              id: 'msg_empty_completed',
              type: 'message',
              role: 'assistant',
              status: 'completed',
              content: [
                {
                  type: 'output_text',
                  text: 'pong',
                },
              ],
            },
          ],
          output_text: 'pong',
          usage: {
            input_tokens: 3,
            output_tokens: 1,
            total_tokens: 4,
          },
        },
      });
  });

  it('decodes zstd-compressed responses SSE before aggregating the final payload', async () => {
    const upstream = new Response(zstdCompressSync(Buffer.from([
      'event: response.created',
      'data: {"type":"response.created","response":{"id":"resp_zstd_completed","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}',
      '',
      'event: response.output_item.added',
      'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_zstd_completed","type":"message","role":"assistant","status":"in_progress","content":[]}}',
      '',
      'event: response.output_text.delta',
      'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_zstd_completed","delta":"你好，来自 zstd 聚合 SSE"}',
      '',
      'event: response.completed',
      'data: {"type":"response.completed","response":{"id":"resp_zstd_completed","model":"gpt-5.4","status":"completed","output":[],"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}',
      '',
      'data: [DONE]',
      '',
    ].join('\n'))), {
      status: 200,
      headers: {
        'content-encoding': 'zstd',
        'content-type': 'text/event-stream; charset=utf-8',
      },
    });

    await expect(collectResponsesFinalPayloadFromSse(upstream, 'gpt-5.4'))
      .resolves
      .toMatchObject({
        payload: {
          id: 'resp_zstd_completed',
          status: 'completed',
          output_text: '你好，来自 zstd 聚合 SSE',
        },
        rawText: expect.stringContaining('你好，来自 zstd 聚合 SSE'),
      });
  });

  it('returns response.incomplete payloads instead of treating them as upstream failures', async () => {
    const upstream = {
      async text() {
        return [
          'event: response.created',
          'data: {"type":"response.created","response":{"id":"resp_incomplete_terminal","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}',
          '',
          'event: response.incomplete',
          'data: {"type":"response.incomplete","response":{"id":"resp_incomplete_terminal","model":"gpt-5.4","status":"incomplete","output":[{"id":"msg_incomplete_1","type":"message","role":"assistant","status":"incomplete","content":[{"type":"output_text","text":"partial answer"}]}],"output_text":"partial answer","incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}',
          '',
          'data: [DONE]',
          '',
        ].join('\n');
      },
    };

    await expect(collectResponsesFinalPayloadFromSse(upstream, 'gpt-5.4'))
      .resolves
      .toMatchObject({
        payload: {
          id: 'resp_incomplete_terminal',
          status: 'incomplete',
          output_text: 'partial answer',
          incomplete_details: {
            reason: 'max_output_tokens',
          },
        },
      });
  });

  it('returns response.incomplete terminal payloads instead of throwing', async () => {
    const upstream = {
      async text() {
        return [
          'event: response.created',
          'data: {"type":"response.created","response":{"id":"resp_incomplete_1","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}',
          '',
          'event: response.output_text.delta',
          'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_incomplete_1","delta":"partial"}',
          '',
          'event: response.incomplete',
          'data: {"type":"response.incomplete","response":{"id":"resp_incomplete_1","model":"gpt-5.4","status":"incomplete","output":[{"id":"msg_incomplete_1","type":"message","role":"assistant","status":"incomplete","content":[{"type":"output_text","text":"partial"}]}],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}',
          '',
          'data: [DONE]',
          '',
        ].join('\n');
      },
    };

    await expect(collectResponsesFinalPayloadFromSse(upstream, 'gpt-5.4'))
      .resolves
      .toMatchObject({
        payload: {
          id: 'resp_incomplete_1',
          status: 'incomplete',
          incomplete_details: {
            reason: 'max_output_tokens',
          },
          output_text: 'partial',
        },
      });
  });

  it('treats response.incomplete as terminal even when only response.output carries the visible text', async () => {
    const upstream = {
      async text() {
        return [
          'event: response.created',
          'data: {"type":"response.created","response":{"id":"resp_incomplete_output_only","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}',
          '',
          'event: response.incomplete',
          'data: {"type":"response.incomplete","response":{"id":"resp_incomplete_output_only","model":"gpt-5.4","status":"incomplete","output":[{"id":"msg_incomplete_output_only","type":"message","role":"assistant","status":"incomplete","content":[{"type":"output_text","text":"partial from output"}]}],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}',
          '',
          'data: [DONE]',
          '',
        ].join('\n');
      },
    };

    await expect(collectResponsesFinalPayloadFromSse(upstream, 'gpt-5.4'))
      .resolves
      .toMatchObject({
        payload: {
          id: 'resp_incomplete_output_only',
          status: 'incomplete',
          output: [
            {
              id: 'msg_incomplete_output_only',
              type: 'message',
              role: 'assistant',
              status: 'incomplete',
              content: [
                {
                  type: 'output_text',
                  text: 'partial from output',
                },
              ],
            },
          ],
          output_text: 'partial from output',
          incomplete_details: {
            reason: 'max_output_tokens',
          },
        },
      });
  });

  it('preserves incomplete item status when response.incomplete needs aggregate output repair', async () => {
    const upstream = {
      async text() {
        return [
          'event: response.created',
          'data: {"type":"response.created","response":{"id":"resp_incomplete_repair","model":"gpt-5.4","created_at":1706000000,"status":"in_progress","output":[]}}',
          '',
          'event: response.output_item.added',
          'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_incomplete_repair","type":"message","role":"assistant","status":"in_progress","content":[]}}',
          '',
          'event: response.output_text.delta',
          'data: {"type":"response.output_text.delta","output_index":0,"item_id":"msg_incomplete_repair","delta":"partial repair"}',
          '',
          'event: response.incomplete',
          'data: {"type":"response.incomplete","response":{"id":"resp_incomplete_repair","model":"gpt-5.4","status":"incomplete","output":[],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4}}}',
          '',
          'data: [DONE]',
          '',
        ].join('\n');
      },
    };

    await expect(collectResponsesFinalPayloadFromSse(upstream, 'gpt-5.4'))
      .resolves
      .toMatchObject({
        payload: {
          id: 'resp_incomplete_repair',
          status: 'incomplete',
          output: [
            {
              id: 'msg_incomplete_repair',
              type: 'message',
              role: 'assistant',
              status: 'incomplete',
              content: [
                {
                  type: 'output_text',
                  text: 'partial repair',
                },
              ],
            },
          ],
          output_text: 'partial repair',
          incomplete_details: {
            reason: 'max_output_tokens',
          },
        },
      });
  });
});
