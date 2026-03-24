import { describe, expect, it } from 'vitest';

import { serializeResponsesFinalPayload } from './outbound.js';

describe('serializeResponsesFinalPayload', () => {
  it('preserves native response.compaction payloads when compact serialization is requested', () => {
    const upstreamPayload = {
      id: 'cmp_123',
      object: 'response.compaction',
      created_at: 1700000000,
      output: [
        {
          id: 'rs_123',
          type: 'compaction',
          encrypted_content: 'enc-compact-payload',
        },
      ],
      usage: {
        input_tokens: 1234,
        output_tokens: 321,
        total_tokens: 1555,
      },
    };

    const payload = serializeResponsesFinalPayload({
      upstreamPayload,
      normalized: {
        id: 'cmp_123',
        model: 'gpt-5',
        created: 1700000000,
        content: '',
        reasoningContent: '',
        finishReason: 'stop',
        toolCalls: [],
      },
      usage: {
        promptTokens: 1234,
        completionTokens: 321,
        totalTokens: 1555,
      },
      serializationMode: 'compact',
    } as any);

    expect(payload).toEqual(upstreamPayload);
  });

  it('serializes compact mode as response.compaction instead of an ordinary response object', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'chatcmpl_compact',
        object: 'chat.completion',
        created: 1700000000,
        model: 'gpt-5',
        choices: [
          {
            index: 0,
            finish_reason: 'stop',
            message: {
              role: 'assistant',
              content: 'hello',
            },
          },
        ],
      },
      normalized: {
        id: 'chatcmpl_compact',
        model: 'gpt-5',
        created: 1700000000,
        content: 'hello',
        reasoningContent: '',
        finishReason: 'stop',
        toolCalls: [],
      },
      usage: {
        promptTokens: 11,
        completionTokens: 7,
        totalTokens: 18,
      },
      serializationMode: 'compact',
    } as any);

    expect(payload).toEqual({
      id: 'resp_chatcmpl_compact',
      object: 'response.compaction',
      created_at: 1700000000,
      output: [
        {
          id: 'msg_chatcmpl_compact',
          type: 'message',
          role: 'assistant',
          status: 'completed',
          content: [
            {
              type: 'output_text',
              text: 'hello',
            },
          ],
        },
      ],
      usage: {
        input_tokens: 11,
        output_tokens: 7,
        total_tokens: 18,
      },
    });
    expect(payload).not.toHaveProperty('created');
    expect(payload).not.toHaveProperty('status');
    expect(payload).not.toHaveProperty('model');
    expect(payload).not.toHaveProperty('output_text');
  });

  it('serializes response mode with created_at instead of created', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'chatcmpl_response_mode',
        object: 'chat.completion',
        created: 1700000000,
        model: 'gpt-5',
        choices: [
          {
            index: 0,
            finish_reason: 'stop',
            message: {
              role: 'assistant',
              content: 'hello',
            },
          },
        ],
      },
      normalized: {
        id: 'chatcmpl_response_mode',
        model: 'gpt-5',
        created: 1700000000,
        content: 'hello',
        reasoningContent: '',
        finishReason: 'stop',
        toolCalls: [],
      },
      usage: {
        promptTokens: 11,
        completionTokens: 7,
        totalTokens: 18,
      },
    } as any);

    expect(payload).toMatchObject({
      object: 'response',
      created_at: 1700000000,
    });
    expect(payload).not.toHaveProperty('created');
  });

  it('preserves top-level chat annotations on synthetic assistant messages', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'chatcmpl_1',
        object: 'chat.completion',
        created: 1700000000,
        model: 'gpt-5',
        choices: [
          {
            index: 0,
            finish_reason: 'stop',
            message: {
              role: 'assistant',
              content: 'hello',
              annotations: [
                {
                  type: 'url_citation',
                  url: 'https://example.com',
                  title: 'Example',
                },
              ],
            },
          },
        ],
      },
      normalized: {
        id: 'chatcmpl_1',
        model: 'gpt-5',
        created: 1700000000,
        content: 'hello',
        reasoningContent: '',
        finishReason: 'stop',
        toolCalls: [],
      },
      usage: {
        promptTokens: 1,
        completionTokens: 2,
        totalTokens: 3,
      },
    });

    expect(payload.output).toEqual([
      {
        id: 'msg_chatcmpl_1',
        type: 'message',
        role: 'assistant',
        status: 'completed',
        content: [
          {
            type: 'output_text',
            text: 'hello',
            annotations: [
              {
                type: 'url_citation',
                url: 'https://example.com',
                title: 'Example',
              },
            ],
          },
        ],
      },
    ]);
  });

  it('falls back to normalized tool calls when upstream payload no longer exposes them directly', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'opaque_1',
        model: 'gpt-5',
      },
      normalized: {
        id: 'opaque_1',
        model: 'gpt-5',
        created: 1700000000,
        content: '',
        reasoningContent: '',
        finishReason: 'tool_calls',
        toolCalls: [
          {
            id: 'call_1',
            name: 'browser',
            arguments: '{"url":"https://example.com"}',
          },
        ],
      },
      usage: {
        promptTokens: 1,
        completionTokens: 2,
        totalTokens: 3,
      },
    });

    expect(payload.output).toEqual([
      {
        id: 'call_1',
        type: 'function_call',
        status: 'completed',
        call_id: 'call_1',
        name: 'browser',
        arguments: '{"url":"https://example.com"}',
      },
    ]);
  });

  it('restores mcp items from compatibility tool calls when serializing fallback response payloads', () => {
    const mcpCall = {
      type: 'mcp_call',
      id: 'mcp_call_1',
      call_id: 'mcp_call_1',
      name: 'read_file',
      server_label: 'filesystem',
      arguments: {
        path: '/tmp/demo.txt',
      },
    };

    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'opaque_mcp_1',
        model: 'gpt-5',
      },
      normalized: {
        id: 'opaque_mcp_1',
        model: 'gpt-5',
        created: 1700000000,
        content: '',
        reasoningContent: '',
        finishReason: 'tool_calls',
        toolCalls: [
          {
            id: 'mcp_call_1',
            name: 'metapi_mcp_item__mcp_call',
            arguments: JSON.stringify({
              metapi_compat: 'responses_mcp_item',
              itemType: 'mcp_call',
              item: mcpCall,
            }),
          },
        ],
      },
      usage: {
        promptTokens: 1,
        completionTokens: 2,
        totalTokens: 3,
      },
    });

    expect(payload.output).toEqual([mcpCall]);
  });

  it('preserves response-like custom tool and image generation items when synthesizing object=response payloads', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'resp_like_1',
        model: 'gpt-5',
        output: [
          {
            id: 'ct_1',
            type: 'custom_tool_call',
            status: 'completed',
            call_id: 'ct_1',
            name: 'browser',
            input: 'open example.com',
          },
          {
            id: 'img_1',
            type: 'image_generation_call',
            status: 'completed',
            result: 'data:image/png;base64,final',
            background: 'transparent',
            output_format: 'png',
            quality: 'high',
            size: '1024x1024',
            partial_images: [
              {
                partial_image_index: 0,
                partial_image_b64: 'partial',
              },
            ],
          },
        ],
      },
      normalized: {
        id: 'resp_like_1',
        model: 'gpt-5',
        created: 1700000000,
        content: '',
        reasoningContent: '',
        finishReason: 'stop',
        toolCalls: [],
      },
      usage: {
        promptTokens: 1,
        completionTokens: 2,
        totalTokens: 3,
      },
    });

    expect(payload.output).toEqual([
      {
        id: 'ct_1',
        type: 'custom_tool_call',
        status: 'completed',
        call_id: 'ct_1',
        name: 'browser',
        input: 'open example.com',
      },
      {
        id: 'img_1',
        type: 'image_generation_call',
        status: 'completed',
        result: 'data:image/png;base64,final',
        background: 'transparent',
        output_format: 'png',
        quality: 'high',
        size: '1024x1024',
        partial_images: [
          {
            partial_image_index: 0,
            partial_image_b64: 'partial',
          },
        ],
      },
    ]);
  });

  it('maps upstream chat-completion usage details into Responses usage details', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'chatcmpl_usage',
        object: 'chat.completion',
        created: 1700000000,
        model: 'gpt-5',
        choices: [
          {
            index: 0,
            finish_reason: 'stop',
            message: {
              role: 'assistant',
              content: 'hello',
            },
          },
        ],
        usage: {
          prompt_tokens: 11,
          completion_tokens: 7,
          total_tokens: 18,
          prompt_tokens_details: {
            cached_tokens: 5,
            audio_tokens: 2,
          },
          completion_tokens_details: {
            reasoning_tokens: 3,
            audio_tokens: 1,
            accepted_prediction_tokens: 4,
            rejected_prediction_tokens: 6,
          },
        },
      },
      normalized: {
        id: 'chatcmpl_usage',
        model: 'gpt-5',
        created: 1700000000,
        content: 'hello',
        reasoningContent: '',
        finishReason: 'stop',
        toolCalls: [],
      },
      usage: {
        promptTokens: 11,
        completionTokens: 7,
        totalTokens: 18,
      },
    });

    expect(payload.usage).toMatchObject({
      input_tokens: 11,
      output_tokens: 7,
      total_tokens: 18,
      input_tokens_details: {
        cached_tokens: 5,
        audio_tokens: 2,
      },
      output_tokens_details: {
        reasoning_tokens: 3,
        audio_tokens: 1,
        accepted_prediction_tokens: 4,
        rejected_prediction_tokens: 6,
      },
    });
  });

  it('restores encrypted reasoning content from provider-tagged reasoning signatures', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'chatcmpl_reasoning',
        model: 'gpt-5',
      },
      normalized: {
        id: 'chatcmpl_reasoning',
        model: 'gpt-5',
        created: 1700000000,
        content: '',
        reasoningContent: 'Think step by step',
        reasoningSignature: 'metapi:openai-encrypted-reasoning:enc-sig-1',
        finishReason: 'stop',
        toolCalls: [],
      } as any,
      usage: {
        promptTokens: 1,
        completionTokens: 2,
        totalTokens: 3,
      },
    });

    expect(payload.output).toEqual([
      {
        id: 'msg_chatcmpl_reasoning_reasoning',
        type: 'reasoning',
        status: 'completed',
        encrypted_content: 'enc-sig-1',
        summary: [
          {
            type: 'summary_text',
            text: 'Think step by step',
          },
        ],
      },
    ]);
  });

  it('emits encrypted-only reasoning items when summary text is empty', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'chatcmpl_reasoning_only',
        model: 'gpt-5',
      },
      normalized: {
        id: 'chatcmpl_reasoning_only',
        model: 'gpt-5',
        created: 1700000000,
        content: '',
        reasoningContent: '',
        reasoningSignature: 'metapi:openai-encrypted-reasoning:enc-only-1',
        finishReason: 'stop',
        toolCalls: [],
      } as any,
      usage: {
        promptTokens: 1,
        completionTokens: 2,
        totalTokens: 3,
      },
    });

    expect(payload.output).toEqual([
      {
        id: 'msg_chatcmpl_reasoning_only_reasoning',
        type: 'reasoning',
        status: 'completed',
        encrypted_content: 'enc-only-1',
        summary: [],
      },
    ]);
  });

  it('preserves image generation mime_type on synthesized response payloads', () => {
    const payload = serializeResponsesFinalPayload({
      upstreamPayload: {
        id: 'resp_like_mime_1',
        model: 'gpt-5',
        output: [
          {
            id: 'img_1',
            type: 'image_generation_call',
            status: 'completed',
            result: 'data:image/png;base64,final',
            mime_type: 'image/png',
            output_format: 'png',
          },
        ],
      },
      normalized: {
        id: 'resp_like_mime_1',
        model: 'gpt-5',
        created: 1700000000,
        content: '',
        reasoningContent: '',
        finishReason: 'stop',
        toolCalls: [],
      },
      usage: {
        promptTokens: 1,
        completionTokens: 2,
        totalTokens: 3,
      },
    });

    expect(payload.output).toEqual([
      {
        id: 'img_1',
        type: 'image_generation_call',
        status: 'completed',
        result: 'data:image/png;base64,final',
        mime_type: 'image/png',
        output_format: 'png',
        partial_images: [],
      },
    ]);
  });
});
