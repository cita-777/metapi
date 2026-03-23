import { describe, expect, it } from 'vitest';

import {
  canonicalRequestFromOpenAiBody,
  canonicalRequestToOpenAiChatBody,
  createCanonicalRequestEnvelope,
} from './request.js';

describe('canonical request helpers', () => {
  it('normalizes a count_tokens request without provider-owned fields', () => {
    const request = createCanonicalRequestEnvelope({
      operation: 'count_tokens',
      surface: 'anthropic-messages',
      cliProfile: 'claude_code',
      requestedModel: ' claude-sonnet-4-5 ',
      stream: false,
      continuation: {
        sessionId: '  session-1  ',
        promptCacheKey: '  cache-1  ',
      },
    });

    expect(request).toEqual({
      operation: 'count_tokens',
      surface: 'anthropic-messages',
      cliProfile: 'claude_code',
      requestedModel: 'claude-sonnet-4-5',
      stream: false,
      messages: [],
      continuation: {
        sessionId: 'session-1',
        promptCacheKey: 'cache-1',
      },
    });
  });

  it('defaults generate requests to generic profile and empty collections', () => {
    const request = createCanonicalRequestEnvelope({
      requestedModel: 'gpt-5.2-codex',
      surface: 'openai-responses',
    });

    expect(request).toEqual({
      operation: 'generate',
      surface: 'openai-responses',
      cliProfile: 'generic',
      requestedModel: 'gpt-5.2-codex',
      stream: false,
      messages: [],
    });
  });

  it('parses metadata and explicit function tool choice from OpenAI-compatible bodies', () => {
    const request = canonicalRequestFromOpenAiBody({
      body: {
        model: 'gpt-5',
        stream: true,
        metadata: { user_id: 'user-1' },
        tools: [{
          type: 'function',
          function: {
            name: 'Glob',
            description: 'Search files',
            strict: true,
            parameters: {
              type: 'object',
              properties: {
                pattern: { type: 'string' },
              },
            },
          },
        }],
        tool_choice: {
          type: 'function',
          function: {
            name: 'Glob',
          },
        },
        messages: [{ role: 'user', content: 'hello' }],
      },
      surface: 'openai-chat',
    });

    expect(request).toMatchObject({
      requestedModel: 'gpt-5',
      stream: true,
      metadata: { user_id: 'user-1' },
      tools: [{
        name: 'Glob',
        description: 'Search files',
        strict: true,
        inputSchema: {
          type: 'object',
          properties: {
            pattern: { type: 'string' },
          },
        },
      }],
      toolChoice: {
        type: 'tool',
        name: 'Glob',
      },
    });
  });

  it('parses anthropic-shaped tools from compatibility bodies', () => {
    const request = canonicalRequestFromOpenAiBody({
      body: {
        model: 'gpt-5',
        tools: [{
          name: 'Glob',
          description: 'Search files',
          input_schema: {
            type: 'object',
            properties: {
              pattern: { type: 'string' },
            },
          },
        }],
        tool_choice: {
          type: 'tool',
          name: 'Glob',
        },
        messages: [{ role: 'user', content: 'hello' }],
      },
      surface: 'openai-chat',
    });

    expect(request.tools).toEqual([{
      name: 'Glob',
      description: 'Search files',
      inputSchema: {
        type: 'object',
        properties: {
          pattern: { type: 'string' },
        },
      },
    }]);
    expect(request.toolChoice).toEqual({
      type: 'tool',
      name: 'Glob',
    });
  });

  it('builds metadata back into OpenAI chat requests', () => {
    const body = canonicalRequestToOpenAiChatBody({
      operation: 'generate',
      surface: 'openai-chat',
      cliProfile: 'generic',
      requestedModel: 'gpt-5',
      stream: false,
      messages: [{ role: 'user', parts: [{ type: 'text', text: 'hello' }] }],
      metadata: { user_id: 'user-1' },
      toolChoice: {
        type: 'tool',
        name: 'Glob',
      },
      tools: [{
        name: 'Glob',
        strict: true,
        inputSchema: {
          type: 'object',
          properties: {
            pattern: { type: 'string' },
          },
        },
      }],
    });

    expect(body).toMatchObject({
      model: 'gpt-5',
      metadata: { user_id: 'user-1' },
      tool_choice: {
        type: 'function',
        function: {
          name: 'Glob',
        },
      },
      tools: [{
        type: 'function',
        function: {
          name: 'Glob',
          strict: true,
          parameters: {
            type: 'object',
            properties: {
              pattern: { type: 'string' },
            },
          },
        },
      }],
    });
  });

  it('round-trips include continuity metadata back into OpenAI-compatible bodies', () => {
    const request = canonicalRequestFromOpenAiBody({
      body: {
        model: 'gpt-5',
        stream: true,
        include: ['reasoning.encrypted_content', 'message.input_image.image_url'],
        reasoning: {
          effort: 'high',
        },
        messages: [{ role: 'user', content: 'hello' }],
      },
      surface: 'openai-responses',
    });

    const body = canonicalRequestToOpenAiChatBody(request);

    expect(body).toMatchObject({
      model: 'gpt-5',
      reasoning_effort: 'high',
      include: ['reasoning.encrypted_content', 'message.input_image.image_url'],
    });
  });

  it('preserves extra fields on tool-shaped raw tool_choice objects', () => {
    const request = canonicalRequestFromOpenAiBody({
      body: {
        model: 'gpt-5',
        tool_choice: {
          type: 'tool',
          name: 'browser',
          mode: 'required',
          disable_parallel_tool_use: true,
        },
        messages: [{ role: 'user', content: 'hello' }],
      },
      surface: 'openai-responses',
    });

    const body = canonicalRequestToOpenAiChatBody(request);

    expect(body.tool_choice).toEqual({
      type: 'tool',
      name: 'browser',
      mode: 'required',
      disable_parallel_tool_use: true,
    });
  });

  it('preserves structured tool outputs and top-level attachments through canonical round-trips', () => {
    const request = createCanonicalRequestEnvelope({
      requestedModel: 'gpt-5',
      surface: 'openai-chat',
      attachments: [{
        kind: 'file',
        fileId: 'file-top-level',
      }],
      messages: [{
        role: 'tool',
        parts: [{
          type: 'tool_result',
          toolCallId: 'call_1',
          resultContent: [
            { type: 'text', text: 'tool result' },
            { type: 'image_url', image_url: { url: 'https://example.com/tool.png' } },
          ],
        } as any],
      }],
    });

    const body = canonicalRequestToOpenAiChatBody(request);

    expect(body.attachments).toEqual([{
      kind: 'file',
      fileId: 'file-top-level',
    }]);
    expect(body.messages).toEqual([{
      role: 'tool',
      tool_call_id: 'call_1',
      content: [
        { type: 'text', text: 'tool result' },
        { type: 'image_url', image_url: { url: 'https://example.com/tool.png' } },
      ],
    }]);
  });

  it('preserves richer Responses tools, raw tool_choice, assistant phase, and reasoning signatures through canonical round-trips', () => {
    const request = canonicalRequestFromOpenAiBody({
      body: {
        model: 'gpt-5',
        parallel_tool_calls: false,
        tools: [
          {
            type: 'custom',
            name: 'browser',
            description: 'browse the web',
            format: { type: 'text' },
          },
          {
            type: 'image_generation',
            background: 'transparent',
          },
        ],
        tool_choice: {
          type: 'allowed_tools',
          mode: 'auto',
          tools: [{ type: 'custom', name: 'browser' }],
        },
        messages: [
          {
            role: 'assistant',
            phase: 'analysis',
            reasoning_signature: 'sig_123',
            content: 'thinking',
          },
          {
            role: 'user',
            content: 'hello',
          },
        ],
      },
      surface: 'openai-responses',
    });

    const body = canonicalRequestToOpenAiChatBody(request);

    expect(body.parallel_tool_calls).toBe(false);
    expect(body.tools).toEqual([
      {
        type: 'custom',
        name: 'browser',
        description: 'browse the web',
        format: { type: 'text' },
      },
      {
        type: 'image_generation',
        background: 'transparent',
      },
    ]);
    expect(body.tool_choice).toEqual({
      type: 'allowed_tools',
      mode: 'auto',
      tools: [{ type: 'custom', name: 'browser' }],
    });
    expect(body.messages).toMatchObject([
      {
        role: 'assistant',
        phase: 'analysis',
        reasoning_signature: 'sig_123',
        content: 'thinking',
      },
      {
        role: 'user',
        content: 'hello',
      },
    ]);
  });

  it('writes raw canonical tool types back into OpenAI-compatible bodies when the raw payload omits the discriminator', () => {
    const request = createCanonicalRequestEnvelope({
      requestedModel: 'gpt-5',
      surface: 'openai-responses',
      tools: [{
        type: 'custom',
        raw: {
          name: 'browser',
          description: 'browse the web',
          format: { type: 'text' },
        },
      }],
    });

    const body = canonicalRequestToOpenAiChatBody(request);

    expect(body.tools).toEqual([{
      type: 'custom',
      name: 'browser',
      description: 'browse the web',
      format: { type: 'text' },
    }]);
  });
});
