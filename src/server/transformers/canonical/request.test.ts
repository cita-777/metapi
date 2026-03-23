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
});
