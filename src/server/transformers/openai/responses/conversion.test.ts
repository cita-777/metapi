import { describe, expect, it } from 'vitest';

import {
  convertOpenAiBodyToResponsesBody,
  convertResponsesBodyToOpenAiBody,
  sanitizeResponsesBodyForProxy,
} from './conversion.js';
import {
  buildResponsesCompatibilityBodies,
  convertOpenAiBodyToResponsesBody as convertOpenAiBodyToResponsesBodyViaCompatibility,
  normalizeResponsesInputForCompatibility as normalizeResponsesInputForCompatibilityViaCompatibility,
  normalizeResponsesMessageContent as normalizeResponsesMessageContentViaCompatibility,
  sanitizeResponsesBodyForProxy as sanitizeResponsesBodyForProxyViaCompatibility,
} from './compatibility.js';
import {
  normalizeResponsesInputForCompatibility,
  normalizeResponsesMessageContent,
} from './conversion.js';

describe('responses conversion single source of truth', () => {
  it('exports shared conversion helpers from one implementation', () => {
    expect(normalizeResponsesInputForCompatibilityViaCompatibility).toBe(normalizeResponsesInputForCompatibility);
    expect(
      normalizeResponsesMessageContentViaCompatibility(
        [{ type: 'text', text: 'hello' }],
        'user',
      ),
    ).toEqual(
      normalizeResponsesMessageContent(
        'user',
        [{ type: 'text', text: 'hello' }],
      ),
    );
    expect(convertOpenAiBodyToResponsesBodyViaCompatibility).toBe(convertOpenAiBodyToResponsesBody);
    expect(sanitizeResponsesBodyForProxyViaCompatibility).toBe(sanitizeResponsesBodyForProxy);
  });

  it('preserves extra properties when normalizing role-only message items', () => {
    expect(normalizeResponsesInputForCompatibility([
      {
        role: 'assistant',
        content: 'done',
        id: 'msg_1',
        status: 'completed',
      },
    ])).toEqual([
      {
        type: 'message',
        role: 'assistant',
        content: [{ type: 'output_text', text: 'done' }],
        id: 'msg_1',
        status: 'completed',
      },
    ]);
  });

  it('filters whitespace-only string entries from normalized responses input arrays', () => {
    expect(normalizeResponsesInputForCompatibility([
      'hello',
      '   ',
      {
        role: 'user',
        content: 'world',
      },
    ])).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello' }],
      },
      {
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'world' }],
      },
    ]);
  });

  it('falls back to non-empty text and image sources when earlier compatibility fields are blank', () => {
    const normalized = normalizeResponsesInputForCompatibility([
      {
        role: 'assistant',
        content: '',
        text: 'done',
      },
      {
        role: 'user',
        content: [
          { type: 'text', text: '   ', content: 'hello' },
          { type: 'image_url', image_url: '   ', url: 'https://example.com/image.png' },
        ],
      },
    ]);

    expect(normalized).toEqual([
      expect.objectContaining({
        type: 'message',
        role: 'assistant',
        text: 'done',
        content: [{ type: 'output_text', text: 'done' }],
      }),
      expect.objectContaining({
        type: 'message',
        role: 'user',
        content: [
          expect.objectContaining({
            type: 'input_text',
            text: 'hello',
            content: 'hello',
          }),
          expect.objectContaining({
            type: 'input_image',
            image_url: 'https://example.com/image.png',
            url: 'https://example.com/image.png',
          }),
        ],
      }),
    ]);
  });
});

describe('sanitizeResponsesBodyForProxy', () => {
  it('preserves newer Responses request fields needed by the proxy', () => {
    const result = sanitizeResponsesBodyForProxy(
      {
        model: 'gpt-5',
        input: 'hello',
        safety_identifier: 'safe-user-1',
        max_tool_calls: 3,
        prompt_cache_key: 'cache-key',
        prompt_cache_retention: { scope: 'session' },
        stream_options: { include_obfuscation: true },
        background: true,
        text: { format: { type: 'text' }, verbosity: 'high' },
        top_logprobs: 2,
      },
      'gpt-5',
      true,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      stream: true,
      safety_identifier: 'safe-user-1',
      max_tool_calls: 3,
      prompt_cache_key: 'cache-key',
      prompt_cache_retention: { scope: 'session' },
      stream_options: { include_obfuscation: true },
      background: true,
      text: { format: { type: 'text' }, verbosity: 'high' },
      top_logprobs: 2,
    });
  });

  it('normalizes current Responses inbound parity fields', () => {
    const result = sanitizeResponsesBodyForProxy(
      {
        input: 'hello',
        safety_identifier: '  safe-user-4  ',
        max_tool_calls: '5',
        prompt_cache_key: '  cache-key-2 ',
        prompt_cache_retention: ' 24h ',
        stream_options: { include_obfuscation: 'true', extra: 'keep-me' },
        background: 'false',
        text: { format: { type: 'text' }, verbosity: ' high ' },
        truncation: ' auto ',
        previous_response_id: ' resp_prev_2 ',
        include: [' reasoning.encrypted_content ', '', 123, 'message.input_image.image_url'],
        top_logprobs: '7',
        user: '  user-456 ',
        service_tier: ' priority ',
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      stream: false,
      safety_identifier: 'safe-user-4',
      max_tool_calls: 5,
      prompt_cache_key: 'cache-key-2',
      prompt_cache_retention: '24h',
      stream_options: { include_obfuscation: true, extra: 'keep-me' },
      background: false,
      text: { format: { type: 'text' }, verbosity: 'high' },
      truncation: 'auto',
      previous_response_id: 'resp_prev_2',
      include: ['reasoning.encrypted_content', 'message.input_image.image_url'],
      top_logprobs: 7,
      user: 'user-456',
      service_tier: 'priority',
    });
  });

  it('defaults encrypted reasoning include when reasoning is requested without an explicit include list on the codex responses surface', () => {
    const result = sanitizeResponsesBodyForProxy(
      {
        model: 'gpt-5',
        input: 'hello',
        reasoning: {
          effort: 'high',
          summary: 'auto',
        },
      },
      'gpt-5',
      false,
      { defaultEncryptedReasoningInclude: true },
    );

    expect(result).toMatchObject({
      include: ['reasoning.encrypted_content'],
      reasoning: {
        effort: 'high',
        summary: 'auto',
      },
    });
  });

  it('does not inject default include on generic responses requests when the codex surface default is disabled', () => {
    const result = sanitizeResponsesBodyForProxy(
      {
        model: 'gpt-5',
        input: 'hello',
        reasoning: {
          effort: 'high',
          summary: 'auto',
        },
      },
      'gpt-5',
      false,
    );

    expect(result.include).toBeUndefined();
  });

  it('defaults encrypted reasoning include on codex responses requests even without explicit reasoning config', () => {
    const result = sanitizeResponsesBodyForProxy(
      {
        model: 'gpt-5',
        input: 'hello',
      },
      'gpt-5',
      false,
      { defaultEncryptedReasoningInclude: true },
    );

    expect(result).toMatchObject({
      include: ['reasoning.encrypted_content'],
    });
  });

  it('respects an explicit empty include list when the codex responses default is enabled', () => {
    const result = sanitizeResponsesBodyForProxy(
      {
        model: 'gpt-5',
        input: 'hello',
        reasoning: {
          effort: 'high',
          summary: 'auto',
        },
        include: [],
      },
      'gpt-5',
      false,
      { defaultEncryptedReasoningInclude: true },
    );

    expect(result).toMatchObject({
      include: [],
      reasoning: {
        effort: 'high',
        summary: 'auto',
      },
    });
  });

  it('respects an explicit custom include list when the codex responses default is enabled', () => {
    const result = sanitizeResponsesBodyForProxy(
      {
        model: 'gpt-5',
        input: 'hello',
        reasoning: {
          effort: 'high',
          summary: 'auto',
        },
        include: ['message.input_image.image_url'],
      },
      'gpt-5',
      false,
      { defaultEncryptedReasoningInclude: true },
    );

    expect(result).toMatchObject({
      include: ['message.input_image.image_url'],
      reasoning: {
        effort: 'high',
        summary: 'auto',
      },
    });
  });

  it('preserves unknown top-level fields while still normalizing known compatibility fields', () => {
    const result = sanitizeResponsesBodyForProxy(
      {
        model: 'gpt-5',
        input: 'hello',
        max_completion_tokens: 256,
        custom_vendor_flag: 'keep-me',
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      stream: false,
      custom_vendor_flag: 'keep-me',
      max_output_tokens: 256,
    });
    expect(result.max_completion_tokens).toBeUndefined();
  });
});

describe('convertOpenAiBodyToResponsesBody', () => {
  it('maps OpenAI chat file blocks into Responses input_file blocks', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'user',
            content: [
              {
                type: 'file',
                file: {
                  file_id: 'file-metapi-demo',
                },
              },
              {
                type: 'file',
                file: {
                  filename: 'notes.md',
                  file_data: Buffer.from('# hello').toString('base64'),
                },
              },
            ],
          },
        ],
      },
      'gpt-5',
      false,
    );

    expect(result.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          {
            type: 'input_file',
            file_id: 'file-metapi-demo',
          },
          {
            type: 'input_file',
            filename: 'notes.md',
            file_data: `data:text/markdown;base64,${Buffer.from('# hello').toString('base64')}`,
          },
        ],
      },
    ]);
  });

  it('maps extra request fields and preserves custom/image_generation tools', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [{ role: 'user', content: 'draw a cat' }],
        safety_identifier: 'safe-user-2',
        max_tool_calls: 2,
        prompt_cache_key: 'prompt-key',
        prompt_cache_retention: { scope: 'workspace' },
        stream_options: { include_obfuscation: true },
        background: false,
        verbosity: 'low',
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
            size: '1024x1024',
          },
        ],
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      stream: false,
      safety_identifier: 'safe-user-2',
      max_tool_calls: 2,
      prompt_cache_key: 'prompt-key',
      prompt_cache_retention: { scope: 'workspace' },
      stream_options: { include_obfuscation: true },
      background: false,
      text: { verbosity: 'low' },
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
          size: '1024x1024',
        },
      ],
    });
  });

  it('maps OpenAI response_format into Responses text.format while preserving verbosity', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [{ role: 'user', content: 'return structured data' }],
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'payload',
            schema: {
              type: 'object',
              properties: {
                name: { type: 'string' },
              },
              required: ['name'],
            },
          },
        },
        verbosity: 'high',
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      text: {
        format: {
          type: 'json_schema',
          json_schema: {
            name: 'payload',
            schema: {
              type: 'object',
              properties: {
                name: { type: 'string' },
              },
              required: ['name'],
            },
          },
        },
        verbosity: 'high',
      },
    });
  });

  it('normalizes and preserves field parity when converting from OpenAI-compatible input', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [{ role: 'user', content: 'hello' }],
        safety_identifier: '  safe-user-5 ',
        max_tool_calls: '6',
        prompt_cache_key: '  cache-key-3 ',
        prompt_cache_retention: ' in-memory ',
        stream_options: { include_obfuscation: 'false' },
        background: 'true',
        verbosity: ' medium ',
        truncation: ' disabled ',
        previous_response_id: ' resp_prev_3 ',
        include: 'reasoning.encrypted_content',
        top_logprobs: '4',
        user: ' user-789 ',
        service_tier: ' flex ',
      },
      'gpt-5',
      true,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      stream: true,
      safety_identifier: 'safe-user-5',
      max_tool_calls: 6,
      prompt_cache_key: 'cache-key-3',
      prompt_cache_retention: 'in-memory',
      stream_options: { include_obfuscation: false },
      background: true,
      text: { verbosity: 'medium' },
      truncation: 'disabled',
      previous_response_id: 'resp_prev_3',
      include: ['reasoning.encrypted_content'],
      top_logprobs: 4,
      user: 'user-789',
      service_tier: 'flex',
    });
  });

  it('does not inject default include when converting non-responses OpenAI input into Responses bodies', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [{ role: 'user', content: 'hello' }],
      },
      'gpt-5',
      true,
    );

    expect(result.include).toBeUndefined();
  });

  it('maps OpenAI file-style content blocks into inline-only Responses input_file blocks', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'summarize this file' },
              {
                type: 'file',
                file_id: 'file_local_123',
                filename: 'report.pdf',
                mime_type: 'application/pdf',
                file_data: 'JVBERi0xLjQK',
              },
            ],
          },
        ],
      },
      'gpt-5',
      false,
    );

    expect(result.input).toEqual([
      {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'summarize this file' },
          {
            type: 'input_file',
            filename: 'report.pdf',
            file_data: 'data:application/pdf;base64,JVBERi0xLjQK',
          },
        ],
      },
    ]);
  });

  it('shortens long MCP tool names consistently across tools, tool_choice and assistant tool calls', () => {
    const sharedSuffix = 'server__execute_super_long_nested_tool_name_that_needs_shortening';
    const firstName = `mcp__alpha_workspace__${sharedSuffix}`;
    const secondName = `mcp__beta_workspace__${sharedSuffix}`;

    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'assistant',
            tool_calls: [
              {
                id: 'call_1',
                type: 'function',
                function: {
                  name: firstName,
                  arguments: '{"city":"shanghai"}',
                },
              },
            ],
          },
          {
            role: 'tool',
            tool_call_id: 'call_1',
            content: 'done',
          },
        ],
        tools: [
          {
            type: 'function',
            function: {
              name: firstName,
              parameters: { type: 'object' },
            },
          },
          {
            type: 'function',
            function: {
              name: secondName,
              parameters: { type: 'object' },
            },
          },
        ],
        tool_choice: {
          type: 'function',
          function: {
            name: secondName,
          },
        },
      },
      'gpt-5',
      false,
    );

    const toolNames = Array.isArray(result.tools)
      ? result.tools.map((tool: any) => tool.name)
      : [];
    const assistantCall = Array.isArray(result.input)
      ? result.input.find((item: any) => item.type === 'function_call')
      : null;

    expect(toolNames).toHaveLength(2);
    expect(toolNames[0].length).toBeLessThanOrEqual(64);
    expect(toolNames[1].length).toBeLessThanOrEqual(64);
    expect(toolNames[0].startsWith('mcp__')).toBe(true);
    expect(toolNames[1].startsWith('mcp__')).toBe(true);
    expect(toolNames[0]).not.toBe(toolNames[1]);
    expect(result.tool_choice).toEqual({
      type: 'function',
      name: toolNames[1],
    });
    expect(assistantCall).toMatchObject({
      type: 'function_call',
      name: toolNames[0],
    });
  });
});

describe('convertResponsesBodyToOpenAiBody', () => {
  it('maps Responses input_file blocks back into OpenAI chat file blocks', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_file', file_id: 'file-metapi-demo' },
              {
                type: 'input_file',
                filename: 'paper.pdf',
                file_data: Buffer.from('%PDF-demo').toString('base64'),
              },
            ],
          },
        ],
      },
      'gpt-5',
      false,
    );

    expect(result.messages).toEqual([
      {
        role: 'user',
        content: [
          {
            type: 'file',
            file: {
              file_id: 'file-metapi-demo',
            },
          },
          {
            type: 'file',
            file: {
              filename: 'paper.pdf',
              file_data: Buffer.from('%PDF-demo').toString('base64'),
            },
          },
        ],
      },
    ]);
  });

  it('preserves richer Responses request fields back onto the OpenAI-compatible body', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: 'hello' }] }],
        safety_identifier: 'safe-user-3',
        max_tool_calls: 4,
        prompt_cache_key: 'prompt-key-2',
        prompt_cache_retention: { scope: 'project' },
        stream_options: { include_obfuscation: true },
        background: true,
        text: { format: { type: 'json_object' }, verbosity: 'high' },
        tools: [
          {
            type: 'custom',
            name: 'browser',
            format: { type: 'grammar', syntax: 'lark' },
          },
          {
            type: 'image_generation',
            background: 'transparent',
            partial_images: 2,
            output_format: 'png',
          },
        ],
      },
      'gpt-5',
      true,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      stream: true,
      safety_identifier: 'safe-user-3',
      max_tool_calls: 4,
      prompt_cache_key: 'prompt-key-2',
      prompt_cache_retention: { scope: 'project' },
      stream_options: { include_obfuscation: true },
      background: true,
      verbosity: 'high',
      tools: [
        {
          type: 'custom',
          name: 'browser',
          format: { type: 'grammar', syntax: 'lark' },
        },
        {
          type: 'image_generation',
          background: 'transparent',
          partial_images: 2,
          output_format: 'png',
        },
      ],
    });
  });

  it('converts custom tool calls and outputs into OpenAI-compatible tool messages', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: [
          {
            type: 'custom_tool_call',
            id: 'ct_1',
            call_id: 'ct_1',
            name: 'browser',
            input: 'open example.com',
          },
          {
            type: 'custom_tool_call_output',
            call_id: 'ct_1',
            output: 'done',
          },
        ],
      },
      'gpt-5',
      false,
    );

    expect(result.messages).toEqual([
      {
        role: 'assistant',
        content: '',
        tool_calls: [
          {
            id: 'ct_1',
            type: 'function',
            function: {
              name: 'browser',
              arguments: 'open example.com',
            },
          },
        ],
      },
      {
        role: 'tool',
        tool_call_id: 'ct_1',
        content: 'done',
      },
    ]);
  });

  it('converts reasoning items back into assistant content instead of dropping them', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: [
          {
            type: 'reasoning',
            id: 'rs_1',
            status: 'completed',
            encrypted_content: 'enc_sig_1',
            summary: [
              { type: 'summary_text', text: 'Think step by step' },
            ],
          },
        ],
      },
      'gpt-5',
      false,
    );

    expect(result.messages).toEqual([
      {
        role: 'assistant',
        content: [
          {
            type: 'text',
            text: 'Think step by step',
          },
        ],
        reasoning_signature: 'enc_sig_1',
      },
    ]);
  });

  it('preserves remaining request fields needed for OpenAI-compatible downstream fallback', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        user: 'user-123',
        include: ['reasoning.encrypted_content'],
        previous_response_id: 'resp_prev',
        truncation: 'auto',
        service_tier: 'priority',
        top_logprobs: 4,
        reasoning: {
          effort: 'high',
          summary: 'auto',
        },
      },
      'gpt-5',
      true,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      stream: true,
      user: 'user-123',
      include: ['reasoning.encrypted_content'],
      previous_response_id: 'resp_prev',
      truncation: 'auto',
      service_tier: 'priority',
      top_logprobs: 4,
      reasoning: {
        effort: 'high',
        summary: 'auto',
      },
    });
  });

  it('does not inject default include for generic OpenAI-compatible fallback when reasoning options are present', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        reasoning: {
          effort: 'high',
        },
      },
      'gpt-5',
      true,
    );

    expect(result.include).toBeUndefined();
  });

  it('adds encrypted reasoning include for OpenAI-compatible fallback when the codex surface default is enabled', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        reasoning: {
          effort: 'high',
        },
      },
      'gpt-5',
      true,
      { defaultEncryptedReasoningInclude: true },
    );

    expect(result).toMatchObject({
      include: ['reasoning.encrypted_content'],
      reasoning: {
        effort: 'high',
      },
    });
  });

  it('does not inject default include for generic OpenAI-compatible fallback when responses input omits include and reasoning', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
      },
      'gpt-5',
      true,
    );

    expect(result.include).toBeUndefined();
  });

  it('adds encrypted reasoning include for OpenAI-compatible fallback when the codex surface default is enabled even without explicit reasoning config', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
      },
      'gpt-5',
      true,
      { defaultEncryptedReasoningInclude: true },
    );

    expect(result).toMatchObject({
      include: ['reasoning.encrypted_content'],
    });
  });

  it('respects an explicit empty include list for OpenAI-compatible fallback when the codex surface default is enabled', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        reasoning: {
          effort: 'high',
        },
        include: [],
      },
      'gpt-5',
      true,
      { defaultEncryptedReasoningInclude: true },
    );

    expect(result).toMatchObject({
      include: [],
      reasoning: {
        effort: 'high',
      },
    });
  });

  it('respects an explicit custom include list for OpenAI-compatible fallback when the codex surface default is enabled', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        reasoning: {
          effort: 'high',
        },
        include: ['message.input_image.image_url'],
      },
      'gpt-5',
      true,
      { defaultEncryptedReasoningInclude: true },
    );

    expect(result).toMatchObject({
      include: ['message.input_image.image_url'],
      reasoning: {
        effort: 'high',
      },
    });
  });

  it('keeps Responses input_file items when converting back to OpenAI-compatible bodies without conflicting file ids', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'analyze this upload' },
              {
                type: 'input_file',
                file_id: 'file_local_456',
                filename: 'notes.md',
                mime_type: 'text/markdown',
                file_data: 'IyBoZWxsbwo=',
              },
            ],
          },
        ],
      },
      'gpt-5',
      false,
    );

    expect(result.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'analyze this upload' },
          {
            type: 'file',
            file: {
              filename: 'notes.md',
              mime_type: 'text/markdown',
              file_data: 'IyBoZWxsbwo=',
            },
          },
        ],
      },
    ]);
  });

  it('keeps Responses input_file file_url items when converting back to OpenAI-compatible bodies', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              { type: 'input_text', text: 'read this remote file' },
              {
                type: 'input_file',
                filename: 'remote.pdf',
                file_url: 'https://example.com/remote.pdf',
              },
            ],
          },
        ],
      },
      'gpt-5',
      false,
    );

    expect(result.messages).toEqual([
      {
        role: 'user',
        content: [
          { type: 'text', text: 'read this remote file' },
          {
            type: 'file',
            file: {
              filename: 'remote.pdf',
              file_url: 'https://example.com/remote.pdf',
            },
          },
        ],
      },
    ]);
  });

  it('keeps richer field parity on compatibility retry bodies when metadata is absent', () => {
    const candidates = buildResponsesCompatibilityBodies({
      model: 'gpt-5',
      input: 'hello',
      stream: true,
      parallel_tool_calls: true,
      include: ['reasoning.encrypted_content'],
      reasoning: {
        effort: 'high',
        summary: 'auto',
      },
      safety_identifier: 'safe-user-9',
      max_tool_calls: 3,
      prompt_cache_key: 'cache-key-9',
      prompt_cache_retention: { scope: 'workspace' },
      background: true,
      top_logprobs: 2,
      previous_response_id: 'resp_prev_9',
      truncation: 'auto',
      service_tier: 'priority',
      text: {
        verbosity: 'high',
      },
    });

    expect(candidates).toContainEqual({
      model: 'gpt-5',
      input: 'hello',
      stream: true,
      parallel_tool_calls: true,
      include: ['reasoning.encrypted_content'],
      reasoning: {
        effort: 'high',
        summary: 'auto',
      },
      safety_identifier: 'safe-user-9',
      max_tool_calls: 3,
      prompt_cache_key: 'cache-key-9',
      prompt_cache_retention: { scope: 'workspace' },
      background: true,
      top_logprobs: 2,
      previous_response_id: 'resp_prev_9',
      truncation: 'auto',
      service_tier: 'priority',
      text: {
        verbosity: 'high',
      },
    });
  });

  it('preserves tools and tool_choice across all compatibility retry bodies', () => {
    const candidates = buildResponsesCompatibilityBodies({
      model: 'gpt-5',
      input: 'hello',
      stream: true,
      metadata: { user_id: 'user-1' },
      instructions: 'be helpful',
      tools: [{
        type: 'function',
        function: {
          name: 'lookup_weather',
          parameters: {
            type: 'object',
            properties: {
              city: { type: 'string' },
            },
          },
        },
      }],
      tool_choice: {
        type: 'function',
        function: {
          name: 'lookup_weather',
        },
      },
    });

    expect(candidates.length).toBeGreaterThan(0);
    for (const candidate of candidates) {
      expect(candidate.tools).toEqual([{
        type: 'function',
        function: {
          name: 'lookup_weather',
          parameters: {
            type: 'object',
            properties: {
              city: { type: 'string' },
            },
          },
        },
      }]);
      expect(candidate.tool_choice).toEqual({
        type: 'function',
        function: {
          name: 'lookup_weather',
        },
      });
    }
  });

  it('maps native tool choices and strict function tools into OpenAI-compatible fallback bodies', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        tools: [{
          type: 'function',
          name: 'lookup_weather',
          parameters: {
            type: 'object',
            properties: {
              city: { type: 'string' },
            },
          },
          strict: true,
        }],
        tool_choice: {
          type: 'tool',
          name: 'lookup_weather',
        },
      },
      'gpt-5',
      false,
    );

    expect(result.tools).toEqual([{
      type: 'function',
      function: {
        name: 'lookup_weather',
        parameters: {
          type: 'object',
          properties: {
            city: { type: 'string' },
          },
        },
        strict: true,
      },
    }]);
    expect(result.tool_choice).toEqual({
      type: 'function',
      function: {
        name: 'lookup_weather',
      },
    });
  });

  it('derives Responses reasoning config from chat-style reasoning request fields', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [{ role: 'user', content: 'hello' }],
        reasoning_effort: 'high',
        reasoning_budget: 2048,
        reasoning_summary: 'detailed',
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      reasoning: {
        effort: 'high',
        budget_tokens: 2048,
        summary: 'detailed',
      },
    });
  });

  it('preserves assistant reasoning history when converting OpenAI-compatible bodies to Responses input', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [{
          role: 'assistant',
          content: '',
          reasoning_content: 'plan quietly',
          reasoning_signature: 'sig_1',
          tool_calls: [{
            id: 'call_1',
            type: 'function',
            function: {
              name: 'Glob',
              arguments: '{"pattern":"README*"}',
            },
          }],
        }],
      },
      'gpt-5',
      false,
    );

    expect(result.input).toEqual([
      {
        type: 'reasoning',
        summary: [{
          type: 'summary_text',
          text: 'plan quietly',
        }],
        encrypted_content: 'sig_1',
      },
      {
        type: 'function_call',
        call_id: 'call_1',
        name: 'Glob',
        arguments: '{"pattern":"README*"}',
      },
    ]);
  });

  it('preserves chat-native modalities and audio settings when converting to Responses bodies', () => {
    const result = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [{ role: 'user', content: 'hello' }],
        metadata: { user_id: 'user-1' },
        modalities: ['text', 'audio'],
        audio: {
          voice: 'alloy',
          format: 'mp3',
        },
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      metadata: { user_id: 'user-1' },
      modalities: ['text', 'audio'],
      audio: {
        voice: 'alloy',
        format: 'mp3',
      },
    });
  });

  it('preserves metadata, modalities, and audio when converting Responses bodies back to OpenAI-compatible bodies', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        metadata: { user_id: 'user-1' },
        modalities: ['text', 'audio'],
        audio: {
          voice: 'alloy',
          format: 'mp3',
        },
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      metadata: { user_id: 'user-1' },
      modalities: ['text', 'audio'],
      audio: {
        voice: 'alloy',
        format: 'mp3',
      },
    });
  });

  it('maps Responses text.format back into OpenAI response_format', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        text: {
          format: {
            type: 'json_schema',
            json_schema: {
              name: 'payload',
              schema: {
                type: 'object',
                properties: {
                  value: { type: 'string' },
                },
              },
            },
          },
          verbosity: 'medium',
        },
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      response_format: {
        type: 'json_schema',
        json_schema: {
          name: 'payload',
          schema: {
            type: 'object',
            properties: {
              value: { type: 'string' },
            },
          },
        },
      },
      verbosity: 'medium',
    });
  });

  it('preserves responses metadata when converting back to OpenAI-compatible bodies', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        metadata: {
          user_id: 'user-1',
        },
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      metadata: {
        user_id: 'user-1',
      },
    });
  });

  it('normalizes field parity when converting Responses input back to OpenAI-compatible input', () => {
    const result = convertResponsesBodyToOpenAiBody(
      {
        model: 'gpt-5',
        input: 'hello',
        safety_identifier: '  safe-user-6 ',
        max_tool_calls: '8',
        prompt_cache_key: '  cache-key-4 ',
        prompt_cache_retention: ' 24h ',
        stream_options: { include_obfuscation: 'true' },
        background: 'false',
        text: { verbosity: ' low ' },
        truncation: ' auto ',
        previous_response_id: ' resp_prev_4 ',
        include: [' reasoning.encrypted_content ', ''],
        top_logprobs: '9',
        user: ' user-999 ',
        service_tier: ' default ',
      },
      'gpt-5',
      false,
    );

    expect(result).toMatchObject({
      model: 'gpt-5',
      stream: false,
      safety_identifier: 'safe-user-6',
      max_tool_calls: 8,
      prompt_cache_key: 'cache-key-4',
      prompt_cache_retention: '24h',
      stream_options: { include_obfuscation: true },
      background: false,
      verbosity: 'low',
      truncation: 'auto',
      previous_response_id: 'resp_prev_4',
      include: ['reasoning.encrypted_content'],
      top_logprobs: 9,
      user: 'user-999',
      service_tier: 'default',
    });
  });
});
