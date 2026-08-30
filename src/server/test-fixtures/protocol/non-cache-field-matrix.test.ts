import { describe, expect, it } from 'vitest';

import { convertOpenAiBodyToResponsesBody } from '../../transformers/openai/responses/conversion.js';
import {
  convertAnthropicToolsToOpenAi,
  convertOpenAiBodyToAnthropicMessagesBody,
  convertOpenAiToolsToAnthropic,
} from '../../transformers/anthropic/messages/conversion.js';
import { convertClaudeRequestToOpenAiBody } from '../../transformers/shared/chatFormatsCore.js';
import { validateExternalResponsesHttpRequest } from '../../proxy-core/responsesPreflight.js';
import { applyOpenAiServiceTierPolicy } from '../../proxy-core/serviceTierPolicy.js';

describe('non-cache cross-protocol field matrix', () => {
  it('audits web_search, legacy functions/function_call, continuation diagnostics, function outputs and service_tier', () => {
    const legacyChatToResponses = convertOpenAiBodyToResponsesBody(
      {
        model: 'gpt-5',
        messages: [
          { role: 'user', content: 'hello' },
          { role: 'function', name: 'legacy_tool', content: 'done' },
        ],
        functions: [{ name: 'legacy_tool', parameters: { type: 'object' } }],
        function_call: { name: 'legacy_tool' },
      },
      'gpt-5',
      false,
    );
    expect(legacyChatToResponses).toMatchObject({
      tools: [{ type: 'function', name: 'legacy_tool' }],
      tool_choice: { type: 'function', name: 'legacy_tool' },
    });
    expect((legacyChatToResponses.input as any[]).some((item) => item.type === 'function_call_output')).toBe(true);

    expect(convertOpenAiToolsToAnthropic([
      { type: 'web_search' },
      { type: 'google_search' },
    ])).toEqual([
      { type: 'web_search_20250305', name: 'web_search' },
      { type: 'web_search_20250305', name: 'web_search' },
    ]);
    expect(convertAnthropicToolsToOpenAi([
      { type: 'web_search_20250305' },
    ])).toEqual([
      { type: 'web_search', name: 'web_search' },
    ]);

    const claudeToChat = convertClaudeRequestToOpenAiBody({
      model: 'claude-opus',
      max_tokens: 256,
      tools: [{ type: 'web_search_20250305' }],
      messages: [{ role: 'user', content: 'search' }],
    });
    expect(claudeToChat.payload.tools).toEqual([{ type: 'web_search', name: 'web_search' }]);

    const openAiToClaude = convertOpenAiBodyToAnthropicMessagesBody(
      {
        model: 'gpt-5',
        messages: [{ role: 'user', content: 'search' }],
        tools: [{ type: 'web_search' }],
      },
      'claude-opus',
      false,
    );
    expect(openAiToClaude.tools).toEqual([{ type: 'web_search_20250305', name: 'web_search' }]);

    const previousResponseDiagnostic = validateExternalResponsesHttpRequest({
      model: 'gpt-5',
      previous_response_id: 'msg_wrong',
      input: 'hello',
    });
    expect(previousResponseDiagnostic.ok).toBe(false);
    if (!previousResponseDiagnostic.ok) {
      expect(previousResponseDiagnostic.payload.error.message).toContain('msg_*');
    }

    const functionOutputDiagnostic = validateExternalResponsesHttpRequest({
      model: 'gpt-5',
      input: [{ type: 'function_call_output', call_id: 'call_missing', output: 'done' }],
    });
    expect(functionOutputDiagnostic.ok).toBe(false);
    if (!functionOutputDiagnostic.ok) {
      expect(functionOutputDiagnostic.payload.error.message).toContain('Responses WebSocket v2');
    }

    expect(applyOpenAiServiceTierPolicy({
      body: { model: 'gpt-5', service_tier: 'fast' },
    })).toMatchObject({
      ok: true,
      body: { model: 'gpt-5', service_tier: 'priority' },
    });
  });
});

