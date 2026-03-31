import { describe, expect, it } from 'vitest';

import {
  extractResponsesTerminalResponseId,
  isResponsesPreviousResponseNotFoundError,
  shouldInferResponsesPreviousResponseId,
  stripResponsesPreviousResponseId,
  withResponsesPreviousResponseId,
} from './continuation.js';

describe('responses continuation helpers', () => {
  it('infers previous_response_id only for tool-output follow-up turns that omit it', () => {
    expect(shouldInferResponsesPreviousResponseId({
      input: [{
        type: 'function_call_output',
        call_id: 'call_1',
        output: '{"ok":true}',
      }],
    }, 'resp_prev_1')).toBe(true);

    expect(shouldInferResponsesPreviousResponseId({
      previous_response_id: 'resp_existing',
      input: [{
        type: 'function_call_output',
        call_id: 'call_1',
        output: '{"ok":true}',
      }],
    }, 'resp_prev_1')).toBe(false);

    expect(shouldInferResponsesPreviousResponseId({
      input: [{
        type: 'message',
        role: 'user',
        content: [{ type: 'input_text', text: 'hello' }],
      }],
    }, 'resp_prev_1')).toBe(false);
  });

  it('adds and removes previous_response_id without mutating other fields', () => {
    const body = {
      model: 'gpt-5.4',
      input: [{
        type: 'function_call_output',
        call_id: 'call_1',
        output: '{"ok":true}',
      }],
    };

    const withPrevious = withResponsesPreviousResponseId(body, 'resp_prev_1');
    expect(withPrevious).toMatchObject({
      model: 'gpt-5.4',
      previous_response_id: 'resp_prev_1',
    });

    const stripped = stripResponsesPreviousResponseId(withPrevious);
    expect(stripped.removed).toBe(true);
    expect(stripped.body.previous_response_id).toBeUndefined();
    expect(stripped.body.input).toEqual(body.input);
  });

  it('detects previous_response_not_found from either raw text or structured payloads', () => {
    expect(isResponsesPreviousResponseNotFoundError({
      rawErrText: JSON.stringify({
        error: {
          code: 'previous_response_not_found',
          message: 'previous_response_not_found',
        },
      }),
    })).toBe(true);

    expect(isResponsesPreviousResponseNotFoundError({
      payload: {
        type: 'response.failed',
        response: {
          error: {
            message: 'Previous response id not found',
            type: 'invalid_request_error',
          },
        },
      },
    })).toBe(true);

    expect(isResponsesPreviousResponseNotFoundError({
      rawErrText: JSON.stringify({
        error: {
          code: 'rate_limit_exceeded',
          message: 'too many requests',
        },
      }),
    })).toBe(false);
  });

  it('extracts terminal response ids from responses payloads and websocket terminal events', () => {
    expect(extractResponsesTerminalResponseId({
      id: 'resp_1',
      object: 'response',
      status: 'completed',
    })).toBe('resp_1');

    expect(extractResponsesTerminalResponseId({
      type: 'response.failed',
      response: {
        id: 'resp_2',
        status: 'failed',
        error: {
          message: 'tool failed',
        },
      },
    })).toBe('resp_2');

    expect(extractResponsesTerminalResponseId({
      type: 'response.created',
      response: {
        id: 'resp_3',
        status: 'in_progress',
      },
    })).toBeNull();

    expect(extractResponsesTerminalResponseId({
      id: 'resp_in_progress',
      object: 'response',
      status: 'in_progress',
    })).toBeNull();
  });
});
