import { parseDownstreamChatRequest, type ParsedDownstreamChatRequest } from '../../shared/normalized.js';
import { createProtocolRequestEnvelope, type ProtocolRequestEnvelope } from '../../shared/protocolModel.js';
import { validateAnthropicMessagesBody } from './conversion.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toPositiveInteger(value: unknown): number {
  const numberValue = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numberValue) || numberValue <= 0) return 0;
  return Math.trunc(numberValue);
}

function invalidRequest(message: string): { statusCode: number; payload: unknown } {
  return {
    statusCode: 400,
    payload: {
      error: {
        message,
        type: 'invalid_request_error',
      },
    },
  };
}

function validateMaxTokens(body: Record<string, unknown>): { statusCode: number; payload: unknown } | undefined {
  const maxTokens = toPositiveInteger(body.max_tokens ?? body.maxTokens);
  if (maxTokens > 0) return undefined;
  return invalidRequest('max_tokens is required and must be positive');
}

function validateSystemPrompts(body: Record<string, unknown>): { statusCode: number; payload: unknown } | undefined {
  const system = body.system;
  if (system === undefined || system === null || typeof system === 'string') return undefined;
  if (!Array.isArray(system)) return undefined;

  for (const entry of system) {
    if (typeof entry === 'string') continue;
    if (!isRecord(entry)) {
      return invalidRequest('system prompt must be text');
    }

    const type = asTrimmedString(entry.type).toLowerCase();
    if (type && type !== 'text') {
      return invalidRequest('system prompt must be text');
    }
  }

  return undefined;
}

function sanitizeAnthropicInboundBody(
  body: Record<string, unknown>,
): { sanitizedBody?: Record<string, unknown>; error?: { statusCode: number; payload: unknown } } {
  const maxTokensError = validateMaxTokens(body);
  if (maxTokensError) return { error: maxTokensError };

  const systemError = validateSystemPrompts(body);
  if (systemError) return { error: systemError };

  const validation = validateAnthropicMessagesBody(body, {
    autoOptimizeCacheControls: false,
  });
  if (validation.error) {
    return { error: validation.error };
  }

  return {
    sanitizedBody: validation.sanitizedBody ?? body,
  };
}

export const anthropicMessagesInbound = {
  parse(body: unknown): {
    value?: ProtocolRequestEnvelope<'anthropic/messages', ParsedDownstreamChatRequest>;
    error?: { statusCode: number; payload: unknown };
  } {
    const rawBody = isRecord(body) ? body : null;
    const inboundValidation = rawBody ? sanitizeAnthropicInboundBody(rawBody) : null;
    if (inboundValidation?.error) {
      return { error: inboundValidation.error };
    }

    const effectiveBody = inboundValidation?.sanitizedBody ?? body;
    const parsed = parseDownstreamChatRequest(effectiveBody, 'claude');
    if (parsed.error) {
      return { error: parsed.error };
    }
    if (!parsed.value) {
      return { error: invalidRequest('invalid messages request') };
    }

    if (inboundValidation?.sanitizedBody) {
      parsed.value.claudeOriginalBody = inboundValidation.sanitizedBody;
    }

    return {
      value: createProtocolRequestEnvelope({
        protocol: 'anthropic/messages',
        model: parsed.value.requestedModel,
        stream: parsed.value.isStream,
        rawBody: body,
        parsed: parsed.value,
      }),
    };
  },
};
