import { type DownstreamFormat } from '../../shared/normalized.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function hasAnthropicContinuationHint(body: Record<string, unknown>): boolean {
  if (asTrimmedString(body.previous_response_id)) return true;
  if (asTrimmedString(body.prompt_cache_key)) return true;
  if (isRecord(body.metadata) && asTrimmedString(body.metadata.user_id)) return true;
  return false;
}

function hasOrphanAnthropicToolResult(body: Record<string, unknown>): boolean {
  const messages = Array.isArray(body.messages) ? body.messages : [];
  const seenToolUseIds = new Set<string>();

  for (const message of messages) {
    if (!isRecord(message) || !Array.isArray(message.content)) continue;

    const role = asTrimmedString(message.role).toLowerCase();
    for (const block of message.content) {
      if (!isRecord(block)) continue;
      const type = asTrimmedString(block.type).toLowerCase();
      if (!type) continue;

      if (role === 'assistant' && type === 'tool_use') {
        const toolUseId = asTrimmedString(block.id);
        if (toolUseId) seenToolUseIds.add(toolUseId);
        continue;
      }

      if (type !== 'tool_result') continue;
      const toolUseId = asTrimmedString(block.tool_use_id ?? block.toolUseId);
      if (toolUseId && !seenToolUseIds.has(toolUseId)) {
        return true;
      }
    }
  }

  return false;
}

export function shouldPreferResponsesForAnthropicContinuation(
  body: Record<string, unknown> | null | undefined,
): boolean {
  if (!body) return false;
  return hasAnthropicContinuationHint(body) && hasOrphanAnthropicToolResult(body);
}

export function shouldRetryNormalizedMessagesBody(input: {
  downstreamFormat: DownstreamFormat;
  endpointPath: string;
  status: number;
  upstreamErrorText: string;
}): boolean {
  if (input.downstreamFormat !== 'claude') return false;
  if (!input.endpointPath.includes('/v1/messages')) return false;
  if (input.status < 400 || input.status >= 500) return false;
  return /messages\s+is\s+required/i.test(input.upstreamErrorText);
}

export function isMessagesRequiredError(upstreamErrorText: string): boolean {
  return /messages\s+is\s+required/i.test(upstreamErrorText);
}
