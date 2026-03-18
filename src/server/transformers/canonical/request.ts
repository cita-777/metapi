import type { CanonicalAttachment } from './attachments.js';
import type { CanonicalTool, CanonicalToolChoice } from './tools.js';
import type {
  CanonicalCliProfile,
  CanonicalContinuation,
  CanonicalMessage,
  CanonicalOperation,
  CanonicalReasoningRequest,
  CanonicalRequestEnvelope,
  CanonicalSurface,
} from './types.js';

export type CreateCanonicalRequestEnvelopeInput = {
  operation?: CanonicalOperation;
  surface: CanonicalSurface;
  cliProfile?: CanonicalCliProfile;
  requestedModel: string;
  stream?: boolean;
  messages?: CanonicalMessage[];
  reasoning?: CanonicalReasoningRequest;
  tools?: CanonicalTool[];
  toolChoice?: CanonicalToolChoice;
  continuation?: CanonicalContinuation;
  metadata?: Record<string, unknown>;
  passthrough?: Record<string, unknown>;
  attachments?: CanonicalAttachment[];
};

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeCanonicalContinuation(
  continuation: CanonicalContinuation | undefined,
): CanonicalContinuation | undefined {
  if (!continuation) return undefined;

  const normalized: CanonicalContinuation = {
    ...(asTrimmedString(continuation.sessionId) ? { sessionId: asTrimmedString(continuation.sessionId) } : {}),
    ...(asTrimmedString(continuation.previousResponseId)
      ? { previousResponseId: asTrimmedString(continuation.previousResponseId) }
      : {}),
    ...(asTrimmedString(continuation.promptCacheKey)
      ? { promptCacheKey: asTrimmedString(continuation.promptCacheKey) }
      : {}),
    ...(asTrimmedString(continuation.turnState) ? { turnState: asTrimmedString(continuation.turnState) } : {}),
  };

  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

export function createCanonicalRequestEnvelope(
  input: CreateCanonicalRequestEnvelopeInput,
): CanonicalRequestEnvelope {
  const requestedModel = asTrimmedString(input.requestedModel);
  if (!requestedModel) {
    throw new Error('canonical request requires requestedModel');
  }

  return {
    operation: input.operation ?? 'generate',
    surface: input.surface,
    cliProfile: input.cliProfile ?? 'generic',
    requestedModel,
    stream: input.stream === true,
    messages: Array.isArray(input.messages) ? input.messages : [],
    ...(input.reasoning ? { reasoning: input.reasoning } : {}),
    ...(Array.isArray(input.tools) && input.tools.length > 0 ? { tools: input.tools } : {}),
    ...(input.toolChoice !== undefined ? { toolChoice: input.toolChoice } : {}),
    ...(normalizeCanonicalContinuation(input.continuation)
      ? { continuation: normalizeCanonicalContinuation(input.continuation) }
      : {}),
    ...(input.metadata ? { metadata: input.metadata } : {}),
    ...(input.passthrough ? { passthrough: input.passthrough } : {}),
  };
}

export * from './attachments.js';
export * from './reasoning.js';
export * from './tools.js';
export * from './types.js';
