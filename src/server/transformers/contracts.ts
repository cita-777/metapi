import type {
  CanonicalCliProfile,
  CanonicalContinuation,
  CanonicalOperation,
  CanonicalRequestEnvelope,
} from './canonical/types.js';
import type {
  ClaudeDownstreamContext,
  NormalizedFinalResponse,
  NormalizedStreamEvent,
  StreamTransformContext,
} from './shared/normalized.js';

export type ProtocolParseContext = {
  cliProfile?: CanonicalCliProfile;
  operation?: CanonicalOperation;
  continuation?: CanonicalContinuation;
  metadata?: Record<string, unknown>;
  passthrough?: Record<string, unknown>;
  defaultEncryptedReasoningInclude?: boolean;
};

export type ProtocolBuildContext = {
  cliProfile?: CanonicalCliProfile;
};

export type ProtocolResponseContext = {
  modelName: string;
  fallbackText?: string;
};

export type ProtocolStreamContext = {
  modelName: string;
  streamContext?: StreamTransformContext;
};

export type ProtocolSerializeContext = {
  modelName: string;
  usage?: {
    promptTokens?: number | null;
    completionTokens?: number | null;
    totalTokens?: number | null;
  };
  streamContext?: StreamTransformContext;
  claudeContext?: ClaudeDownstreamContext;
};

export interface ProtocolTransformer {
  parseRequest(
    body: unknown,
    ctx?: ProtocolParseContext,
  ): { value?: CanonicalRequestEnvelope; error?: { statusCode: number; payload: unknown } };

  buildProtocolRequest(
    request: CanonicalRequestEnvelope,
    ctx?: ProtocolBuildContext,
  ): Record<string, unknown>;

  normalizeFinal(
    payload: unknown,
    ctx: ProtocolResponseContext,
  ): NormalizedFinalResponse;

  normalizeStreamEvent(
    payload: unknown,
    ctx: ProtocolStreamContext,
  ): NormalizedStreamEvent;

  serializeFinal(
    normalized: NormalizedFinalResponse,
    ctx: ProtocolSerializeContext,
  ): unknown;

  serializeStreamEvent(
    normalized: NormalizedStreamEvent,
    ctx: ProtocolSerializeContext,
  ): string[] | unknown[];
}
