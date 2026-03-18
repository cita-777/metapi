import type {
  NormalizedFinalResponse,
  NormalizedStreamEvent,
} from './normalized.js';

export type TransformerProtocol =
  | 'openai/chat'
  | 'anthropic/messages'
  | 'openai/responses'
  | 'gemini/generate-content'
  | 'gemini-cli/generate-content';

export type ProtocolRequestEnvelope<
  TProtocol extends TransformerProtocol = TransformerProtocol,
  TParsed = unknown,
  TMetadata = unknown,
> = {
  protocol: TProtocol;
  model: string;
  stream: boolean;
  rawBody: unknown;
  parsed: TParsed;
  metadata?: TMetadata;
};

export type ProtocolResponseEnvelope<
  TProtocol extends TransformerProtocol = TransformerProtocol,
  TFinal extends NormalizedFinalResponse = NormalizedFinalResponse,
  TMetadata = unknown,
> = {
  protocol: TProtocol;
  model: string;
  final: TFinal;
  usage?: unknown;
  metadata?: TMetadata;
};

export type ProtocolStreamEnvelope<
  TProtocol extends TransformerProtocol = TransformerProtocol,
  TEvent extends NormalizedStreamEvent = NormalizedStreamEvent,
  TMetadata = unknown,
> = {
  protocol: TProtocol;
  model: string;
  event: TEvent;
  metadata?: TMetadata;
};

export function createProtocolRequestEnvelope<
  TProtocol extends TransformerProtocol,
  TParsed,
  TMetadata = unknown,
>(envelope: ProtocolRequestEnvelope<TProtocol, TParsed, TMetadata>): ProtocolRequestEnvelope<TProtocol, TParsed, TMetadata> {
  return envelope;
}

export function createProtocolResponseEnvelope<
  TProtocol extends TransformerProtocol,
  TFinal extends NormalizedFinalResponse,
  TMetadata = unknown,
>(envelope: ProtocolResponseEnvelope<TProtocol, TFinal, TMetadata>): ProtocolResponseEnvelope<TProtocol, TFinal, TMetadata> {
  return envelope;
}

export function createProtocolStreamEnvelope<
  TProtocol extends TransformerProtocol,
  TEvent extends NormalizedStreamEvent,
  TMetadata = unknown,
>(envelope: ProtocolStreamEnvelope<TProtocol, TEvent, TMetadata>): ProtocolStreamEnvelope<TProtocol, TEvent, TMetadata> {
  return envelope;
}
