import { canonicalRequestFromOpenAiBody, canonicalRequestToOpenAiChatBody } from '../../canonical/request.js';
import type { CanonicalRequestEnvelope } from '../../canonical/types.js';
import type { ProtocolBuildContext, ProtocolParseContext } from '../../contracts.js';
import { type StreamTransformContext } from '../../shared/normalized.js';
import {
  convertOpenAiBodyToResponsesBody,
  convertResponsesBodyToOpenAiBody,
  sanitizeResponsesBodyForProxy,
} from './conversion.js';
import {
  buildResponsesCompatibilityBodies as buildRetryBodies,
  buildResponsesCompatibilityHeaderCandidates as buildRetryHeaders,
  normalizeResponsesInputForCompatibility,
  normalizeResponsesMessageContent,
  normalizeResponsesMessageItem,
  shouldDowngradeResponsesChatToMessages as shouldDowngradeChatToMessages,
  shouldRetryResponsesCompatibility as shouldRetry,
} from './compatibility.js';
import {
  type OpenAiResponsesAggregateState,
  completeResponsesStream,
  createOpenAiResponsesAggregateState,
  failResponsesStream,
  serializeConvertedResponsesEvents,
} from './aggregator.js';
import { openAiResponsesOutbound } from './outbound.js';
import { openAiResponsesInbound } from './inbound.js';
import { createResponsesProxyStreamSession } from './proxyStream.js';
import { createResponsesEndpointStrategy } from './routeCompatibility.js';
import { openAiResponsesStream } from './stream.js';
import { openAiResponsesUsage } from './usage.js';
import type {
  OpenAiResponsesParsedRequest as OpenAiResponsesParsedRequestModel,
  OpenAiResponsesRequestEnvelope as OpenAiResponsesRequestEnvelopeModel,
} from './model.js';

export const openAiResponsesTransformer = {
  protocol: 'openai/responses' as const,
  inbound: {
    parse: openAiResponsesInbound.parse,
    normalizeInput: normalizeResponsesInputForCompatibility,
    normalizeMessage: normalizeResponsesMessageItem,
    normalizeContent: normalizeResponsesMessageContent,
    sanitizeProxyBody: sanitizeResponsesBodyForProxy,
    fromOpenAiBody: convertOpenAiBodyToResponsesBody,
    toOpenAiBody: convertResponsesBodyToOpenAiBody,
  },
  outbound: openAiResponsesOutbound,
  stream: openAiResponsesStream,
  usage: openAiResponsesUsage,
  compatibility: {
    createEndpointStrategy: createResponsesEndpointStrategy,
    buildRetryBodies,
    buildRetryHeaders,
    shouldRetry,
    shouldDowngradeChatToMessages,
  },
  aggregator: {
    createState: createOpenAiResponsesAggregateState,
    serialize: serializeConvertedResponsesEvents,
    complete: completeResponsesStream,
    fail: failResponsesStream,
  },
  proxyStream: {
    createSession: createResponsesProxyStreamSession,
  },
  parseRequest(
    body: unknown,
    ctx?: ProtocolParseContext,
  ): { value?: CanonicalRequestEnvelope; error?: { statusCode: number; payload: unknown } } {
    const parsed = openAiResponsesInbound.parse(body, {
      defaultEncryptedReasoningInclude: ctx?.defaultEncryptedReasoningInclude,
    });
    if (parsed.error) {
      return { error: parsed.error };
    }
    if (!parsed.value) {
      return {
        error: {
          statusCode: 400,
          payload: {
            error: {
              message: 'invalid responses request',
              type: 'invalid_request_error',
            },
          },
        },
      };
    }

    const responsesBody = parsed.value.parsed.normalizedBody;
    const openAiBody = convertResponsesBodyToOpenAiBody(
      responsesBody,
      typeof responsesBody.model === 'string' ? responsesBody.model : parsed.value.model,
      responsesBody.stream === true,
      { defaultEncryptedReasoningInclude: ctx?.defaultEncryptedReasoningInclude },
    );

    return {
      value: canonicalRequestFromOpenAiBody({
        body: openAiBody,
        surface: 'openai-responses',
        cliProfile: ctx?.cliProfile,
        operation: ctx?.operation,
        metadata: ctx?.metadata,
        passthrough: ctx?.passthrough,
        continuation: ctx?.continuation,
      }),
    };
  },
  buildProtocolRequest(
    request: CanonicalRequestEnvelope,
    _ctx?: ProtocolBuildContext,
  ): Record<string, unknown> {
    const openAiBody = canonicalRequestToOpenAiChatBody(request);
    if (request.reasoning) {
      openAiBody.reasoning = {
        ...(request.reasoning.effort ? { effort: request.reasoning.effort } : {}),
        ...(request.reasoning.budgetTokens !== undefined ? { budget_tokens: request.reasoning.budgetTokens } : {}),
        ...(request.reasoning.summary ? { summary: request.reasoning.summary } : {}),
      };
    }
    return convertOpenAiBodyToResponsesBody(openAiBody, request.requestedModel, request.stream);
  },
  transformRequest(
    body: unknown,
    options?: { defaultEncryptedReasoningInclude?: boolean },
  ): { value?: OpenAiResponsesRequestEnvelopeModel; error?: { statusCode: number; payload: unknown } } {
    return openAiResponsesInbound.parse(body, options);
  },
  createStreamContext(modelName: string): StreamTransformContext {
    return openAiResponsesStream.createContext(modelName);
  },
  transformFinalResponse(payload: unknown, modelName: string, fallbackText = '') {
    return openAiResponsesOutbound.normalizeFinal(payload, modelName, fallbackText);
  },
  transformStreamEvent(payload: unknown, context: StreamTransformContext, modelName: string) {
    return openAiResponsesStream.normalizeEvent(payload, context, modelName);
  },
  pullSseEvents(buffer: string) {
    return openAiResponsesStream.pullSseEvents(buffer);
  },
};

export type OpenAiResponsesTransformer = typeof openAiResponsesTransformer;
export type OpenAiResponsesAggregate = OpenAiResponsesAggregateState;
export type OpenAiResponsesParsedRequest = OpenAiResponsesParsedRequestModel;
export type OpenAiResponsesRequestEnvelope = OpenAiResponsesRequestEnvelopeModel;
export {
  convertOpenAiBodyToResponsesBody,
  convertResponsesBodyToOpenAiBody,
  normalizeResponsesInputForCompatibility,
  normalizeResponsesMessageContent,
  normalizeResponsesMessageItem,
  sanitizeResponsesBodyForProxy,
};
