import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('proxy route architecture boundaries', () => {
  it('keeps shared protocol helpers out of chat route', () => {
    const source = readSource('./chat.ts');
    const surfaceSource = readSource('../../proxy-core/surfaces/chatSurface.ts');
    expect(source).toContain("from '../../proxy-core/surfaces/chatSurface.js'");
    expect(source).not.toContain("from './chatFormats.js'");
    expect(surfaceSource).toContain("from '../../transformers/openai/chat/index.js'");
    expect(surfaceSource).toContain("from '../../transformers/anthropic/messages/index.js'");
  });
  it('keeps anthropic-specific stream orchestration out of chat route', () => {
    const source = readSource('./chat.ts');
    const surfaceSource = readSource('../../proxy-core/surfaces/chatSurface.ts');
    expect(source).not.toContain('serializeAnthropicRawSseEvent');
    expect(source).not.toContain('syncAnthropicRawStreamStateFromEvent');
    expect(source).not.toContain('isAnthropicRawSseEventName');
    expect(source).not.toContain('serializeAnthropicFinalAsStream');
    expect(source).not.toContain('function shouldRetryClaudeMessagesWithNormalizedBody(');
    expect(source).not.toContain('const emitNormalizedFinalAsStream =');
    expect(source).not.toContain("from './protocolCompat.js'");
    expect(source).not.toContain("from './chatStreamCompat.js'");
    expect(source).not.toContain('const promoteResponsesCandidate =');
    expect(source).not.toContain('shouldRetryClaudeMessagesWithNormalizedBody(');
    expect(source).not.toContain('buildOpenAiSyntheticFinalStream(');
    expect(source).not.toContain('anthropicMessagesTransformer.consumeSseEventBlock(');
    expect(source).not.toContain('anthropicMessagesTransformer.serializeUpstreamFinalAsStream(');
    expect(source).not.toContain('openAiChatTransformer.serializeUpstreamFinalAsStream(');
    expect(surfaceSource).toContain('openAiChatTransformer.proxyStream.createSession(');
    expect(surfaceSource).toContain('streamSession.consumeUpstreamFinalPayload(');
    expect(surfaceSource).toContain('streamSession.run(');
  });

  it('keeps chat endpoint retry and downgrade strategy out of the route', () => {
    const source = readSource('./chat.ts');
    const surfaceSource = readSource('../../proxy-core/surfaces/chatSurface.ts');
    expect(surfaceSource).toContain('downstreamTransformer.compatibility.createEndpointStrategy(');
    expect(source).not.toContain('anthropicMessagesTransformer.compatibility.shouldRetryNormalizedBody(');
    expect(source).not.toContain('buildMinimalJsonHeadersForCompatibility(');
    expect(source).not.toContain('promoteResponsesCandidateAfterLegacyChatError(');
    expect(source).not.toContain('isEndpointDowngradeError(');
    expect(source).not.toContain('isEndpointDispatchDeniedError(');
    expect(source).not.toContain('isUnsupportedMediaTypeError(');
  });

  it('keeps responses protocol assembly out of responses route', () => {
    const source = readSource('./responses.ts');
    const surfaceSource = readSource('../../proxy-core/surfaces/openAiResponsesSurface.ts');
    expect(source).toContain("from '../../proxy-core/surfaces/openAiResponsesSurface.js'");
    expect(source).not.toContain('function toResponsesPayload(');
    expect(source).not.toContain('function createResponsesStreamState(');
    expect(source).not.toContain("from '../../transformers/openai/responses/conversion.js'");
    expect(source).not.toContain("from '../../transformers/openai/responses/outbound.js'");
    expect(source).not.toContain("from '../../transformers/openai/responses/aggregator.js'");
    expect(source).not.toContain('function buildResponsesCompatibilityBodies(');
    expect(source).not.toContain('function buildResponsesCompatibilityHeaderCandidates(');
    expect(source).not.toContain('function shouldRetryResponsesCompatibility(');
    expect(source).not.toContain("from './protocolCompat.js'");
    expect(source).not.toContain('function shouldDowngradeFromChatToMessagesForResponses(');
    expect(source).not.toContain('function normalizeText(');
    expect(surfaceSource).toContain('openAiResponsesTransformer.inbound.toOpenAiBody(');
    expect(surfaceSource).toContain('openAiResponsesTransformer.compatibility.createEndpointStrategy(');
    expect(surfaceSource).not.toContain('openAiResponsesTransformer.aggregator.createState(');
    expect(surfaceSource).not.toContain('openAiResponsesTransformer.aggregator.serialize(');
    expect(surfaceSource).not.toContain('openAiResponsesTransformer.aggregator.complete(');
    expect(surfaceSource).toContain('openAiResponsesTransformer.proxyStream.createSession(');
    expect(surfaceSource).toContain('streamSession.run(');
    expect(surfaceSource).toContain('openAiResponsesTransformer.outbound.serializeFinal(');
  });

  it('keeps responses endpoint retry and downgrade strategy out of the route', () => {
    const source = readSource('./responses.ts');
    const surfaceSource = readSource('../../proxy-core/surfaces/openAiResponsesSurface.ts');
    expect(surfaceSource).toContain('openAiResponsesTransformer.compatibility.createEndpointStrategy(');
    expect(source).not.toContain('openAiResponsesTransformer.compatibility.shouldRetry(');
    expect(source).not.toContain('openAiResponsesTransformer.compatibility.buildRetryBodies(');
    expect(source).not.toContain('openAiResponsesTransformer.compatibility.buildRetryHeaders(');
    expect(source).not.toContain('openAiResponsesTransformer.compatibility.shouldDowngradeChatToMessages(');
    expect(source).not.toContain('buildMinimalJsonHeadersForCompatibility(');
    expect(source).not.toContain('isEndpointDowngradeError(');
    expect(source).not.toContain('isUnsupportedMediaTypeError(');
  });

  it('removes normalizeContentText from upstream endpoint routing', () => {
    const source = readSource('./upstreamEndpoint.ts');
    expect(source).not.toContain('function normalizeContentText(');
    expect(source).not.toContain('normalizeContentText(');
  });

  it('keeps codex runtime header and prompt-cache derivation inside provider profiles', () => {
    const source = readSource('./upstreamEndpoint.ts');
    expect(source).not.toContain('buildCodexRuntimeHeaders(');
    expect(source).not.toContain('shouldInjectDerivedPromptCacheKey');
  });

  it('keeps endpoint runtime snapshot helper out of the route layer', () => {
    const source = readSource('./upstreamEndpoint.ts');
    expect(source).not.toContain('function getUpstreamEndpointRuntimeStateSnapshot(');
    expect(source).not.toContain('export function getUpstreamEndpointRuntimeStateSnapshot(');
  });

  it('keeps gemini runtime closure in transformer-owned helpers', () => {
    const source = readSource('./gemini.ts');
    const surfaceSource = readSource('../../proxy-core/surfaces/geminiSurface.ts');
    expect(source).toContain("from '../../proxy-core/surfaces/geminiSurface.js'");
    expect(source).not.toContain('outbound.serializeAggregateResponse(');
    expect(source).not.toContain('aggregator.apply(');
    expect(source).not.toContain('stream.serializeAggregateSsePayload(');
    expect(source).not.toContain('stream.serializeAggregateJsonPayload(');
    expect(source).not.toContain('stream.applyJsonPayloadToAggregate(');
    expect(source).not.toContain('stream.parseSsePayloads(');
    expect(surfaceSource).toContain('stream.consumeUpstreamSseBuffer(');
    expect(surfaceSource).toContain('stream.serializeUpstreamJsonPayload(');
  });

  it('keeps proxy file persistence out of files route', () => {
    const source = readSource('./files.ts');
    expect(source).toContain("from '../../proxy-core/surfaces/filesSurface.js'");
    expect(source).not.toContain('saveProxyFile(');
    expect(source).not.toContain('listProxyFilesByOwner(');
    expect(source).not.toContain('getProxyFileByPublicIdForOwner(');
    expect(source).not.toContain('getProxyFileContentByPublicIdForOwner(');
    expect(source).not.toContain('softDeleteProxyFileByPublicIdForOwner(');
  });

  it('keeps chat stream lifecycle behind transformer-owned facade', () => {
    const source = readSource('./chat.ts');
    const surfaceSource = readSource('../../proxy-core/surfaces/chatSurface.ts');
    expect(source).not.toContain("from '../../transformers/shared/protocolLifecycle.js'");
    expect(source).not.toContain('createProxyStreamLifecycle');
    expect(source).not.toContain('let shouldTerminateEarly = false;');
    expect(source).not.toContain('const consumeSseBuffer = (incoming: string): string => {');
    expect(source).not.toContain('writeDone();');
    expect(surfaceSource).toContain('openAiChatTransformer.proxyStream.createSession(');
  });

  it('keeps responses stream lifecycle behind transformer-owned facade', () => {
    const source = readSource('./responses.ts');
    const surfaceSource = readSource('../../proxy-core/surfaces/openAiResponsesSurface.ts');
    expect(source).not.toContain("from '../../transformers/shared/protocolLifecycle.js'");
    expect(source).not.toContain('createProxyStreamLifecycle');
    expect(source).not.toContain('const consumeSseBuffer = (incoming: string): string => {');
    expect(source).not.toContain('reply.raw.end();');
    expect(surfaceSource).not.toContain('openAiResponsesTransformer.aggregator.complete(');
    expect(surfaceSource).toContain('reply.hijack();');
    expect(surfaceSource).toContain('openAiResponsesTransformer.proxyStream.createSession(');
  });

  it('keeps oauth refresh recovery and success bookkeeping behind shared surface helpers', () => {
    const chatSurfaceSource = readSource('../../proxy-core/surfaces/chatSurface.ts');
    const responsesSurfaceSource = readSource('../../proxy-core/surfaces/openAiResponsesSurface.ts');

    expect(chatSurfaceSource).toContain('trySurfaceOauthRefreshRecovery(');
    expect(chatSurfaceSource).toContain('recordSurfaceSuccess(');
    expect(chatSurfaceSource).not.toContain('refreshOauthAccessTokenSingleflight(');
    expect(chatSurfaceSource).not.toContain('resolveProxyUsageWithSelfLogFallback(');
    expect(chatSurfaceSource).not.toContain('resolveProxyLogBilling(');
    expect((chatSurfaceSource.match(/bestEffortMetrics:/g) || []).length).toBeGreaterThanOrEqual(2);

    expect(responsesSurfaceSource).toContain('trySurfaceOauthRefreshRecovery(');
    expect(responsesSurfaceSource).toContain('recordSurfaceSuccess(');
    expect(responsesSurfaceSource).not.toContain('refreshOauthAccessTokenSingleflight(');
    expect(responsesSurfaceSource).not.toContain('resolveProxyUsageWithSelfLogFallback(');
    expect(responsesSurfaceSource).not.toContain('resolveProxyLogBilling(');
  });

  it('keeps canonical transformer contracts imported from the transformer boundary only', () => {
    const chatSource = readSource('./chat.ts');
    const responsesSource = readSource('./responses.ts');
    const geminiSource = readSource('./gemini.ts');

    expect(chatSource).not.toContain("from '../proxy-core/");
    expect(responsesSource).not.toContain("from '../proxy-core/");
    expect(geminiSource).not.toContain("from '../proxy-core/");
    expect(chatSource).not.toContain("from '../../transformers/contracts.js'");
    expect(responsesSource).not.toContain("from '../../transformers/contracts.js'");
    expect(geminiSource).not.toContain("from '../../transformers/contracts.js'");
    expect(chatSource).not.toContain("from '../../transformers/canonical/");
    expect(responsesSource).not.toContain("from '../../transformers/canonical/");
    expect(geminiSource).not.toContain("from '../../transformers/canonical/");
  });
});
