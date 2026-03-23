import type { PreparedProviderRequest, PrepareProviderRequestInput, ProviderProfile } from './types.js';
import { config } from '../../config.js';
import { buildCodexRuntimeHeaders, getInputHeader } from './headerUtils.js';

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export const codexProviderProfile: ProviderProfile = {
  id: 'codex',
  prepareRequest(input: PrepareProviderRequestInput): PreparedProviderRequest {
    const isCodexOauth = asTrimmedString(input.oauthProvider).toLowerCase() === 'codex';
    const websocketTransport = getInputHeader(input.baseHeaders, 'x-metapi-responses-websocket-transport') === '1';
    const configuredUserAgent = isCodexOauth ? asTrimmedString(config.codexHeaderDefaults.userAgent) : '';
    const configuredBetaFeatures = (
      isCodexOauth && websocketTransport
        ? asTrimmedString(config.codexHeaderDefaults.betaFeatures)
        : ''
    );
    const headers = buildCodexRuntimeHeaders({
      baseHeaders: input.baseHeaders,
      providerHeaders: input.providerHeaders,
      explicitSessionId: asTrimmedString(input.codexExplicitSessionId) || null,
      continuityKey: asTrimmedString(input.codexSessionCacheKey) || null,
      userAgentOverride: configuredUserAgent || null,
      codexBetaFeatures: getInputHeader(input.baseHeaders, 'x-codex-beta-features') || configuredBetaFeatures,
      codexTurnState: getInputHeader(input.baseHeaders, 'x-codex-turn-state'),
      codexTurnMetadata: getInputHeader(input.baseHeaders, 'x-codex-turn-metadata'),
      timingMetrics: getInputHeader(input.baseHeaders, 'x-responsesapi-include-timing-metrics'),
      openAiBeta: getInputHeader(input.baseHeaders, 'openai-beta')
        || (websocketTransport ? asTrimmedString(config.codexResponsesWebsocketBeta) : null),
    });

    return {
      path: '/responses',
      headers,
      body: input.body,
      runtime: {
        executor: 'codex',
        modelName: input.modelName,
        stream: input.stream,
        oauthProjectId: asTrimmedString(input.oauthProjectId) || null,
      },
    };
  },
};
