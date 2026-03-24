import type { PreparedProviderRequest, PrepareProviderRequestInput, ProviderProfile } from './types.js';
import { buildClaudeRuntimeHeaders } from './headerUtils.js';

export const claudeProviderProfile: ProviderProfile = {
  id: 'claude',
  prepareRequest(input: PrepareProviderRequestInput): PreparedProviderRequest {
    const anthropicVersion = (
      input.claudeHeaders?.['anthropic-version']
      || input.baseHeaders['anthropic-version']
      || '2023-06-01'
    );
    const isClaudeOauthUpstream = input.sitePlatform?.trim().toLowerCase() === 'claude'
      && input.oauthProvider === 'claude';
    const isCountTokens = input.action === 'countTokens';

    return {
      path: isCountTokens ? '/v1/messages/count_tokens?beta=true' : '/v1/messages',
      headers: buildClaudeRuntimeHeaders({
        baseHeaders: input.baseHeaders,
        claudeHeaders: input.claudeHeaders ?? {},
        anthropicVersion,
        stream: isCountTokens ? false : input.stream,
        isClaudeOauthUpstream,
        tokenValue: input.tokenValue,
      }),
      body: input.body,
      runtime: {
        executor: 'claude',
        modelName: input.modelName,
        stream: isCountTokens ? false : input.stream,
        oauthProjectId: null,
        ...(isCountTokens ? { action: 'countTokens' } : {}),
      },
    };
  },
};
