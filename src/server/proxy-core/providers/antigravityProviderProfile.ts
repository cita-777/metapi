import type { PreparedProviderRequest, PrepareProviderRequestInput, ProviderAction, ProviderProfile } from './types.js';

const ANTIGRAVITY_RUNTIME_USER_AGENT = 'antigravity/1.19.6 darwin/arm64';

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function resolveAction(action: ProviderAction | undefined, stream: boolean): ProviderAction {
  if (action) return action;
  return stream ? 'streamGenerateContent' : 'generateContent';
}

function resolvePath(action: ProviderAction): string {
  if (action === 'countTokens') return '/v1internal:countTokens';
  if (action === 'streamGenerateContent') return '/v1internal:streamGenerateContent?alt=sse';
  return '/v1internal:generateContent';
}

export const antigravityProviderProfile: ProviderProfile = {
  id: 'antigravity',
  prepareRequest(input: PrepareProviderRequestInput): PreparedProviderRequest {
    const action = resolveAction(input.action, input.stream);
    const projectId = asTrimmedString(input.oauthProjectId);
    return {
      path: resolvePath(action),
      headers: {
        Authorization: input.baseHeaders.Authorization,
        'Content-Type': 'application/json',
        Accept: action === 'streamGenerateContent' ? 'text/event-stream' : 'application/json',
        'User-Agent': ANTIGRAVITY_RUNTIME_USER_AGENT,
      },
      body: {
        project: projectId,
        model: input.modelName,
        request: input.body,
      },
      runtime: {
        executor: 'antigravity',
        modelName: input.modelName,
        stream: action === 'streamGenerateContent',
        oauthProjectId: projectId,
        action,
      },
    };
  },
};
