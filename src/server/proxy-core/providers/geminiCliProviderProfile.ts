import type { PreparedProviderRequest, PrepareProviderRequestInput, ProviderAction, ProviderProfile } from './types.js';
import { buildGeminiCliRuntimeHeaders } from './headerUtils.js';

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

export const geminiCliProviderProfile: ProviderProfile = {
  id: 'gemini-cli',
  prepareRequest(input: PrepareProviderRequestInput): PreparedProviderRequest {
    const projectId = asTrimmedString(input.oauthProjectId);
    if (!projectId) {
      throw new Error('gemini-cli oauth project id missing');
    }
    const action = resolveAction(input.action, input.stream);
    const headers = buildGeminiCliRuntimeHeaders({
      baseHeaders: input.baseHeaders,
      providerHeaders: input.providerHeaders,
      modelName: input.modelName,
      stream: action === 'streamGenerateContent',
    });
    return {
      path: resolvePath(action),
      headers,
      body: {
        project: projectId,
        model: input.modelName,
        request: input.body,
      },
      runtime: {
        executor: 'gemini-cli',
        modelName: input.modelName,
        stream: action === 'streamGenerateContent',
        oauthProjectId: projectId,
        action,
      },
    };
  },
};
