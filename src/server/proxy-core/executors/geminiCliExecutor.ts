import type { RuntimeDispatchInput, RuntimeExecutor, RuntimeResponse } from './types.js';
import {
  asTrimmedString,
  materializeErrorResponse,
  performFetch,
  withRequestBody,
} from './types.js';

function replaceGeminiCliModelInUserAgent(userAgent: string | undefined, modelName: string): string | undefined {
  const raw = asTrimmedString(userAgent);
  if (!raw) return undefined;
  return raw.replace(/^GeminiCLI\/([^/]+)\/[^ ]+ /i, `GeminiCLI/$1/${modelName} `);
}

function buildGeminiCliAttemptRequest(
  request: RuntimeDispatchInput['request'],
  modelName: string,
) {
  const body = structuredClone(request.body);
  const action = request.runtime?.action;
  if (action === 'countTokens') {
    delete body.model;
    delete body.project;
  } else {
    body.model = modelName;
  }
  const headers = { ...request.headers };
  const nextUserAgent = replaceGeminiCliModelInUserAgent(
    headers['User-Agent'] || headers['user-agent'],
    modelName,
  );
  if (nextUserAgent) {
    headers['User-Agent'] = nextUserAgent;
    delete headers['user-agent'];
  }
  return withRequestBody(request, body, headers);
}

export const geminiCliExecutor: RuntimeExecutor = {
  async dispatch(input: RuntimeDispatchInput) {
    const baseModel = asTrimmedString(input.request.runtime?.modelName) || asTrimmedString(input.request.body.model);
    const models = [baseModel].filter(Boolean);
    let lastResponse: RuntimeResponse | null = null;

    for (const modelName of models.length > 0 ? models : [baseModel || 'unknown']) {
      const attemptRequest = buildGeminiCliAttemptRequest(input.request, modelName);
      const response = await performFetch(input, attemptRequest);
      if (response.ok) return response;

      if (response.status === 429) {
        lastResponse = await materializeErrorResponse(response);
        continue;
      }

      return materializeErrorResponse(response);
    }

    return lastResponse || performFetch(input, input.request);
  },
};
