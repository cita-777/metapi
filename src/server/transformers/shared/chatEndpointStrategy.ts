import type { Response as UndiciResponse } from 'undici';
import type { DownstreamFormat } from './normalized.js';
import {
  buildMinimalJsonHeadersForCompatibility,
  isEndpointDispatchDeniedError,
  isEndpointDowngradeError,
  isUnsupportedMediaTypeError,
  promoteResponsesCandidateAfterLegacyChatError,
  type CompatibilityEndpoint,
} from './endpointCompatibility.js';
import {
  isMessagesRequiredError,
  shouldRetryNormalizedMessagesBody,
} from '../anthropic/messages/compatibility.js';

type EndpointAttemptContext = {
  request: CompatibilityRequest;
  targetUrl: string;
  response: UndiciResponse;
  rawErrText: string;
};

type EndpointRecoverResult = {
  upstream: UndiciResponse;
  upstreamPath: string;
} | null;

type CompatibilityRequest = {
  endpoint: CompatibilityEndpoint;
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
};

type UpstreamResponse = Exclude<EndpointRecoverResult, null>['upstream'];

type CreateChatEndpointStrategyInput = {
  downstreamFormat: DownstreamFormat;
  endpointCandidates: CompatibilityEndpoint[];
  modelName: string;
  requestedModelHint: string;
  sitePlatform?: string | null;
  isStream: boolean;
  buildRequest: (input: {
    endpoint: CompatibilityEndpoint;
    forceNormalizeClaudeBody?: boolean;
  }) => CompatibilityRequest;
  dispatchRequest: (
    request: CompatibilityRequest,
    targetUrl?: string,
  ) => Promise<UpstreamResponse>;
};

export function createChatEndpointStrategy(input: CreateChatEndpointStrategyInput) {
  return {
    async tryRecover(ctx: EndpointAttemptContext): Promise<EndpointRecoverResult> {
      if (shouldRetryNormalizedMessagesBody({
        downstreamFormat: input.downstreamFormat,
        endpointPath: ctx.request.path,
        status: ctx.response.status,
        upstreamErrorText: ctx.rawErrText,
      })) {
        const normalizedClaudeRequest = input.buildRequest({
          endpoint: ctx.request.endpoint,
          forceNormalizeClaudeBody: true,
        });
        const normalizedResponse = await input.dispatchRequest(normalizedClaudeRequest);

        if (normalizedResponse.ok) {
          return {
            upstream: normalizedResponse,
            upstreamPath: normalizedClaudeRequest.path,
          };
        }

        ctx.request = normalizedClaudeRequest;
        ctx.response = normalizedResponse;
        ctx.rawErrText = await normalizedResponse.text().catch(() => 'unknown error');
      }

      if (!isUnsupportedMediaTypeError(ctx.response.status, ctx.rawErrText)) {
        return null;
      }

      const minimalHeaders = buildMinimalJsonHeadersForCompatibility({
        headers: ctx.request.headers,
        endpoint: ctx.request.endpoint,
        stream: input.isStream,
      });
      const normalizedCurrentHeaders = Object.fromEntries(
        Object.entries(ctx.request.headers).map(([key, value]) => [key.toLowerCase(), value]),
      );
      if (JSON.stringify(minimalHeaders) === JSON.stringify(normalizedCurrentHeaders)) {
        return null;
      }

      const minimalRequest = {
        ...ctx.request,
        headers: minimalHeaders,
      };
      const minimalResponse = await input.dispatchRequest(minimalRequest, ctx.targetUrl);

      if (minimalResponse.ok) {
        return {
          upstream: minimalResponse,
          upstreamPath: minimalRequest.path,
        };
      }

      ctx.request = minimalRequest;
      ctx.response = minimalResponse;
      ctx.rawErrText = await minimalResponse.text().catch(() => 'unknown error');
      return null;
    },
    shouldDowngrade(ctx: EndpointAttemptContext): boolean {
      promoteResponsesCandidateAfterLegacyChatError(input.endpointCandidates, {
        status: ctx.response.status,
        upstreamErrorText: ctx.rawErrText,
        downstreamFormat: input.downstreamFormat,
        sitePlatform: input.sitePlatform,
        modelName: input.modelName,
        requestedModelHint: input.requestedModelHint,
        currentEndpoint: ctx.request.endpoint,
      });
      return (
        ctx.response.status >= 500
        || isEndpointDowngradeError(ctx.response.status, ctx.rawErrText)
        || isMessagesRequiredError(ctx.rawErrText)
        || isEndpointDispatchDeniedError(ctx.response.status, ctx.rawErrText)
      );
    },
  };
}
