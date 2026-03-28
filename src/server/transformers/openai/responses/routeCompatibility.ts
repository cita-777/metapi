import type { Response as UndiciResponse } from 'undici';
import {
  buildMinimalJsonHeadersForCompatibility,
  isEndpointDowngradeError,
  isUnsupportedMediaTypeError,
  type CompatibilityEndpoint,
} from '../../shared/endpointCompatibility.js';
import {
  buildResponsesCompatibilityBodies,
  buildResponsesCompatibilityHeaderCandidates,
  shouldDowngradeResponsesChatToMessages,
  shouldRetryResponsesCompatibility,
} from './compatibility.js';

type CompatibilityRequest = {
  endpoint: CompatibilityEndpoint;
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
};

type EndpointAttemptContext = {
  request: CompatibilityRequest;
  targetUrl: string;
  response: UndiciResponse;
  rawErrText: string;
};

type EndpointRecoverResult = {
  upstream: UndiciResponse;
  upstreamPath: string;
  request?: CompatibilityRequest;
  targetUrl?: string;
} | null;

type UpstreamResponse = Exclude<EndpointRecoverResult, null>['upstream'];

type CreateResponsesEndpointStrategyInput = {
  isStream: boolean;
  requiresNativeResponsesFileUrl: boolean;
  dispatchRequest: (
    request: CompatibilityRequest,
    targetUrl?: string,
  ) => Promise<UpstreamResponse>;
};

export function createResponsesEndpointStrategy(input: CreateResponsesEndpointStrategyInput) {
  return {
    async tryRecover(ctx: EndpointAttemptContext): Promise<EndpointRecoverResult> {
      if (shouldRetryResponsesCompatibility({
        endpoint: ctx.request.endpoint,
        status: ctx.response.status,
        rawErrText: ctx.rawErrText,
      })) {
        const compatibilityBodies = buildResponsesCompatibilityBodies(ctx.request.body);
        const compatibilityHeaders = buildResponsesCompatibilityHeaderCandidates(
          ctx.request.headers,
          input.isStream,
        );

        for (const compatibilityHeadersCandidate of compatibilityHeaders) {
          for (const compatibilityBody of compatibilityBodies) {
            const compatibilityRequest = {
              ...ctx.request,
              headers: compatibilityHeadersCandidate,
              body: compatibilityBody,
            };
            const compatibilityResponse = await input.dispatchRequest(
              compatibilityRequest,
              ctx.targetUrl,
            );
            if (compatibilityResponse.ok) {
              return {
                upstream: compatibilityResponse,
                upstreamPath: compatibilityRequest.path,
              };
            }

            ctx.request = compatibilityRequest;
            ctx.response = compatibilityResponse;
            ctx.rawErrText = await compatibilityResponse.text().catch(() => 'unknown error');
          }
        }
      }

      if (!isUnsupportedMediaTypeError(ctx.response.status, ctx.rawErrText)) {
        return null;
      }

      const minimalRequest = {
        ...ctx.request,
        headers: buildMinimalJsonHeadersForCompatibility({
          headers: ctx.request.headers,
          endpoint: ctx.request.endpoint,
          stream: input.isStream,
        }),
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
      if (input.requiresNativeResponsesFileUrl) return false;
      return (
        ctx.response.status >= 500
        || isEndpointDowngradeError(ctx.response.status, ctx.rawErrText)
        || shouldDowngradeResponsesChatToMessages(
          ctx.request.path,
          ctx.response.status,
          ctx.rawErrText,
        )
      );
    },
  };
}
