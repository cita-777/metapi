import { fetch } from 'undici';
import { readRuntimeResponseText } from '../executors/types.js';
import { fetchWithObservedFirstByte, isObservedFirstByteTimeoutResponse } from '../firstByteTimeout.js';
import { withSiteProxyRequestInit } from '../../services/siteProxy.js';
import {
  buildUpstreamUrl,
  summarizeUpstreamError,
  type UpstreamEndpoint,
} from './upstreamRequest.js';

export type BuiltEndpointRequest = {
  endpoint: UpstreamEndpoint;
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  runtime?: {
    executor: 'default' | 'codex' | 'gemini-cli' | 'antigravity' | 'claude';
    modelName?: string;
    stream?: boolean;
    oauthProjectId?: string | null;
    action?: 'generateContent' | 'streamGenerateContent' | 'countTokens';
  };
};

export type EndpointAttemptContext = {
  endpointIndex: number;
  endpointCount: number;
  request: BuiltEndpointRequest;
  targetUrl: string;
  response: Awaited<ReturnType<typeof fetch>>;
  rawErrText: string;
  recoverApplied?: boolean;
};

export type EndpointAttemptSuccessContext = {
  endpointIndex: number;
  endpointCount: number;
  request: BuiltEndpointRequest;
  targetUrl: string;
  response: Awaited<ReturnType<typeof fetch>>;
  recoverApplied?: boolean;
};

export type EndpointRecoverResult = {
  upstream: Awaited<ReturnType<typeof fetch>>;
  upstreamPath: string;
  request?: BuiltEndpointRequest;
  targetUrl?: string;
} | null;

export type EndpointFlowResult =
  | {
    ok: true;
    upstream: Awaited<ReturnType<typeof fetch>>;
    upstreamPath: string;
  }
  | {
    ok: false;
    status: number;
    errText: string;
    rawErrText?: string;
  };

export type ExecuteEndpointFlowInput = {
  siteUrl: string;
  proxyUrl?: string | null;
  disableCrossProtocolFallback?: boolean;
  endpointCandidates: UpstreamEndpoint[];
  buildRequest: (endpoint: UpstreamEndpoint, endpointIndex: number) => BuiltEndpointRequest;
  dispatchRequest?: (
    request: BuiltEndpointRequest,
    targetUrl: string,
    signal?: AbortSignal,
  ) => Promise<Awaited<ReturnType<typeof fetch>>>;
  firstByteTimeoutMs?: number;
  tryRecover?: (ctx: EndpointAttemptContext) => Promise<EndpointRecoverResult>;
  shouldDowngrade?: (ctx: EndpointAttemptContext) => boolean;
  shouldAbortRemainingEndpoints?: (ctx: EndpointAttemptContext & { errText: string }) => boolean;
  onDowngrade?: (ctx: EndpointAttemptContext & { errText: string }) => void | Promise<void>;
  onAttemptFailure?: (ctx: EndpointAttemptContext & { errText: string }) => void | Promise<void>;
  onAttemptSuccess?: (ctx: EndpointAttemptSuccessContext) => void | Promise<void>;
};

export function withUpstreamPath(path: string, message: string): string {
  return `[upstream:${path}] ${message}`;
}

async function runEndpointFlowHook<T>(
  hook: ((ctx: T) => void | Promise<void>) | undefined,
  ctx: T,
  hookName: string,
): Promise<void> {
  if (!hook) return;
  try {
    await hook(ctx);
  } catch (error) {
    console.error(`endpointFlow ${hookName} hook failed`, error);
  }
}

export async function executeEndpointFlow(input: ExecuteEndpointFlowInput): Promise<EndpointFlowResult> {
  const endpointCount = input.endpointCandidates.length;
  if (endpointCount <= 0) {
    return {
      ok: false,
      status: 502,
      errText: 'Upstream request failed',
    };
  }

  let finalStatus = 0;
  let finalErrText = 'unknown error';
  let finalRawErrText: string | undefined;

  for (let endpointIndex = 0; endpointIndex < endpointCount; endpointIndex += 1) {
    const endpoint = input.endpointCandidates[endpointIndex] as UpstreamEndpoint;
    const request = input.buildRequest(endpoint, endpointIndex);
    const defaultTarget = buildUpstreamUrl(input.siteUrl, request.path);
    const targetUrl = input.proxyUrl
      ? buildUpstreamUrl(input.proxyUrl, request.path)
      : defaultTarget;

    const attemptStartedAtMs = Date.now();
    let response = await fetchWithObservedFirstByte(
      async (signal) => (
        input.dispatchRequest
          ? await input.dispatchRequest(request, targetUrl, signal)
          : await fetch(targetUrl, await withSiteProxyRequestInit(targetUrl, {
            method: 'POST',
            headers: request.headers,
            body: JSON.stringify(request.body),
            signal,
          }))
      ),
      {
        firstByteTimeoutMs: input.firstByteTimeoutMs,
        startedAtMs: attemptStartedAtMs,
      },
    );

    if (response.ok) {
      await runEndpointFlowHook(input.onAttemptSuccess, {
        endpointIndex,
        endpointCount,
        request,
        targetUrl,
        response,
        recoverApplied: false,
      }, 'onAttemptSuccess');
      return {
        ok: true,
        upstream: response,
        upstreamPath: request.path,
      };
    }

    let rawErrText = await readRuntimeResponseText(response).catch(() => 'unknown error');
    const baseContext: EndpointAttemptContext = {
      endpointIndex,
      endpointCount,
      request,
      targetUrl,
      response,
      rawErrText,
      recoverApplied: false,
    };
    const isLastEndpoint = endpointIndex >= endpointCount - 1;

    if (isObservedFirstByteTimeoutResponse(response) && !isLastEndpoint) {
      const errText = rawErrText.trim() || 'first byte timeout';
      const timeoutContext = {
        ...baseContext,
        errText,
      };
      await runEndpointFlowHook(input.onAttemptFailure, timeoutContext, 'onAttemptFailure');
      finalStatus = response.status || 408;
      finalErrText = errText;
      finalRawErrText = rawErrText;
      if (input.disableCrossProtocolFallback) {
        break;
      }
      continue;
    }

    if (input.tryRecover) {
      const recovered = await input.tryRecover(baseContext);
      baseContext.recoverApplied = recovered !== null
        || baseContext.request !== request
        || baseContext.response !== response
        || baseContext.rawErrText !== rawErrText;
      if (recovered?.upstream?.ok) {
        const recoveredRequest = recovered.request ?? baseContext.request;
        const recoveredTargetUrl = recovered.targetUrl ?? (
          input.proxyUrl
            ? buildUpstreamUrl(input.proxyUrl, recovered.upstreamPath)
            : buildUpstreamUrl(input.siteUrl, recovered.upstreamPath)
        );
        await runEndpointFlowHook(input.onAttemptSuccess, {
          endpointIndex,
          endpointCount,
          request: recoveredRequest,
          targetUrl: recoveredTargetUrl,
          response: recovered.upstream,
          recoverApplied: true,
        }, 'onAttemptSuccess');
        return {
          ok: true,
          upstream: recovered.upstream,
          upstreamPath: recovered.upstreamPath,
        };
      }
    }

    rawErrText = baseContext.rawErrText;
    response = baseContext.response;
    const errText = withUpstreamPath(
      baseContext.request.path,
      summarizeUpstreamError(response.status, rawErrText),
    );
    await runEndpointFlowHook(input.onAttemptFailure, {
      ...baseContext,
      errText,
    }, 'onAttemptFailure');

    if (input.disableCrossProtocolFallback && !isLastEndpoint) {
      finalStatus = response.status;
      finalErrText = errText;
      finalRawErrText = rawErrText;
      break;
    }
    const shouldAbortRemainingEndpoints = !isLastEndpoint && !!input.shouldAbortRemainingEndpoints?.({
      ...baseContext,
      errText,
    });
    if (shouldAbortRemainingEndpoints) {
      finalStatus = response.status;
      finalErrText = errText;
      finalRawErrText = rawErrText;
      break;
    }
    const shouldDowngrade = !isLastEndpoint && !!input.shouldDowngrade?.(baseContext);
    if (shouldDowngrade) {
      await runEndpointFlowHook(input.onDowngrade, {
        ...baseContext,
        errText,
      }, 'onDowngrade');
      continue;
    }

    finalStatus = response.status;
    finalErrText = errText;
    finalRawErrText = rawErrText;
    break;
  }

  return {
    ok: false,
    status: finalStatus || 502,
    errText: finalErrText || 'unknown error',
    rawErrText: finalRawErrText,
  };
}
