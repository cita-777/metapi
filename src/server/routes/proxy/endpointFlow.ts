import { fetch } from 'undici';
import { readRuntimeResponseText } from '../../proxy-core/executors/types.js';
import { withSiteProxyRequestInit } from '../../services/siteProxy.js';
import { summarizeUpstreamError } from './upstreamError.js';
import type { UpstreamEndpoint } from './upstreamEndpoint.js';
import { buildUpstreamUrl } from './upstreamUrl.js';

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

export function withUpstreamPath(path: string, message: string): string {
  return `[upstream:${path}] ${message}`;
}

type ExecuteEndpointFlowInput = {
  siteUrl: string;
  proxyUrl?: string | null;
  endpointCandidates: UpstreamEndpoint[];
  buildRequest: (endpoint: UpstreamEndpoint, endpointIndex: number) => BuiltEndpointRequest;
  dispatchRequest?: (
    request: BuiltEndpointRequest,
    targetUrl: string,
  ) => Promise<Awaited<ReturnType<typeof fetch>>>;
  tryRecover?: (ctx: EndpointAttemptContext) => Promise<EndpointRecoverResult>;
  shouldDowngrade?: (ctx: EndpointAttemptContext) => boolean;
  onDowngrade?: (ctx: EndpointAttemptContext & { errText: string }) => void | Promise<void>;
  onAttemptFailure?: (ctx: EndpointAttemptContext & { errText: string }) => void | Promise<void>;
  onAttemptSuccess?: (ctx: EndpointAttemptSuccessContext) => void | Promise<void>;
};

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

    let response = input.dispatchRequest
      ? await input.dispatchRequest(request, targetUrl)
      : await fetch(targetUrl, await withSiteProxyRequestInit(targetUrl, {
        method: 'POST',
        headers: request.headers,
        body: JSON.stringify(request.body),
      }));

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

    // Normalize again in case recoverer performed additional probes and updated the response text.
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

    const isLastEndpoint = endpointIndex >= endpointCount - 1;
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
