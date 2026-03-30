import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { TextDecoder } from 'node:util';
import { fetch } from 'undici';
import { and, eq } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';
import { parseProxyUsage } from '../../services/proxyUsageParser.js';
import { isModelAllowedByPolicyOrAllowedRoutes } from '../../services/downstreamApiKeyService.js';
import { tokenRouter } from '../../services/tokenRouter.js';
import { buildOauthProviderHeaders } from '../../services/oauth/service.js';
import { getOauthInfoFromAccount } from '../../services/oauth/oauthAccount.js';
import { refreshOauthAccessTokenSingleflight } from '../../services/oauth/refreshSingleflight.js';
import { resolveChannelProxyUrl, withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import * as routeRefreshWorkflow from '../../services/routeRefreshWorkflow.js';
import { getDownstreamRoutingPolicy } from '../../routes/proxy/downstreamPolicy.js';
import { executeEndpointFlow, type BuiltEndpointRequest } from '../../routes/proxy/endpointFlow.js';
import { composeProxyLogMessage } from '../../routes/proxy/logPathMeta.js';
import {
  buildUpstreamEndpointRequest,
  resolveUpstreamEndpointCandidates,
} from '../../routes/proxy/upstreamEndpoint.js';
import {
  getUpstreamEndpointRuntimeStateSnapshot,
  recordUpstreamEndpointFailure,
  recordUpstreamEndpointSuccess,
} from '../../services/upstreamEndpointRuntimeMemory.js';
import {
  geminiGenerateContentTransformer,
} from '../../transformers/gemini/generate-content/index.js';
import { createChatEndpointStrategy } from '../../transformers/shared/chatEndpointStrategy.js';
import { normalizeUpstreamFinalResponse } from '../../transformers/shared/normalized.js';
import {
  createGeminiCliStreamReader,
  unwrapGeminiCliPayload,
  wrapGeminiCliRequest,
} from '../../routes/proxy/geminiCliCompat.js';
import { dispatchRuntimeRequest } from '../../routes/proxy/runtimeExecutor.js';
import { detectDownstreamClientContext, type DownstreamClientContext } from '../../routes/proxy/downstreamClientContext.js';
import { insertProxyLog } from '../../services/proxyLogStore.js';
import { summarizeConversationFileInputsInOpenAiBody } from '../capabilities/conversationFileCapabilities.js';
import { readRuntimeResponseText } from '../executors/types.js';
import { canRetryProxyChannel, getProxyMaxChannelRetries } from '../../services/proxyChannelRetry.js';
import {
  buildSurfaceProxyDebugResponseHeaders,
  captureSurfaceProxyDebugSuccessResponseBody,
  parseSurfaceProxyDebugTextPayload,
  reserveSurfaceProxyDebugAttemptBase,
  safeFinalizeSurfaceProxyDebugTrace,
  safeInsertSurfaceProxyDebugAttempt,
  safeUpdateSurfaceProxyDebugAttempt,
  safeUpdateSurfaceProxyDebugCandidates,
  safeUpdateSurfaceProxyDebugSelection,
  startSurfaceProxyDebugTrace,
} from '../../services/proxyDebugTraceRuntime.js';
const GEMINI_MODEL_PROBES = [
  'gemini-2.5-flash',
  'gemini-2.0-flash',
  'gemini-1.5-flash',
  'gemini-pro',
];
const GEMINI_CLI_STATIC_MODELS = [
  { name: 'models/gemini-2.5-pro', displayName: 'Gemini 2.5 Pro' },
  { name: 'models/gemini-2.5-flash', displayName: 'Gemini 2.5 Flash' },
  { name: 'models/gemini-2.5-flash-lite', displayName: 'Gemini 2.5 Flash Lite' },
  { name: 'models/gemini-3-pro-preview', displayName: 'Gemini 3 Pro Preview' },
  { name: 'models/gemini-3.1-pro-preview', displayName: 'Gemini 3.1 Pro Preview' },
  { name: 'models/gemini-3-flash-preview', displayName: 'Gemini 3 Flash Preview' },
  { name: 'models/gemini-3.1-flash-lite-preview', displayName: 'Gemini 3.1 Flash Lite Preview' },
];
const EMPTY_PROXY_USAGE = {
  promptTokens: 0,
  completionTokens: 0,
  totalTokens: 0,
};

function isGeminiCliPlatform(platform: unknown): boolean {
  return String(platform || '').trim().toLowerCase() === 'gemini-cli';
}

function isAntigravityPlatform(platform: unknown): boolean {
  return String(platform || '').trim().toLowerCase() === 'antigravity';
}

function isInternalGeminiPlatform(platform: unknown): boolean {
  return isGeminiCliPlatform(platform) || isAntigravityPlatform(platform);
}

function buildGeminiCliActionPath(input: {
  isStreamAction: boolean;
  isCountTokensAction: boolean;
}) {
  if (input.isCountTokensAction) return '/v1internal:countTokens';
  if (input.isStreamAction) return '/v1internal:streamGenerateContent?alt=sse';
  return '/v1internal:generateContent';
}

function isDirectGeminiFamilyPlatform(platform: unknown): boolean {
  const normalized = String(platform || '').trim().toLowerCase();
  return normalized === 'gemini' || normalized === 'gemini-cli' || normalized === 'antigravity';
}

function omitGeminiCliModelField(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return {};
  const { model: _model, ...rest } = body as Record<string, unknown>;
  return rest;
}

async function selectGeminiChannel(request: FastifyRequest) {
  const policy = getDownstreamRoutingPolicy(request);
  for (const candidate of GEMINI_MODEL_PROBES) {
    const selected = await tokenRouter.selectChannel(candidate, policy);
    if (selected) return selected;
  }
  return null;
}

async function selectNextGeminiProbeChannel(request: FastifyRequest, excludeChannelIds: number[]) {
  const policy = getDownstreamRoutingPolicy(request);
  for (const candidate of GEMINI_MODEL_PROBES) {
    const selected = await tokenRouter.selectNextChannel(candidate, excludeChannelIds, policy);
    if (selected) return selected;
  }
  return null;
}

function resolveDownstreamPath(request: FastifyRequest): string {
  const rawUrl = request.raw.url || request.url || '';
  const withoutQuery = rawUrl.split('?')[0] || rawUrl;
  return withoutQuery || '/v1beta/models';
}

function resolveUpstreamPath(apiVersion: string, modelActionPath: string): string {
  const normalizedVersion = apiVersion.replace(/^\/+/, '');
  const normalizedAction = modelActionPath.replace(/^\/+/, '');
  return `/${normalizedVersion}/${normalizedAction}`;
}

function hasDownstreamModelRestrictions(policy: { supportedModels?: unknown; allowedRouteIds?: unknown; denyAllWhenEmpty?: unknown }): boolean {
  const supportedModels = Array.isArray(policy.supportedModels) ? policy.supportedModels : [];
  const allowedRouteIds = Array.isArray(policy.allowedRouteIds) ? policy.allowedRouteIds : [];
  return supportedModels.length > 0 || allowedRouteIds.length > 0 || policy.denyAllWhenEmpty === true;
}

function extractGeminiListedModelName(item: unknown): string {
  if (!item || typeof item !== 'object') return '';
  const rawName = typeof (item as { name?: unknown }).name === 'string'
    ? (item as { name: string }).name.trim()
    : '';
  if (!rawName) return '';
  return rawName.startsWith('models/') ? rawName.slice('models/'.length) : rawName;
}

async function filterGeminiListedModelsForPolicy(
  payload: unknown,
  request: FastifyRequest,
): Promise<unknown> {
  if (!payload || typeof payload !== 'object' || !Array.isArray((payload as { models?: unknown[] }).models)) {
    return payload;
  }

  const policy = getDownstreamRoutingPolicy(request);
  if (!hasDownstreamModelRestrictions(policy)) {
    return payload;
  }

  const filteredModels: unknown[] = [];
  for (const item of (payload as { models: unknown[] }).models) {
    const modelName = extractGeminiListedModelName(item);
    if (!modelName) continue;
    if (!await isModelAllowedByPolicyOrAllowedRoutes(modelName, policy)) continue;
    const decision = await tokenRouter.explainSelection?.(modelName, [], policy);
    if (decision && typeof decision.selectedChannelId !== 'number') continue;
    filteredModels.push(item);
  }

  return {
    ...(payload as Record<string, unknown>),
    models: filteredModels,
  };
}

async function readRouteAwareGeminiModels(request: FastifyRequest): Promise<Array<{ name: string; displayName: string }>> {
  const policy = getDownstreamRoutingPolicy(request);
  const rows = await db.select({ modelName: schema.modelAvailability.modelName })
    .from(schema.modelAvailability)
    .innerJoin(schema.accounts, eq(schema.modelAvailability.accountId, schema.accounts.id))
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(and(
      eq(schema.modelAvailability.available, true),
      eq(schema.accounts.status, 'active'),
      eq(schema.sites.status, 'active'),
    ))
    .all();
  const routeAliases = await db.select({ displayName: schema.tokenRoutes.displayName })
    .from(schema.tokenRoutes)
    .where(eq(schema.tokenRoutes.enabled, true))
    .all();
  const deduped = Array.from(new Set([
    ...rows.map((row) => String(row.modelName || '').trim()).filter(Boolean),
    ...routeAliases.map((row) => String(row.displayName || '').trim()).filter(Boolean),
  ])).sort();

  const allowed: Array<{ name: string; displayName: string }> = [];
  for (const modelName of deduped) {
    if (!await isModelAllowedByPolicyOrAllowedRoutes(modelName, policy)) continue;
    const decision = await tokenRouter.explainSelection?.(modelName, [], policy);
    if (decision && typeof decision.selectedChannelId !== 'number') continue;
    allowed.push({
      name: `models/${modelName}`,
      displayName: modelName,
    });
  }

  return allowed;
}

async function logProxy(
  selected: any,
  modelRequested: string,
  status: string,
  httpStatus: number,
  latencyMs: number,
  errorMessage: string | null,
  retryCount: number,
  downstreamPath: string,
  upstreamPath: string | null,
  clientContext: DownstreamClientContext | null = null,
  promptTokens = 0,
  completionTokens = 0,
  totalTokens = 0,
) {
  try {
    const createdAt = formatUtcSqlDateTime(new Date());
    const normalizedErrorMessage = composeProxyLogMessage({
      clientKind: clientContext?.clientKind && clientContext.clientKind !== 'generic'
        ? clientContext.clientKind
        : null,
      sessionId: clientContext?.sessionId || null,
      traceHint: clientContext?.traceHint || null,
      downstreamPath,
      upstreamPath,
      errorMessage,
    });
    await insertProxyLog({
      routeId: selected.channel.routeId,
      channelId: selected.channel.id,
      accountId: selected.account.id,
      modelRequested,
      modelActual: selected.actualModel || modelRequested,
      status,
      httpStatus,
      latencyMs,
      promptTokens,
      completionTokens,
      totalTokens,
      estimatedCost: 0,
      clientFamily: clientContext?.clientKind || null,
      clientAppId: clientContext?.clientAppId || null,
      clientAppName: clientContext?.clientAppName || null,
      clientConfidence: clientContext?.clientConfidence || null,
      errorMessage: normalizedErrorMessage,
      retryCount,
      createdAt,
    });
  } catch (error) {
    console.warn('[proxy/gemini] failed to write proxy log', error);
  }
}

async function recordGeminiChannelSuccessBestEffort(
  channelId: number,
  latencyMs: number,
  modelName: string,
): Promise<void> {
  try {
    await tokenRouter.recordSuccess?.(channelId, latencyMs, 0, modelName);
  } catch (error) {
    console.warn('[proxy/gemini] failed to record channel success', error);
  }
}

export async function geminiProxyRoute(app: FastifyInstance) {
  const listModels = async (request: FastifyRequest, reply: FastifyReply) => {
    const apiVersion = geminiGenerateContentTransformer.resolveProxyApiVersion(
      request.params as { geminiApiVersion?: string } | undefined,
    );
    const downstreamPath = resolveDownstreamPath(request);
    const clientContext = detectDownstreamClientContext({
      downstreamPath,
      headers: request.headers as Record<string, unknown>,
    });
    const debugTrace = await startSurfaceProxyDebugTrace({
      downstreamPath,
      clientKind: clientContext.clientKind,
      sessionId: clientContext.sessionId || null,
      traceHint: clientContext.traceHint || null,
      requestedModel: null,
      requestHeaders: request.headers as Record<string, unknown>,
      requestBody: null,
    });
    const finalizeDebugFailure = async (status: number, payload: unknown, upstreamPath: string | null = null) => {
      await safeFinalizeSurfaceProxyDebugTrace(debugTrace, {
        finalStatus: 'failed',
        finalHttpStatus: status,
        finalUpstreamPath: upstreamPath,
        finalResponseHeaders: {
          'content-type': 'application/json',
        },
        finalResponseBody: payload,
      });
    };
    const finalizeDebugSuccess = async (status: number, upstreamPath: string | null, responseHeaders: unknown, responseBody: unknown) => {
      await safeFinalizeSurfaceProxyDebugTrace(debugTrace, {
        finalStatus: 'success',
        finalHttpStatus: status,
        finalUpstreamPath: upstreamPath,
        finalResponseHeaders: responseHeaders as Record<string, unknown> | null,
        finalResponseBody: responseBody,
      });
    };
    const excludeChannelIds: number[] = [];
    let retryCount = 0;
    let lastStatus = 503;
    let lastText = 'No available channels for Gemini models';
    let lastContentType = 'application/json';

    while (retryCount <= getProxyMaxChannelRetries()) {
      const selected = retryCount === 0
        ? await selectGeminiChannel(request)
        : await selectNextGeminiProbeChannel(request, excludeChannelIds);
      if (!selected) {
        await finalizeDebugFailure(lastStatus, lastText, null);
        return reply.code(lastStatus).type(lastContentType).send(lastText);
      }

      excludeChannelIds.push(selected.channel.id);
      await safeUpdateSurfaceProxyDebugSelection(debugTrace, {
        stickySessionKey: null,
        stickyHitChannelId: null,
        selectedChannelId: selected.channel.id,
        selectedRouteId: selected.channel.routeId ?? null,
        selectedAccountId: selected.account.id,
        selectedSiteId: selected.site.id,
        selectedSitePlatform: selected.site.platform,
      });

      try {
        if (!isDirectGeminiFamilyPlatform(selected.site.platform)) {
          let models = await readRouteAwareGeminiModels(request);
          if (models.length <= 0) {
            await routeRefreshWorkflow.refreshModelsAndRebuildRoutes();
            models = await readRouteAwareGeminiModels(request);
          }
          await safeUpdateSurfaceProxyDebugCandidates(debugTrace, {
            decisionSummary: {
              retryCount,
              pathKind: 'route-aware-gemini-models',
            },
          });
          await finalizeDebugSuccess(200, null, { 'content-type': 'application/json' }, { models });
          return reply.code(200).send({ models });
        }

        if (isGeminiCliPlatform(selected.site.platform)) {
          const filtered = await filterGeminiListedModelsForPolicy(
            { models: GEMINI_CLI_STATIC_MODELS },
            request,
          );
          await safeUpdateSurfaceProxyDebugCandidates(debugTrace, {
            decisionSummary: {
              retryCount,
              pathKind: 'gemini-cli-static-models',
            },
          });
          await finalizeDebugSuccess(200, null, { 'content-type': 'application/json' }, filtered);
          return reply.code(200).send(filtered);
        }

        const targetUrl = geminiGenerateContentTransformer.resolveModelsUrl(selected.site.url, apiVersion, selected.tokenValue);
        const upstreamPath = `/${apiVersion}/models`;
        const upstream = await fetch(
          targetUrl,
          { method: 'GET' },
        );
        const text = await readRuntimeResponseText(upstream);
        await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
          attemptIndex: retryCount,
          endpoint: 'gemini-models',
          requestPath: upstreamPath,
          targetUrl,
          runtimeExecutor: 'default',
          requestHeaders: null,
          requestBody: null,
          responseStatus: upstream.status,
          responseHeaders: buildSurfaceProxyDebugResponseHeaders(upstream),
          responseBody: parseSurfaceProxyDebugTextPayload(text),
          rawErrorText: upstream.ok ? null : text,
          recoverApplied: false,
          downgradeDecision: false,
          downgradeReason: null,
          memoryWrite: null,
        });
        if (!upstream.ok) {
          lastStatus = upstream.status;
          lastText = text;
          lastContentType = upstream.headers.get('content-type') || 'application/json';
          await tokenRouter.recordFailure?.(selected.channel.id, {
            status: upstream.status,
            errorText: text,
          });
          if (canRetryProxyChannel(retryCount)) {
            retryCount += 1;
            continue;
          }
          await finalizeDebugFailure(lastStatus, parseSurfaceProxyDebugTextPayload(lastText), upstreamPath);
          return reply.code(lastStatus).type(lastContentType).send(lastText);
        }

        try {
          const parsed = JSON.parse(text);
          const filtered = await filterGeminiListedModelsForPolicy(parsed, request);
          await finalizeDebugSuccess(upstream.status, upstreamPath, buildSurfaceProxyDebugResponseHeaders(upstream), filtered);
          return reply.code(upstream.status).send(filtered);
        } catch {
          await finalizeDebugSuccess(upstream.status, upstreamPath, buildSurfaceProxyDebugResponseHeaders(upstream), text);
          return reply.code(upstream.status).type(upstream.headers.get('content-type') || 'application/json').send(text);
        }
      } catch (error) {
        await tokenRouter.recordFailure?.(selected.channel.id, {
          errorText: error instanceof Error ? error.message : 'Gemini upstream request failed',
        });
        lastStatus = 502;
        lastContentType = 'application/json';
        lastText = JSON.stringify({
          error: {
            message: error instanceof Error ? error.message : 'Gemini upstream request failed',
            type: 'upstream_error',
          },
        });
        if (canRetryProxyChannel(retryCount)) {
          retryCount += 1;
          continue;
        }
        await finalizeDebugFailure(lastStatus, parseSurfaceProxyDebugTextPayload(lastText), null);
        return reply.code(lastStatus).type(lastContentType).send(lastText);
      }
    }
  };

  const handleGenerateContent = async (
    request: FastifyRequest,
    reply: FastifyReply,
    options?: {
      downstreamProtocol?: 'gemini' | 'gemini-cli';
      action?: 'generateContent' | 'streamGenerateContent' | 'countTokens';
    },
  ) => {
    const downstreamProtocol = options?.downstreamProtocol || 'gemini';
    const isGeminiCliDownstream = downstreamProtocol === 'gemini-cli';
    const cliRequestedModel = isGeminiCliDownstream
      ? (typeof (request.body as Record<string, unknown> | null | undefined)?.model === 'string'
        ? String((request.body as Record<string, unknown>).model).trim()
        : '')
      : '';
    const parsedPath = isGeminiCliDownstream
      ? {
        apiVersion: 'v1beta',
        modelActionPath: `models/${cliRequestedModel}:${options?.action || 'generateContent'}`,
        isStreamAction: options?.action === 'streamGenerateContent',
        requestedModel: cliRequestedModel,
      }
      : geminiGenerateContentTransformer.parseProxyRequestPath({
        rawUrl: request.raw.url || request.url || '',
        params: request.params as { geminiApiVersion?: string } | undefined,
      });
    const { apiVersion, modelActionPath, isStreamAction, requestedModel } = parsedPath;
    const isCountTokensAction = isGeminiCliDownstream
      ? options?.action === 'countTokens'
      : modelActionPath.endsWith(':countTokens');
    const rawUrl = request.raw.url || request.url || '';
    const wantsSseEnvelope = (
      isStreamAction
      && (isGeminiCliDownstream || /(?:^|[?&])alt=sse(?:&|$)/i.test(rawUrl))
    );
    if (!requestedModel) {
      return reply.code(400).send({
        error: { message: 'Gemini model path is required', type: 'invalid_request_error' },
      });
    }

    const policy = getDownstreamRoutingPolicy(request);
    const downstreamPath = resolveDownstreamPath(request);
    const clientContext = detectDownstreamClientContext({
      downstreamPath,
      headers: request.headers as Record<string, unknown>,
      body: request.body,
    });
    const debugTrace = await startSurfaceProxyDebugTrace({
      downstreamPath,
      clientKind: clientContext.clientKind,
      sessionId: clientContext.sessionId || null,
      traceHint: clientContext.traceHint || null,
      requestedModel,
      requestHeaders: request.headers as Record<string, unknown>,
      requestBody: request.body,
    });
    const finalizeDebugFailure = async (status: number, payload: unknown, upstreamPath: string | null = null) => {
      await safeFinalizeSurfaceProxyDebugTrace(debugTrace, {
        finalStatus: 'failed',
        finalHttpStatus: status,
        finalUpstreamPath: upstreamPath,
        finalResponseHeaders: {
          'content-type': 'application/json',
        },
        finalResponseBody: payload,
      });
    };
    const finalizeDebugSuccess = async (status: number, upstreamPath: string | null, responseHeaders: unknown, responseBody: unknown) => {
      await safeFinalizeSurfaceProxyDebugTrace(debugTrace, {
        finalStatus: 'success',
        finalHttpStatus: status,
        finalUpstreamPath: upstreamPath,
        finalResponseHeaders: responseHeaders as Record<string, unknown> | null,
        finalResponseBody: responseBody,
      });
    };
    const excludeChannelIds: number[] = [];
    let retryCount = 0;
    let lastStatus = 503;
    let lastText = 'No available channels for this model';
    let lastContentType = 'application/json';

    while (retryCount <= getProxyMaxChannelRetries()) {
      const selected = retryCount === 0
        ? await tokenRouter.selectChannel(requestedModel, policy)
        : await tokenRouter.selectNextChannel(requestedModel, excludeChannelIds, policy);
      if (!selected) {
        await finalizeDebugFailure(lastStatus, parseSurfaceProxyDebugTextPayload(lastText), null);
        return reply.code(lastStatus).type(lastContentType).send(lastText);
      }

      excludeChannelIds.push(selected.channel.id);
      await safeUpdateSurfaceProxyDebugSelection(debugTrace, {
        stickySessionKey: null,
        stickyHitChannelId: null,
        selectedChannelId: selected.channel.id,
        selectedRouteId: selected.channel.routeId ?? null,
        selectedAccountId: selected.account.id,
        selectedSiteId: selected.site.id,
        selectedSitePlatform: selected.site.platform,
      });

      const actualModel = selected.actualModel || requestedModel;
      const normalizedBody = geminiGenerateContentTransformer.inbound.normalizeRequest(
        isGeminiCliDownstream ? omitGeminiCliModelField(request.body) : (request.body || {}),
        actualModel,
      );
      let oauth = getOauthInfoFromAccount(selected.account);
      const isGeminiCli = isGeminiCliPlatform(selected.site.platform);
      const isInternalGemini = isInternalGeminiPlatform(selected.site.platform);
      const isDirectGeminiFamily = isDirectGeminiFamilyPlatform(selected.site.platform);
      const startTime = Date.now();
      let upstreamPath = '';

      try {
        if (isDirectGeminiFamily) {
          await safeUpdateSurfaceProxyDebugCandidates(debugTrace, {
            decisionSummary: {
              retryCount,
              pathKind: 'direct-gemini-family',
              isGeminiCli,
              isInternalGemini,
              isCountTokensAction,
              isStreamAction,
            },
          });
          if (isGeminiCli && !oauth?.projectId) {
            lastStatus = 500;
            lastContentType = 'application/json';
            lastText = JSON.stringify({
              error: {
                message: 'Gemini CLI OAuth project is missing',
                type: 'server_error',
              },
            });
            await tokenRouter.recordFailure?.(selected.channel.id, {
              status: 500,
              errorText: 'Gemini CLI OAuth project is missing',
            });
            if (canRetryProxyChannel(retryCount)) {
              retryCount += 1;
              continue;
            }
            await finalizeDebugFailure(lastStatus, parseSurfaceProxyDebugTextPayload(lastText), upstreamPath || null);
            return reply.code(lastStatus).type(lastContentType).send(lastText);
          }

          const actualModelAction = modelActionPath.replace(
            /^models\/[^:]+/,
            `models/${actualModel}`,
          );
          upstreamPath = isInternalGemini
            ? buildGeminiCliActionPath({ isStreamAction, isCountTokensAction })
            : resolveUpstreamPath(apiVersion, actualModelAction);
          const query = new URLSearchParams(request.query as Record<string, string>).toString();
          const channelProxyUrl = resolveChannelProxyUrl(selected.site, selected.account.extraConfig);
          const buildDirectDispatchState = () => {
            const requestBody = isInternalGemini
              ? (
                isCountTokensAction
                  ? { request: normalizedBody }
                  : wrapGeminiCliRequest({
                    modelName: actualModel,
                    projectId: oauth?.projectId || '',
                    request: normalizedBody as Record<string, unknown>,
                  })
              )
              : normalizedBody;
            const requestHeaders = isInternalGemini
              ? {
                'Content-Type': 'application/json',
                ...(isStreamAction ? { Accept: 'text/event-stream' } : {}),
                Authorization: `Bearer ${selected.tokenValue}`,
                ...buildOauthProviderHeaders({
                  account: selected.account,
                  downstreamHeaders: request.headers as Record<string, unknown>,
                }),
              }
              : {
                'Content-Type': 'application/json',
              };
            const targetUrl = isInternalGemini
              ? `${selected.site.url}${upstreamPath}`
              : geminiGenerateContentTransformer.resolveActionUrl(
                selected.site.url,
                apiVersion,
                actualModelAction,
                selected.tokenValue,
                query,
              );
            const runtimeExecutor = isInternalGemini
              ? (isGeminiCli ? 'gemini-cli' : 'antigravity')
              : 'default';

            return {
              requestBody,
              requestHeaders,
              targetUrl,
              runtimeExecutor,
              dispatch: () => (
                isInternalGemini
                  ? dispatchRuntimeRequest({
                    siteUrl: selected.site.url,
                    targetUrl,
                    request: {
                      endpoint: 'chat',
                      path: upstreamPath,
                      headers: requestHeaders,
                      body: requestBody as Record<string, unknown>,
                      runtime: {
                        executor: isGeminiCli ? 'gemini-cli' : 'antigravity',
                        modelName: actualModel,
                        stream: isStreamAction,
                        oauthProjectId: oauth?.projectId || null,
                        action: isCountTokensAction
                          ? 'countTokens'
                          : (isStreamAction ? 'streamGenerateContent' : 'generateContent'),
                      },
                    },
                    buildInit: async (_requestUrl, requestForFetch) => withSiteRecordProxyRequestInit(selected.site, {
                      method: 'POST',
                      headers: requestForFetch.headers,
                      body: JSON.stringify(requestForFetch.body),
                    }, channelProxyUrl),
                  })
                  : fetch(targetUrl, {
                    method: 'POST',
                    headers: requestHeaders,
                    body: JSON.stringify(requestBody),
                  })
              ),
            };
          };

          let directDispatchState = buildDirectDispatchState();
          let upstream = await directDispatchState.dispatch();
          let contentType = upstream.headers.get('content-type') || 'application/json';
          let recoverApplied = false;
          if (upstream.status === 401 && oauth) {
            try {
              const refreshed = await refreshOauthAccessTokenSingleflight(selected.account.id);
              selected.tokenValue = refreshed.accessToken;
              selected.account = {
                ...selected.account,
                accessToken: refreshed.accessToken,
                extraConfig: refreshed.extraConfig ?? selected.account.extraConfig,
              };
              oauth = getOauthInfoFromAccount(selected.account);
              directDispatchState = buildDirectDispatchState();
              upstream = await directDispatchState.dispatch();
              contentType = upstream.headers.get('content-type') || 'application/json';
              recoverApplied = true;
            } catch {
              // Preserve the original 401 response when refresh fails.
            }
          }
          if (!upstream.ok) {
            lastStatus = upstream.status;
            lastContentType = contentType;
            lastText = await readRuntimeResponseText(upstream);
            await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
              attemptIndex: retryCount,
              endpoint: isInternalGemini ? 'gemini-internal' : 'gemini-native',
              requestPath: upstreamPath,
              targetUrl: directDispatchState.targetUrl,
              runtimeExecutor: directDispatchState.runtimeExecutor,
              requestHeaders: directDispatchState.requestHeaders,
              requestBody: directDispatchState.requestBody,
              responseStatus: upstream.status,
              responseHeaders: buildSurfaceProxyDebugResponseHeaders(upstream),
              responseBody: parseSurfaceProxyDebugTextPayload(lastText),
              rawErrorText: lastText,
              recoverApplied,
              downgradeDecision: false,
              downgradeReason: null,
              memoryWrite: null,
            });
            await tokenRouter.recordFailure?.(selected.channel.id, {
              status: upstream.status,
              errorText: lastText,
            });
            await logProxy(
              selected,
              requestedModel,
              'failed',
              lastStatus,
              Date.now() - startTime,
              lastText,
              retryCount,
              downstreamPath,
              upstreamPath,
              clientContext,
            );
            if (canRetryProxyChannel(retryCount)) {
              retryCount += 1;
              continue;
            }

            try {
              await finalizeDebugFailure(lastStatus, JSON.parse(lastText), upstreamPath);
              return reply.code(lastStatus).send(JSON.parse(lastText));
            } catch {
              await finalizeDebugFailure(lastStatus, lastText, upstreamPath);
              return reply.code(lastStatus).type(lastContentType).send(lastText);
            }
          }

          if (geminiGenerateContentTransformer.stream.isSseContentType(contentType)) {
            const upstreamReader = upstream.body?.getReader();
            const reader = isInternalGemini && !isGeminiCliDownstream && upstreamReader
              ? createGeminiCliStreamReader(upstreamReader)
              : upstreamReader;
            const captureStreamChunks = debugTrace?.options.captureStreamChunks === true;
            if (!reader) {
              const latency = Date.now() - startTime;
              const responseBody = captureStreamChunks
                ? ''
                : { stream: true, usage: EMPTY_PROXY_USAGE };
              await recordGeminiChannelSuccessBestEffort(selected.channel.id, latency, actualModel);
              await logProxy(
                selected,
                requestedModel,
                'success',
                upstream.status,
                latency,
                null,
                retryCount,
                downstreamPath,
                upstreamPath,
                clientContext,
              );
              await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
                attemptIndex: retryCount,
                endpoint: isInternalGemini ? 'gemini-internal' : 'gemini-native',
                requestPath: upstreamPath,
                targetUrl: directDispatchState.targetUrl,
                runtimeExecutor: directDispatchState.runtimeExecutor,
                requestHeaders: directDispatchState.requestHeaders,
                requestBody: directDispatchState.requestBody,
                responseStatus: upstream.status,
                responseHeaders: buildSurfaceProxyDebugResponseHeaders(upstream),
                responseBody,
                rawErrorText: null,
                recoverApplied,
                downgradeDecision: false,
                downgradeReason: null,
                memoryWrite: null,
              });
              await finalizeDebugSuccess(
                upstream.status,
                upstreamPath,
                buildSurfaceProxyDebugResponseHeaders(upstream),
                responseBody,
              );
              return reply.code(upstream.status).type(contentType || 'text/event-stream').send('');
            }
            reply.hijack();
            reply.raw.statusCode = upstream.status;
            reply.raw.setHeader('Content-Type', contentType || 'text/event-stream');
            const aggregateState = geminiGenerateContentTransformer.stream.createAggregateState();
            const decoder = new TextDecoder();
            let rest = '';
            let rawStreamText = '';
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (!value) continue;
                const chunkText = decoder.decode(value, { stream: true });
                if (captureStreamChunks) {
                  rawStreamText += chunkText;
                }
                const consumed = geminiGenerateContentTransformer.stream.consumeUpstreamSseBuffer(
                  aggregateState,
                  rest + chunkText,
                );
                rest = consumed.rest;
                for (const line of consumed.lines) {
                  reply.raw.write(line);
                }
              }
              const tail = decoder.decode();
              if (tail) {
                if (captureStreamChunks) {
                  rawStreamText += tail;
                }
                const consumed = geminiGenerateContentTransformer.stream.consumeUpstreamSseBuffer(
                  aggregateState,
                  rest + tail,
                );
                for (const line of consumed.lines) {
                  reply.raw.write(line);
                }
              }
              const parsedUsage = parseProxyUsage(aggregateState);
              const latency = Date.now() - startTime;
              const responseBody = captureStreamChunks
                ? rawStreamText
                : { stream: true, usage: parsedUsage };
              await recordGeminiChannelSuccessBestEffort(selected.channel.id, latency, actualModel);
              await logProxy(
                selected,
                requestedModel,
                'success',
                upstream.status,
                latency,
                null,
                retryCount,
                downstreamPath,
                upstreamPath,
                clientContext,
                parsedUsage.promptTokens,
                parsedUsage.completionTokens,
                parsedUsage.totalTokens,
              );
              await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
                attemptIndex: retryCount,
                endpoint: isInternalGemini ? 'gemini-internal' : 'gemini-native',
                requestPath: upstreamPath,
                targetUrl: directDispatchState.targetUrl,
                runtimeExecutor: directDispatchState.runtimeExecutor,
                requestHeaders: directDispatchState.requestHeaders,
                requestBody: directDispatchState.requestBody,
                responseStatus: upstream.status,
                responseHeaders: buildSurfaceProxyDebugResponseHeaders(upstream),
                responseBody,
                rawErrorText: null,
                recoverApplied,
                downgradeDecision: false,
                downgradeReason: null,
                memoryWrite: null,
              });
              await finalizeDebugSuccess(
                upstream.status,
                upstreamPath,
                buildSurfaceProxyDebugResponseHeaders(upstream),
                responseBody,
              );
              return;
            } catch (error) {
              const latency = Date.now() - startTime;
              const errorMessage = error instanceof Error
                ? error.message
                : 'Gemini upstream stream failed';
              const parsedUsage = parseProxyUsage(aggregateState);
              const responseBody = captureStreamChunks
                ? rawStreamText
                : { stream: true, usage: parsedUsage, error: errorMessage };
              await tokenRouter.recordFailure?.(selected.channel.id, {
                status: 502,
                errorText: errorMessage,
              });
              await logProxy(
                selected,
                requestedModel,
                'failed',
                502,
                latency,
                errorMessage,
                retryCount,
                downstreamPath,
                upstreamPath,
                clientContext,
                parsedUsage.promptTokens,
                parsedUsage.completionTokens,
                parsedUsage.totalTokens,
              );
              await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
                attemptIndex: retryCount,
                endpoint: isInternalGemini ? 'gemini-internal' : 'gemini-native',
                requestPath: upstreamPath,
                targetUrl: directDispatchState.targetUrl,
                runtimeExecutor: directDispatchState.runtimeExecutor,
                requestHeaders: directDispatchState.requestHeaders,
                requestBody: directDispatchState.requestBody,
                responseStatus: upstream.status,
                responseHeaders: buildSurfaceProxyDebugResponseHeaders(upstream),
                responseBody,
                rawErrorText: errorMessage,
                recoverApplied,
                downgradeDecision: false,
                downgradeReason: null,
                memoryWrite: null,
              });
              await safeFinalizeSurfaceProxyDebugTrace(debugTrace, {
                finalStatus: 'failed',
                finalHttpStatus: upstream.status,
                finalUpstreamPath: upstreamPath,
                finalResponseHeaders: buildSurfaceProxyDebugResponseHeaders(upstream),
                finalResponseBody: responseBody,
              });
              return;
            } finally {
              reader.releaseLock();
              reply.raw.end();
            }
          }

          const text = await readRuntimeResponseText(upstream);
          const aggregateState = geminiGenerateContentTransformer.stream.createAggregateState();
          let parsedUsage = EMPTY_PROXY_USAGE;
          try {
            const parsed = JSON.parse(text);
            const unwrappedPayload = isInternalGemini && !isGeminiCliDownstream
              ? unwrapGeminiCliPayload(parsed)
              : parsed;
            const responsePayload = isCountTokensAction
              ? unwrappedPayload
              : geminiGenerateContentTransformer.stream.serializeUpstreamJsonPayload(
                aggregateState,
                unwrappedPayload,
                isStreamAction,
              );
            parsedUsage = parseProxyUsage(aggregateState);
            const latency = Date.now() - startTime;
            await recordGeminiChannelSuccessBestEffort(selected.channel.id, latency, actualModel);
            await logProxy(
              selected,
              requestedModel,
              'success',
              upstream.status,
              latency,
              null,
              retryCount,
              downstreamPath,
              upstreamPath,
              clientContext,
              parsedUsage.promptTokens,
              parsedUsage.completionTokens,
              parsedUsage.totalTokens,
            );
            await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
              attemptIndex: retryCount,
              endpoint: isInternalGemini ? 'gemini-internal' : 'gemini-native',
              requestPath: upstreamPath,
              targetUrl: directDispatchState.targetUrl,
              runtimeExecutor: directDispatchState.runtimeExecutor,
              requestHeaders: directDispatchState.requestHeaders,
              requestBody: directDispatchState.requestBody,
              responseStatus: upstream.status,
              responseHeaders: buildSurfaceProxyDebugResponseHeaders(upstream),
              responseBody: responsePayload,
              rawErrorText: null,
              recoverApplied,
              downgradeDecision: false,
              downgradeReason: null,
              memoryWrite: null,
            });
            await finalizeDebugSuccess(
              upstream.status,
              upstreamPath,
              buildSurfaceProxyDebugResponseHeaders(upstream),
              isGeminiCliDownstream && !isCountTokensAction
                ? { response: responsePayload }
                : responsePayload,
            );
            return reply.code(upstream.status).send(
              isGeminiCliDownstream && !isCountTokensAction
                ? { response: responsePayload }
                : responsePayload,
            );
          } catch {
            const latency = Date.now() - startTime;
            await recordGeminiChannelSuccessBestEffort(selected.channel.id, latency, actualModel);
            await logProxy(
              selected,
              requestedModel,
              'success',
              upstream.status,
              latency,
              null,
              retryCount,
              downstreamPath,
              upstreamPath,
              clientContext,
            );
            await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
              attemptIndex: retryCount,
              endpoint: isInternalGemini ? 'gemini-internal' : 'gemini-native',
              requestPath: upstreamPath,
              targetUrl: directDispatchState.targetUrl,
              runtimeExecutor: directDispatchState.runtimeExecutor,
              requestHeaders: directDispatchState.requestHeaders,
              requestBody: directDispatchState.requestBody,
              responseStatus: upstream.status,
              responseHeaders: buildSurfaceProxyDebugResponseHeaders(upstream),
              responseBody: text,
              rawErrorText: null,
              recoverApplied,
              downgradeDecision: false,
              downgradeReason: null,
              memoryWrite: null,
            });
            await finalizeDebugSuccess(
              upstream.status,
              upstreamPath,
              buildSurfaceProxyDebugResponseHeaders(upstream),
              text,
            );
            return reply.code(upstream.status).type(contentType || 'application/json').send(text);
          }
        }

        if (isCountTokensAction) {
          lastStatus = 501;
          lastContentType = 'application/json';
          lastText = JSON.stringify({
            error: {
              message: 'Gemini countTokens compatibility is not implemented for this upstream',
              type: 'invalid_request_error',
            },
          });
          await safeUpdateSurfaceProxyDebugCandidates(debugTrace, {
            decisionSummary: {
              retryCount,
              pathKind: 'gemini-compat-count-tokens-unsupported',
            },
          });
          await finalizeDebugFailure(lastStatus, parseSurfaceProxyDebugTextPayload(lastText), null);
          return reply.code(lastStatus).type(lastContentType).send(lastText);
        }

        const openAiBody = geminiGenerateContentTransformer.compatibility.buildOpenAiBodyFromGeminiRequest({
          body: normalizedBody as Record<string, unknown>,
          modelName: actualModel,
          stream: isStreamAction,
        });
        const conversationFileSummary = summarizeConversationFileInputsInOpenAiBody(openAiBody);
        const hasNonImageFileInput = conversationFileSummary.hasDocument;
        const endpointCandidates = await resolveUpstreamEndpointCandidates(
          {
            site: selected.site,
            account: selected.account,
          },
          actualModel,
          'openai',
          requestedModel,
          {
            hasNonImageFileInput,
            conversationFileSummary,
          },
        );
        const endpointRuntimeContext = {
          siteId: selected.site.id,
          modelName: actualModel,
          downstreamFormat: 'openai' as const,
          requestedModelHint: requestedModel,
          requestCapabilities: {
            hasNonImageFileInput,
            conversationFileSummary,
          },
        };
        await safeUpdateSurfaceProxyDebugCandidates(debugTrace, {
          endpointCandidates,
          endpointRuntimeState: getUpstreamEndpointRuntimeStateSnapshot(endpointRuntimeContext),
          decisionSummary: {
            retryCount,
            pathKind: 'gemini-compat-openai',
            isStreamAction,
            downstreamProtocol,
          },
        });
        const buildEndpointRequest = (
          endpoint: 'chat' | 'messages' | 'responses',
          requestOptions: { forceNormalizeClaudeBody?: boolean } = {},
        ) => {
          const endpointRequest = buildUpstreamEndpointRequest({
            endpoint,
            modelName: actualModel,
            stream: isStreamAction,
            tokenValue: selected.tokenValue,
            oauthProvider: oauth?.provider,
            oauthProjectId: oauth?.projectId,
            sitePlatform: selected.site.platform,
            siteUrl: selected.site.url,
            openaiBody: openAiBody,
            downstreamFormat: 'openai',
            forceNormalizeClaudeBody: requestOptions.forceNormalizeClaudeBody,
            downstreamHeaders: request.headers as Record<string, unknown>,
            providerHeaders: buildOauthProviderHeaders({
              account: selected.account,
              downstreamHeaders: request.headers as Record<string, unknown>,
            }),
          });
          return {
            endpoint,
            path: endpointRequest.path,
            headers: endpointRequest.headers,
            body: endpointRequest.body as Record<string, unknown>,
            runtime: endpointRequest.runtime,
          };
        };
        const channelProxyUrl = resolveChannelProxyUrl(selected.site, selected.account.extraConfig);
        const dispatchRequest = (compatibilityRequest: BuiltEndpointRequest, targetUrl?: string) => (
          dispatchRuntimeRequest({
            siteUrl: selected.site.url,
            targetUrl,
            request: compatibilityRequest,
            buildInit: async (_requestUrl, requestForFetch) => withSiteRecordProxyRequestInit(selected.site, {
              method: 'POST',
              headers: requestForFetch.headers,
              body: JSON.stringify(requestForFetch.body),
            }, channelProxyUrl),
          })
        );
        const endpointStrategy = createChatEndpointStrategy({
          downstreamFormat: 'openai',
          endpointCandidates,
          modelName: actualModel,
          requestedModelHint: requestedModel,
          sitePlatform: selected.site.platform,
          isStream: isStreamAction,
          buildRequest: ({ endpoint, forceNormalizeClaudeBody }) => buildEndpointRequest(
            endpoint,
            { forceNormalizeClaudeBody },
          ),
          dispatchRequest,
        });
        const debugAttemptBase = reserveSurfaceProxyDebugAttemptBase(debugTrace, endpointCandidates.length);
        const endpointResult = await executeEndpointFlow({
          siteUrl: selected.site.url,
          endpointCandidates,
          buildRequest: (endpoint) => buildEndpointRequest(endpoint),
          dispatchRequest,
          tryRecover: endpointStrategy.tryRecover,
          onAttemptFailure: async (ctx) => {
            const memoryWrite = recordUpstreamEndpointFailure({
              ...endpointRuntimeContext,
              endpoint: ctx.request.endpoint,
              status: ctx.response.status,
              errorText: ctx.rawErrText,
            });
            await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
              attemptIndex: debugAttemptBase + ctx.endpointIndex,
              endpoint: ctx.request.endpoint,
              requestPath: ctx.request.path,
              targetUrl: ctx.targetUrl,
              runtimeExecutor: ctx.request.runtime?.executor || 'default',
              requestHeaders: ctx.request.headers,
              requestBody: ctx.request.body,
              responseStatus: ctx.response.status,
              responseHeaders: buildSurfaceProxyDebugResponseHeaders(ctx.response),
              responseBody: parseSurfaceProxyDebugTextPayload(ctx.rawErrText),
              rawErrorText: ctx.rawErrText,
              recoverApplied: ctx.recoverApplied === true,
              downgradeDecision: false,
              downgradeReason: null,
              memoryWrite,
            });
          },
          onAttemptSuccess: async (ctx) => {
            const memoryWrite = recordUpstreamEndpointSuccess({
              ...endpointRuntimeContext,
              endpoint: ctx.request.endpoint,
            });
            const responseBody = await captureSurfaceProxyDebugSuccessResponseBody(debugTrace, ctx);
            await safeInsertSurfaceProxyDebugAttempt(debugTrace, {
              attemptIndex: debugAttemptBase + ctx.endpointIndex,
              endpoint: ctx.request.endpoint,
              requestPath: ctx.request.path,
              targetUrl: ctx.targetUrl,
              runtimeExecutor: ctx.request.runtime?.executor || 'default',
              requestHeaders: ctx.request.headers,
              requestBody: ctx.request.body,
              responseStatus: ctx.response.status,
              responseHeaders: buildSurfaceProxyDebugResponseHeaders(ctx.response),
              responseBody,
              rawErrorText: null,
              recoverApplied: ctx.recoverApplied === true,
              downgradeDecision: false,
              downgradeReason: null,
              memoryWrite,
            });
          },
          shouldDowngrade: endpointStrategy.shouldDowngrade,
          onDowngrade: async (ctx) => {
            await safeUpdateSurfaceProxyDebugAttempt(debugTrace, debugAttemptBase + ctx.endpointIndex, {
              downgradeDecision: true,
              downgradeReason: ctx.errText,
              rawErrorText: ctx.rawErrText,
            });
          },
        });
        if (!endpointResult.ok) {
          lastStatus = endpointResult.status;
          lastContentType = 'application/json';
          lastText = JSON.stringify({
            error: {
              message: endpointResult.errText,
              type: 'upstream_error',
            },
          });
          await tokenRouter.recordFailure?.(selected.channel.id, {
            status: endpointResult.status,
            errorText: endpointResult.rawErrText || endpointResult.errText,
          });
          await logProxy(
            selected,
            requestedModel,
            'failed',
            lastStatus,
            Date.now() - startTime,
            endpointResult.errText,
            retryCount,
            downstreamPath,
            null,
            clientContext,
          );
          if (canRetryProxyChannel(retryCount)) {
            retryCount += 1;
            continue;
          }
          await finalizeDebugFailure(lastStatus, JSON.parse(lastText), null).catch(async () => {
            await finalizeDebugFailure(lastStatus, parseSurfaceProxyDebugTextPayload(lastText), null);
          });
          return reply.code(lastStatus).type(lastContentType).send(lastText);
        }

        upstreamPath = endpointResult.upstreamPath;
        const upstream = endpointResult.upstream;
        const rawText = await readRuntimeResponseText(upstream);
        let upstreamData: unknown = rawText;
        try {
          upstreamData = JSON.parse(rawText);
        } catch {}
        const parsedUsage = parseProxyUsage(upstreamData);
        const normalizedFinal = normalizeUpstreamFinalResponse(upstreamData, actualModel, rawText);
        const geminiResponse = geminiGenerateContentTransformer.compatibility.serializeNormalizedFinalToGemini({
          normalized: normalizedFinal,
          usage: {
            promptTokens: parsedUsage.promptTokens,
            completionTokens: parsedUsage.completionTokens,
            totalTokens: parsedUsage.totalTokens,
          },
        });
        const latency = Date.now() - startTime;
        await recordGeminiChannelSuccessBestEffort(selected.channel.id, latency, actualModel);
        await logProxy(
          selected,
          requestedModel,
          'success',
          upstream.status,
          latency,
          null,
          retryCount,
          downstreamPath,
          upstreamPath,
          clientContext,
          parsedUsage.promptTokens,
          parsedUsage.completionTokens,
          parsedUsage.totalTokens,
        );
        const downstreamPayload = isGeminiCliDownstream
          ? { response: geminiResponse }
          : geminiResponse;
        await finalizeDebugSuccess(
          upstream.status,
          upstreamPath,
          buildSurfaceProxyDebugResponseHeaders(upstream),
          downstreamPayload,
        );
        if (wantsSseEnvelope) {
          // Some compatibility upstreams finish stream requests with a final JSON payload.
          // Preserve Gemini streaming UX by wrapping that terminal payload back into one SSE event.
          return reply
            .code(upstream.status)
            .type('text/event-stream; charset=utf-8')
            .send(geminiGenerateContentTransformer.stream.serializeSsePayload(downstreamPayload));
        }
        return reply.code(upstream.status).send(downstreamPayload);
      } catch (error) {
        lastStatus = 502;
        lastContentType = 'application/json';
        lastText = JSON.stringify({
          error: {
            message: error instanceof Error ? error.message : 'Gemini upstream request failed',
            type: 'upstream_error',
          },
        });
        await tokenRouter.recordFailure?.(selected.channel.id, {
          errorText: error instanceof Error ? error.message : 'Gemini upstream request failed',
        });
        await logProxy(
          selected,
          requestedModel,
          'failed',
          0,
          Date.now() - startTime,
          error instanceof Error ? error.message : 'Gemini upstream request failed',
          retryCount,
          downstreamPath,
          upstreamPath || null,
          clientContext,
        );
        if (canRetryProxyChannel(retryCount)) {
          retryCount += 1;
          continue;
        }
        await finalizeDebugFailure(lastStatus, parseSurfaceProxyDebugTextPayload(lastText), upstreamPath || null);
        return reply.code(lastStatus).type(lastContentType).send(lastText);
      }
    }
  };

  const generateContent = async (request: FastifyRequest, reply: FastifyReply) => handleGenerateContent(request, reply);
  const geminiCliGenerateContent = async (request: FastifyRequest, reply: FastifyReply) => handleGenerateContent(request, reply, {
    downstreamProtocol: 'gemini-cli',
    action: 'generateContent',
  });
  const geminiCliStreamGenerateContent = async (request: FastifyRequest, reply: FastifyReply) => handleGenerateContent(request, reply, {
    downstreamProtocol: 'gemini-cli',
    action: 'streamGenerateContent',
  });
  const geminiCliCountTokens = async (request: FastifyRequest, reply: FastifyReply) => handleGenerateContent(request, reply, {
    downstreamProtocol: 'gemini-cli',
    action: 'countTokens',
  });

  app.get('/v1beta/models', listModels);
  app.get('/gemini/:geminiApiVersion/models', listModels);
  app.post('/v1beta/models/*', generateContent);
  app.post('/gemini/:geminiApiVersion/models/*', generateContent);
  app.post('/v1internal::generateContent', geminiCliGenerateContent);
  app.post('/v1internal::streamGenerateContent', geminiCliStreamGenerateContent);
  app.post('/v1internal::countTokens', geminiCliCountTokens);
}
