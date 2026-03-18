import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { TextDecoder } from 'node:util';
import { fetch } from 'undici';
import { and, eq } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';
import { parseProxyUsage } from '../../services/proxyUsageParser.js';
import { isModelAllowedByPolicyOrAllowedRoutes } from '../../services/downstreamApiKeyService.js';
import { tokenRouter } from '../../services/tokenRouter.js';
import { buildOauthProviderHeaders } from '../../services/oauth/service.js';
import { getOauthInfoFromExtraConfig } from '../../services/oauth/oauthAccount.js';
import { withSiteProxyRequestInit } from '../../services/siteProxy.js';
import { refreshModelsAndRebuildRoutes } from '../../services/modelService.js';
import { getDownstreamRoutingPolicy } from './downstreamPolicy.js';
import { executeEndpointFlow, type BuiltEndpointRequest } from './endpointFlow.js';
import { composeProxyLogMessage } from './logPathMeta.js';
import {
  buildUpstreamEndpointRequest,
  resolveUpstreamEndpointCandidates,
} from './upstreamEndpoint.js';
import {
  geminiGenerateContentTransformer,
} from '../../transformers/gemini/generate-content/index.js';
import { createChatEndpointStrategy } from '../../transformers/shared/chatEndpointStrategy.js';
import { normalizeUpstreamFinalResponse } from '../../transformers/shared/normalized.js';
import {
  createGeminiCliStreamReader,
  unwrapGeminiCliPayload,
  wrapGeminiCliRequest,
} from './geminiCliCompat.js';
import { dispatchRuntimeRequest } from './runtimeExecutor.js';

const MAX_RETRIES = 2;
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

function hasDownstreamModelRestrictions(policy: { supportedModels?: unknown; allowedRouteIds?: unknown }): boolean {
  const supportedModels = Array.isArray(policy.supportedModels) ? policy.supportedModels : [];
  const allowedRouteIds = Array.isArray(policy.allowedRouteIds) ? policy.allowedRouteIds : [];
  return supportedModels.length > 0 || allowedRouteIds.length > 0;
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
  promptTokens = 0,
  completionTokens = 0,
  totalTokens = 0,
) {
  try {
    const createdAt = formatUtcSqlDateTime(new Date());
    const normalizedErrorMessage = composeProxyLogMessage({
      downstreamPath,
      upstreamPath,
      errorMessage,
    });
    await db.insert(schema.proxyLogs).values({
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
      billingDetails: null,
      errorMessage: normalizedErrorMessage,
      retryCount,
      createdAt,
    }).run();
  } catch (error) {
    console.warn('[proxy/gemini] failed to write proxy log', error);
  }
}

export async function geminiProxyRoute(app: FastifyInstance) {
  const listModels = async (request: FastifyRequest, reply: FastifyReply) => {
    const apiVersion = geminiGenerateContentTransformer.resolveProxyApiVersion(
      request.params as { geminiApiVersion?: string } | undefined,
    );
    const excludeChannelIds: number[] = [];
    let retryCount = 0;
    let lastStatus = 503;
    let lastText = 'No available channels for Gemini models';
    let lastContentType = 'application/json';

    while (retryCount <= MAX_RETRIES) {
      const selected = retryCount === 0
        ? await selectGeminiChannel(request)
        : await selectNextGeminiProbeChannel(request, excludeChannelIds);
      if (!selected) {
        return reply.code(lastStatus).type(lastContentType).send(lastText);
      }

      excludeChannelIds.push(selected.channel.id);

      try {
        if (!isDirectGeminiFamilyPlatform(selected.site.platform)) {
          let models = await readRouteAwareGeminiModels(request);
          if (models.length <= 0) {
            await refreshModelsAndRebuildRoutes();
            models = await readRouteAwareGeminiModels(request);
          }
          return reply.code(200).send({ models });
        }

        if (isGeminiCliPlatform(selected.site.platform)) {
          const filtered = await filterGeminiListedModelsForPolicy(
            { models: GEMINI_CLI_STATIC_MODELS },
            request,
          );
          return reply.code(200).send(filtered);
        }

        const upstream = await fetch(
          geminiGenerateContentTransformer.resolveModelsUrl(selected.site.url, apiVersion, selected.tokenValue),
          { method: 'GET' },
        );
        const text = await upstream.text();
        if (!upstream.ok) {
          lastStatus = upstream.status;
          lastText = text;
          lastContentType = upstream.headers.get('content-type') || 'application/json';
          await tokenRouter.recordFailure?.(selected.channel.id);
          if (retryCount < MAX_RETRIES) {
            retryCount += 1;
            continue;
          }
        }

        try {
          const parsed = JSON.parse(text);
          const filtered = await filterGeminiListedModelsForPolicy(parsed, request);
          return reply.code(upstream.status).send(filtered);
        } catch {
          return reply.code(upstream.status).type(upstream.headers.get('content-type') || 'application/json').send(text);
        }
      } catch (error) {
        await tokenRouter.recordFailure?.(selected.channel.id);
        lastStatus = 502;
        lastContentType = 'application/json';
        lastText = JSON.stringify({
          error: {
            message: error instanceof Error ? error.message : 'Gemini upstream request failed',
            type: 'upstream_error',
          },
        });
        if (retryCount < MAX_RETRIES) {
          retryCount += 1;
          continue;
        }
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
    if (!requestedModel) {
      return reply.code(400).send({
        error: { message: 'Gemini model path is required', type: 'invalid_request_error' },
      });
    }

    const policy = getDownstreamRoutingPolicy(request);
    const downstreamPath = resolveDownstreamPath(request);
    const excludeChannelIds: number[] = [];
    let retryCount = 0;
    let lastStatus = 503;
    let lastText = 'No available channels for this model';
    let lastContentType = 'application/json';

    while (retryCount <= MAX_RETRIES) {
      const selected = retryCount === 0
        ? await tokenRouter.selectChannel(requestedModel, policy)
        : await tokenRouter.selectNextChannel(requestedModel, excludeChannelIds, policy);
      if (!selected) {
        return reply.code(lastStatus).type(lastContentType).send(lastText);
      }

      excludeChannelIds.push(selected.channel.id);

      const actualModel = selected.actualModel || requestedModel;
      const normalizedBody = geminiGenerateContentTransformer.inbound.normalizeRequest(
        isGeminiCliDownstream ? omitGeminiCliModelField(request.body) : (request.body || {}),
        actualModel,
      );
      const oauth = getOauthInfoFromExtraConfig(selected.account.extraConfig);
      const isGeminiCli = isGeminiCliPlatform(selected.site.platform);
      const isInternalGemini = isInternalGeminiPlatform(selected.site.platform);
      const isDirectGeminiFamily = isDirectGeminiFamilyPlatform(selected.site.platform);
      const startTime = Date.now();
      let upstreamPath = '';

      try {
        if (isDirectGeminiFamily) {
          if (isGeminiCli && !oauth?.projectId) {
            lastStatus = 500;
            lastContentType = 'application/json';
            lastText = JSON.stringify({
              error: {
                message: 'Gemini CLI OAuth project is missing',
                type: 'server_error',
              },
            });
            await tokenRouter.recordFailure?.(selected.channel.id);
            if (retryCount < MAX_RETRIES) {
              retryCount += 1;
              continue;
            }
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
                extraConfig: typeof selected.account.extraConfig === 'string' ? selected.account.extraConfig : null,
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
          const upstream = isInternalGemini
            ? await dispatchRuntimeRequest({
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
              buildInit: async (requestUrl, requestForFetch) => withSiteProxyRequestInit(requestUrl, {
                method: 'POST',
                headers: requestForFetch.headers,
                body: JSON.stringify(requestForFetch.body),
              }),
            })
            : await fetch(targetUrl, {
              method: 'POST',
              headers: requestHeaders,
              body: JSON.stringify(requestBody),
            });
          const contentType = upstream.headers.get('content-type') || 'application/json';
          if (!upstream.ok) {
            lastStatus = upstream.status;
            lastContentType = contentType;
            lastText = await upstream.text();
            await tokenRouter.recordFailure?.(selected.channel.id);
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
            );
            if (retryCount < MAX_RETRIES) {
              retryCount += 1;
              continue;
            }

            try {
              return reply.code(lastStatus).send(JSON.parse(lastText));
            } catch {
              return reply.code(lastStatus).type(lastContentType).send(lastText);
            }
          }

          if (geminiGenerateContentTransformer.stream.isSseContentType(contentType)) {
            reply.hijack();
            reply.raw.statusCode = upstream.status;
            reply.raw.setHeader('Content-Type', contentType || 'text/event-stream');
            const upstreamReader = upstream.body?.getReader();
            const reader = isInternalGemini && !isGeminiCliDownstream && upstreamReader
              ? createGeminiCliStreamReader(upstreamReader)
              : upstreamReader;
            if (!reader) {
              const latency = Date.now() - startTime;
              await tokenRouter.recordSuccess?.(selected.channel.id, latency, 0);
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
              );
              reply.raw.end();
              return;
            }
            const aggregateState = geminiGenerateContentTransformer.stream.createAggregateState();
            const decoder = new TextDecoder();
            let rest = '';
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (!value) continue;
                const chunkText = decoder.decode(value, { stream: true });
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
                const consumed = geminiGenerateContentTransformer.stream.consumeUpstreamSseBuffer(
                  aggregateState,
                  rest + tail,
                );
                for (const line of consumed.lines) {
                  reply.raw.write(line);
                }
              }
            } finally {
              reader.releaseLock();
              reply.raw.end();
            }
            const parsedUsage = parseProxyUsage(aggregateState);
            const latency = Date.now() - startTime;
            await tokenRouter.recordSuccess?.(selected.channel.id, latency, 0);
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
              parsedUsage.promptTokens,
              parsedUsage.completionTokens,
              parsedUsage.totalTokens,
            );
            return;
          }

          const text = await upstream.text();
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
            await tokenRouter.recordSuccess?.(selected.channel.id, latency, 0);
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
              parsedUsage.promptTokens,
              parsedUsage.completionTokens,
              parsedUsage.totalTokens,
            );
            return reply.code(upstream.status).send(
              isGeminiCliDownstream && !isCountTokensAction
                ? { response: responsePayload }
                : responsePayload,
            );
          } catch {
            const latency = Date.now() - startTime;
            await tokenRouter.recordSuccess?.(selected.channel.id, latency, 0);
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
          return reply.code(lastStatus).type(lastContentType).send(lastText);
        }

        const openAiBody = geminiGenerateContentTransformer.compatibility.buildOpenAiBodyFromGeminiRequest({
          body: normalizedBody as Record<string, unknown>,
          modelName: actualModel,
          stream: isStreamAction,
        });
        const endpointCandidates = await resolveUpstreamEndpointCandidates(
          {
            site: selected.site,
            account: selected.account,
          },
          actualModel,
          'openai',
          requestedModel,
        );
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
              extraConfig: typeof selected.account.extraConfig === 'string' ? selected.account.extraConfig : null,
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
        const dispatchRequest = (compatibilityRequest: BuiltEndpointRequest, targetUrl?: string) => (
          dispatchRuntimeRequest({
            siteUrl: selected.site.url,
            targetUrl,
            request: compatibilityRequest,
            buildInit: async (requestUrl, requestForFetch) => withSiteProxyRequestInit(requestUrl, {
              method: 'POST',
              headers: requestForFetch.headers,
              body: JSON.stringify(requestForFetch.body),
            }),
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
        const endpointResult = await executeEndpointFlow({
          siteUrl: selected.site.url,
          endpointCandidates,
          buildRequest: (endpoint) => buildEndpointRequest(endpoint),
          dispatchRequest,
          tryRecover: endpointStrategy.tryRecover,
          shouldDowngrade: endpointStrategy.shouldDowngrade,
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
          await tokenRouter.recordFailure?.(selected.channel.id);
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
          );
          if (retryCount < MAX_RETRIES) {
            retryCount += 1;
            continue;
          }
          return reply.code(lastStatus).type(lastContentType).send(lastText);
        }

        upstreamPath = endpointResult.upstreamPath;
        const upstream = endpointResult.upstream;
        const rawText = await upstream.text();
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
        await tokenRouter.recordSuccess?.(selected.channel.id, latency, 0);
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
          parsedUsage.promptTokens,
          parsedUsage.completionTokens,
          parsedUsage.totalTokens,
        );
        return reply.code(upstream.status).send(
          isGeminiCliDownstream
            ? { response: geminiResponse }
            : geminiResponse,
        );
      } catch (error) {
        lastStatus = 502;
        lastContentType = 'application/json';
        lastText = JSON.stringify({
          error: {
            message: error instanceof Error ? error.message : 'Gemini upstream request failed',
            type: 'upstream_error',
          },
        });
        await tokenRouter.recordFailure?.(selected.channel.id);
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
        );
        if (retryCount < MAX_RETRIES) {
          retryCount += 1;
          continue;
        }
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
