import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { tokenRouter } from '../../services/tokenRouter.js';
import { db, hasProxyLogDownstreamApiKeyIdColumn, schema } from '../../db/index.js';
import { refreshModelsAndRebuildRoutes } from '../../services/modelService.js';
import { reportProxyAllFailed, reportTokenExpired } from '../../services/alertService.js';
import { isTokenExpiredError } from '../../services/alertRules.js';
import { shouldRetryProxyRequest } from '../../services/proxyRetryPolicy.js';
import { resolveProxyUsageWithSelfLogFallback } from '../../services/proxyUsageFallbackService.js';
import { mergeProxyUsage, parseProxyUsage } from '../../services/proxyUsageParser.js';
import { resolveProxyUrlForSite, withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import { type DownstreamFormat } from '../../transformers/shared/normalized.js';
import {
  buildClaudeCountTokensUpstreamRequest,
  buildUpstreamEndpointRequest,
  resolveUpstreamEndpointCandidates,
} from './upstreamEndpoint.js';
import {
  ensureModelAllowedForDownstreamKey,
  getDownstreamRoutingPolicy,
  recordDownstreamCostUsage,
} from './downstreamPolicy.js';
import { composeProxyLogMessage } from './logPathMeta.js';
import { executeEndpointFlow, withUpstreamPath, type BuiltEndpointRequest } from './endpointFlow.js';
import { detectProxyFailure } from './proxyFailureJudge.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';
import { resolveProxyLogBilling } from './proxyBilling.js';
import { openAiChatTransformer } from '../../transformers/openai/chat/index.js';
import { anthropicMessagesTransformer } from '../../transformers/anthropic/messages/index.js';
import { detectDownstreamClientContext, type DownstreamClientContext } from './downstreamClientContext.js';
import { getProxyAuthContext, getProxyResourceOwner } from '../../middleware/auth.js';
import {
  ProxyInputFileResolutionError,
  hasNonImageFileInputInOpenAiBody,
  resolveOpenAiBodyInputFiles,
} from '../../services/proxyInputFileResolver.js';
import {
  buildOauthProviderHeaders,
} from '../../services/oauth/service.js';
import { getOauthInfoFromExtraConfig } from '../../services/oauth/oauthAccount.js';
import { recordOauthQuotaResetHint } from '../../services/oauth/quota.js';
import { refreshOauthAccessTokenSingleflight } from '../../services/oauth/refreshSingleflight.js';
import { collectResponsesFinalPayloadFromSse } from './responsesSseFinal.js';
import {
  createGeminiCliStreamReader,
  unwrapGeminiCliPayload,
} from './geminiCliCompat.js';
import { dispatchRuntimeRequest } from './runtimeExecutor.js';

const MAX_RETRIES = 2;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export async function chatProxyRoute(app: FastifyInstance) {
  app.post('/v1/chat/completions', async (request: FastifyRequest, reply: FastifyReply) =>
    handleChatProxyRequest(request, reply, 'openai'));
}

export async function claudeMessagesProxyRoute(app: FastifyInstance) {
  app.post('/v1/messages', async (request: FastifyRequest, reply: FastifyReply) =>
    handleChatProxyRequest(request, reply, 'claude'));
  app.post('/v1/messages/count_tokens', async (request: FastifyRequest, reply: FastifyReply) =>
    handleClaudeCountTokensRequest(request, reply));
}

async function handleChatProxyRequest(
  request: FastifyRequest,
  reply: FastifyReply,
  downstreamFormat: DownstreamFormat,
) {
  const downstreamTransformer = downstreamFormat === 'claude'
    ? anthropicMessagesTransformer
    : openAiChatTransformer;
  const downstreamPath = downstreamFormat === 'claude' ? '/v1/messages' : '/v1/chat/completions';
  const clientContext = detectDownstreamClientContext({
    downstreamPath,
    headers: request.headers as Record<string, unknown>,
    body: request.body,
  });
  const parsedRequestEnvelope = downstreamTransformer.transformRequest(request.body);
  if (parsedRequestEnvelope.error) {
    return reply.code(parsedRequestEnvelope.error.statusCode).send(parsedRequestEnvelope.error.payload);
  }

  const requestEnvelope = parsedRequestEnvelope.value!;
  const {
    requestedModel,
    isStream,
    upstreamBody,
    claudeOriginalBody,
  } = requestEnvelope.parsed;
  if (!await ensureModelAllowedForDownstreamKey(request, reply, requestedModel)) return;
  const downstreamPolicy = getDownstreamRoutingPolicy(request);
  const owner = getProxyResourceOwner(request);
  let resolvedOpenAiBody = upstreamBody;
  if (owner) {
    try {
      resolvedOpenAiBody = await resolveOpenAiBodyInputFiles(upstreamBody, owner);
    } catch (error) {
      if (error instanceof ProxyInputFileResolutionError) {
        return reply.code(error.statusCode).send(error.payload);
      }
      throw error;
    }
  }
  const hasNonImageFileInput = hasNonImageFileInputInOpenAiBody(resolvedOpenAiBody);
  const codexSessionCacheKey = deriveCodexSessionCacheKey({
    downstreamFormat,
    body: downstreamFormat === 'claude' ? claudeOriginalBody : request.body,
    requestedModel,
    proxyToken: getProxyAuthContext(request)?.token || null,
  });
  const downstreamApiKeyId = getProxyAuthContext(request)?.keyId ?? null;
  const logDownstreamApiKeyId = downstreamApiKeyId !== null
    && await hasProxyLogDownstreamApiKeyIdColumn();

  const excludeChannelIds: number[] = [];
  let retryCount = 0;

  while (retryCount <= MAX_RETRIES) {
    let selected = retryCount === 0
      ? await tokenRouter.selectChannel(requestedModel, downstreamPolicy)
      : await tokenRouter.selectNextChannel(requestedModel, excludeChannelIds, downstreamPolicy);

    if (!selected && retryCount === 0) {
      await refreshModelsAndRebuildRoutes();
      selected = await tokenRouter.selectChannel(requestedModel, downstreamPolicy);
    }

    if (!selected) {
      await reportProxyAllFailed({
        model: requestedModel,
        reason: 'No available channels after retries',
      });
      return reply.code(503).send({
        error: { message: 'No available channels for this model', type: 'server_error' },
      });
    }

    excludeChannelIds.push(selected.channel.id);

    const modelName = selected.actualModel || requestedModel;
    const oauth = getOauthInfoFromExtraConfig(selected.account.extraConfig);
    const isCodexSite = String(selected.site.platform || '').trim().toLowerCase() === 'codex';
    const endpointCandidates = [
      ...await resolveUpstreamEndpointCandidates(
        {
          site: selected.site,
          account: selected.account,
        },
        modelName,
        downstreamFormat,
        requestedModel,
        {
          hasNonImageFileInput,
        },
      ),
    ];
    const buildProviderHeaders = () => (
      buildOauthProviderHeaders({
        extraConfig: typeof selected.account.extraConfig === 'string' ? selected.account.extraConfig : null,
        downstreamHeaders: request.headers as Record<string, unknown>,
      })
    );
    const buildEndpointRequest = (
      endpoint: 'chat' | 'messages' | 'responses',
      options: { forceNormalizeClaudeBody?: boolean } = {},
    ) => {
      const upstreamStream = isStream || (isCodexSite && endpoint === 'responses');
      const endpointRequest = buildUpstreamEndpointRequest({
        endpoint,
        modelName,
        stream: upstreamStream,
        tokenValue: selected.tokenValue,
        oauthProvider: oauth?.provider,
        oauthProjectId: oauth?.projectId,
        sitePlatform: selected.site.platform,
        siteUrl: selected.site.url,
        openaiBody: resolvedOpenAiBody,
        downstreamFormat,
        claudeOriginalBody,
        forceNormalizeClaudeBody: options.forceNormalizeClaudeBody,
        downstreamHeaders: request.headers as Record<string, unknown>,
        providerHeaders: buildProviderHeaders(),
        codexSessionCacheKey,
      });
      return {
        endpoint,
        path: endpointRequest.path,
        headers: endpointRequest.headers,
        body: endpointRequest.body as Record<string, unknown>,
        runtime: endpointRequest.runtime,
      };
    };
    const dispatchRequest = (
      compatibilityRequest: BuiltEndpointRequest,
      targetUrl?: string,
    ) => (
      dispatchRuntimeRequest({
        siteUrl: selected.site.url,
        targetUrl,
        request: compatibilityRequest,
        buildInit: (_requestUrl, requestForFetch) => withSiteRecordProxyRequestInit(selected.site, {
          method: 'POST',
          headers: requestForFetch.headers,
          body: JSON.stringify(requestForFetch.body),
        }),
      })
    );
    const endpointStrategy = downstreamTransformer.compatibility.createEndpointStrategy({
      downstreamFormat,
      endpointCandidates,
      modelName,
      requestedModelHint: requestedModel,
      sitePlatform: selected.site.platform,
      isStream: isStream || isCodexSite,
      buildRequest: ({ endpoint, forceNormalizeClaudeBody }) => buildEndpointRequest(
        endpoint,
        { forceNormalizeClaudeBody },
      ),
      dispatchRequest,
    });
    const tryRecover = async (ctx: Parameters<NonNullable<typeof endpointStrategy.tryRecover>>[0]) => {
      if (ctx.response.status === 401 && oauth) {
        try {
          const refreshed = await refreshOauthAccessTokenSingleflight(selected.account.id);
          selected.tokenValue = refreshed.accessToken;
          selected.account = {
            ...selected.account,
            accessToken: refreshed.accessToken,
            extraConfig: refreshed.extraConfig ?? selected.account.extraConfig,
          };
          const refreshedRequest = buildEndpointRequest(ctx.request.endpoint);
          const refreshedTargetUrl = `${selected.site.url}${refreshedRequest.path}`;
          const refreshedResponse = await dispatchRequest(refreshedRequest, refreshedTargetUrl);
          if (refreshedResponse.ok) {
            return {
              upstream: refreshedResponse,
              upstreamPath: refreshedRequest.path,
            };
          }
          ctx.request = refreshedRequest;
          ctx.response = refreshedResponse;
          ctx.rawErrText = await refreshedResponse.text().catch(() => 'unknown error');
        } catch {
          return endpointStrategy.tryRecover(ctx);
        }
      }
      return endpointStrategy.tryRecover(ctx);
    };
    let startTime = Date.now();

    try {
        const endpointResult = await executeEndpointFlow({
          siteUrl: selected.site.url,
          proxyUrl: resolveProxyUrlForSite(selected.site),
          endpointCandidates,
          buildRequest: (endpoint) => buildEndpointRequest(endpoint),
          dispatchRequest,
          tryRecover,
          shouldDowngrade: endpointStrategy.shouldDowngrade,
          onDowngrade: (ctx) => {
          logProxy(
            selected,
            requestedModel,
            'failed',
            ctx.response.status,
            Date.now() - startTime,
            ctx.errText,
            retryCount,
            downstreamPath,
          0,
          0,
          0,
          0,
          null,
          null,
          clientContext,
          logDownstreamApiKeyId ? downstreamApiKeyId : null,
        );
      },
      });

      if (!endpointResult.ok) {
        const status = endpointResult.status || 502;
        const errText = endpointResult.errText || 'unknown error';
        const rawErrText = endpointResult.rawErrText || errText;
        tokenRouter.recordFailure(selected.channel.id);
        logProxy(
          selected,
          requestedModel,
          'failed',
          status,
          Date.now() - startTime,
          errText,
          retryCount,
          downstreamPath,
          0,
          0,
          0,
          0,
          null,
          null,
          clientContext,
          logDownstreamApiKeyId ? downstreamApiKeyId : null,
        );
        await recordOauthQuotaResetHint({
          accountId: selected.account.id,
          statusCode: status,
          errorText: rawErrText,
        });

        if (isTokenExpiredError({ status, message: errText })) {
          await reportTokenExpired({
            accountId: selected.account.id,
            username: selected.account.username,
            siteName: selected.site.name,
            detail: `HTTP ${status}`,
          });
        }

        if (shouldRetryProxyRequest(status, errText) && retryCount < MAX_RETRIES) {
          retryCount += 1;
          continue;
        }

        await reportProxyAllFailed({
          model: requestedModel,
          reason: `upstream returned HTTP ${status}`,
        });

        return reply.code(status).send({
          error: { message: errText, type: 'upstream_error' },
        });
      }

      const upstream = endpointResult.upstream;
      const successfulUpstreamPath = endpointResult.upstreamPath;

      if (isStream) {
        const upstreamContentType = (upstream.headers.get('content-type') || '').toLowerCase();
        const startSseResponse = () => {
          reply.hijack();
          reply.raw.statusCode = 200;
          reply.raw.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
          reply.raw.setHeader('Cache-Control', 'no-cache, no-transform');
          reply.raw.setHeader('Connection', 'keep-alive');
          reply.raw.setHeader('X-Accel-Buffering', 'no');
        };

        let parsedUsage: ReturnType<typeof parseProxyUsage> = {
          promptTokens: 0,
          completionTokens: 0,
          totalTokens: 0,
          cacheReadTokens: 0,
          cacheCreationTokens: 0,
          promptTokensIncludeCache: null,
        };

        const writeLines = (lines: string[]) => {
          for (const line of lines) {
            reply.raw.write(line);
          }
        };
        const streamSession = openAiChatTransformer.proxyStream.createSession({
          downstreamFormat,
          modelName,
          successfulUpstreamPath,
          onParsedPayload: (payload) => {
            if (payload && typeof payload === 'object') {
              parsedUsage = mergeProxyUsage(parsedUsage, parseProxyUsage(payload));
            }
          },
          writeLines,
          writeRaw: (chunk) => {
            reply.raw.write(chunk);
          },
        });
        let rawText = '';

        if (!upstreamContentType.includes('text/event-stream')) {
          const fallbackText = await upstream.text();
          rawText = fallbackText;
          let fallbackData: unknown = null;
          try {
            fallbackData = JSON.parse(fallbackText);
          } catch {
            fallbackData = fallbackText;
          }
          if (String(selected.site.platform || '').trim().toLowerCase() === 'gemini-cli') {
            fallbackData = unwrapGeminiCliPayload(fallbackData);
          }
          parsedUsage = mergeProxyUsage(parsedUsage, parseProxyUsage(fallbackData));
          const latency = Date.now() - startTime;
          const failure = detectProxyFailure({ rawText, usage: parsedUsage });
          if (failure) {
            tokenRouter.recordFailure(selected.channel.id);
            logProxy(
              selected,
              requestedModel,
              'failed',
              failure.status,
              latency,
              failure.reason,
              retryCount,
              downstreamPath,
              parsedUsage.promptTokens,
              parsedUsage.completionTokens,
              parsedUsage.totalTokens,
              0,
              null,
              successfulUpstreamPath,
              clientContext,
              logDownstreamApiKeyId ? downstreamApiKeyId : null,
            );

            if (shouldRetryProxyRequest(failure.status, failure.reason) && retryCount < MAX_RETRIES) {
              retryCount += 1;
              continue;
            }

            await reportProxyAllFailed({
              model: requestedModel,
              reason: failure.reason,
            });

            return reply.code(failure.status).send({
              error: { message: failure.reason, type: 'upstream_error' },
            });
          }

          startSseResponse();
          const streamResult = streamSession.consumeUpstreamFinalPayload(fallbackData, fallbackText, reply.raw);
          if (streamResult.status === 'failed') {
            tokenRouter.recordFailure(selected.channel.id);
            logProxy(
              selected,
              requestedModel,
              'failed',
              200,
              latency,
              streamResult.errorMessage,
              retryCount,
              downstreamPath,
              parsedUsage.promptTokens,
              parsedUsage.completionTokens,
              parsedUsage.totalTokens,
              0,
              null,
              successfulUpstreamPath,
              clientContext,
              logDownstreamApiKeyId ? downstreamApiKeyId : null,
            );
            return;
          }
        } else {
          startSseResponse();
          // Preserve real SSE streaming instead of buffering the whole upstream body.
          const upstreamReader = upstream.body?.getReader();
          const baseReader = String(selected.site.platform || '').trim().toLowerCase() === 'gemini-cli' && upstreamReader
            ? createGeminiCliStreamReader(upstreamReader)
            : upstreamReader;
          const decoder = new TextDecoder();
          const reader = baseReader
            ? {
              async read() {
                const result = await baseReader.read();
                if (result.value) {
                  rawText += decoder.decode(result.value, { stream: true });
                }
                return result;
              },
              async cancel(reason?: unknown) {
                return baseReader.cancel(reason);
              },
              releaseLock() {
                return baseReader.releaseLock();
              },
            }
            : baseReader;
          const streamResult = await streamSession.run(reader, reply.raw);
          rawText += decoder.decode();

          const latency = Date.now() - startTime;
          if (streamResult.status === 'failed') {
            tokenRouter.recordFailure(selected.channel.id);
            logProxy(
              selected,
              requestedModel,
              'failed',
              200,
              latency,
              streamResult.errorMessage,
              retryCount,
              downstreamPath,
              parsedUsage.promptTokens,
              parsedUsage.completionTokens,
              parsedUsage.totalTokens,
              0,
              null,
              successfulUpstreamPath,
              clientContext,
              logDownstreamApiKeyId ? downstreamApiKeyId : null,
            );
            return;
          }

          // Once SSE has been hijacked and streamed downstream, we can no longer
          // safely fall back to an HTTP error response or retry by switching the
          // channel mid-flight. Stream-level failures must be handled in-band by
          // the proxy stream session itself.
        }

        const latency = Date.now() - startTime;
        const resolvedUsage = await resolveProxyUsageWithSelfLogFallback({
          site: selected.site,
          account: selected.account,
          tokenValue: selected.tokenValue,
          tokenName: selected.tokenName,
          modelName,
          requestStartedAtMs: startTime,
          requestEndedAtMs: startTime + latency,
          localLatencyMs: latency,
          usage: {
            promptTokens: parsedUsage.promptTokens,
            completionTokens: parsedUsage.completionTokens,
            totalTokens: parsedUsage.totalTokens,
          },
        });

        const { estimatedCost, billingDetails } = await resolveProxyLogBilling({
          site: selected.site,
          account: selected.account,
          modelName,
          parsedUsage,
          resolvedUsage,
        });

        tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost);
        recordDownstreamCostUsage(request, estimatedCost);
        logProxy(
          selected,
          requestedModel,
          'success',
          200,
          latency,
          null,
          retryCount,
          downstreamPath,
          resolvedUsage.promptTokens,
          resolvedUsage.completionTokens,
          resolvedUsage.totalTokens,
          estimatedCost,
          billingDetails,
          successfulUpstreamPath,
          clientContext,
          logDownstreamApiKeyId ? downstreamApiKeyId : null,
        );
        return;
      }

      const upstreamContentType = (upstream.headers.get('content-type') || '').toLowerCase();
      let rawText = '';
      let upstreamData: unknown;
      if (upstreamContentType.includes('text/event-stream') && successfulUpstreamPath.endsWith('/responses')) {
        const collected = await collectResponsesFinalPayloadFromSse(upstream, modelName);
        rawText = collected.rawText;
        upstreamData = collected.payload;
      } else {
        rawText = await upstream.text();
        upstreamData = rawText;
        try {
          upstreamData = JSON.parse(rawText);
        } catch {
          upstreamData = rawText;
        }
      }
      if (String(selected.site.platform || '').trim().toLowerCase() === 'gemini-cli') {
        upstreamData = unwrapGeminiCliPayload(upstreamData);
      }

      const latency = Date.now() - startTime;
      const parsedUsage = parseProxyUsage(upstreamData);
      const failure = detectProxyFailure({ rawText, usage: parsedUsage });
      if (failure) {
        tokenRouter.recordFailure(selected.channel.id);
        logProxy(
          selected,
          requestedModel,
          'failed',
          failure.status,
          latency,
          failure.reason,
          retryCount,
          downstreamPath,
          parsedUsage.promptTokens,
          parsedUsage.completionTokens,
          parsedUsage.totalTokens,
          0,
          null,
          successfulUpstreamPath,
          clientContext,
          logDownstreamApiKeyId ? downstreamApiKeyId : null,
        );

        if (shouldRetryProxyRequest(failure.status, failure.reason) && retryCount < MAX_RETRIES) {
          retryCount += 1;
          continue;
        }

        await reportProxyAllFailed({
          model: requestedModel,
          reason: failure.reason,
        });

        return reply.code(failure.status).send({
          error: { message: failure.reason, type: 'upstream_error' },
        });
      }
      const normalizedFinal = downstreamTransformer.transformFinalResponse(upstreamData, modelName, rawText);
      const downstreamResponse = downstreamTransformer.serializeFinalResponse(normalizedFinal, parsedUsage);

      const resolvedUsage = await resolveProxyUsageWithSelfLogFallback({
        site: selected.site,
        account: selected.account,
        tokenValue: selected.tokenValue,
        tokenName: selected.tokenName,
        modelName,
        requestStartedAtMs: startTime,
        requestEndedAtMs: startTime + latency,
        localLatencyMs: latency,
        usage: {
          promptTokens: parsedUsage.promptTokens,
          completionTokens: parsedUsage.completionTokens,
          totalTokens: parsedUsage.totalTokens,
        },
      });

      const { estimatedCost, billingDetails } = await resolveProxyLogBilling({
        site: selected.site,
        account: selected.account,
        modelName,
        parsedUsage,
        resolvedUsage,
      });

      tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost);
      recordDownstreamCostUsage(request, estimatedCost);
      logProxy(
        selected,
        requestedModel,
        'success',
        200,
        latency,
        null,
        retryCount,
        downstreamPath,
        resolvedUsage.promptTokens,
        resolvedUsage.completionTokens,
        resolvedUsage.totalTokens,
        estimatedCost,
        billingDetails,
        successfulUpstreamPath,
        clientContext,
        logDownstreamApiKeyId ? downstreamApiKeyId : null,
      );

      return reply.send(downstreamResponse);
    } catch (err: any) {
      tokenRouter.recordFailure(selected.channel.id);
      logProxy(
        selected,
        requestedModel,
        'failed',
        0,
        Date.now() - startTime,
        err?.message || 'network error',
        retryCount,
        downstreamPath,
        0,
        0,
        0,
        0,
        null,
        null,
        clientContext,
        logDownstreamApiKeyId ? downstreamApiKeyId : null,
      );

      if (retryCount < MAX_RETRIES) {
        retryCount += 1;
        continue;
      }

      await reportProxyAllFailed({
        model: requestedModel,
        reason: err?.message || 'network failure',
      });

      return reply.code(502).send({
        error: {
          message: `Upstream error: ${err?.message || 'network failure'}`,
          type: 'upstream_error',
        },
      });
    }
  }
}

function deriveCodexSessionCacheKey(input: {
  downstreamFormat: DownstreamFormat | 'responses';
  body: unknown;
  requestedModel: string;
  proxyToken: string | null;
}): string | null {
  if (isRecord(input.body)) {
    if (input.downstreamFormat === 'claude' && isRecord(input.body.metadata)) {
      const userId = asTrimmedString(input.body.metadata.user_id);
      if (userId) return `${input.requestedModel}:claude:${userId}`;
    }
    const promptCacheKey = asTrimmedString(input.body.prompt_cache_key);
    if (promptCacheKey) return `${input.requestedModel}:responses:${promptCacheKey}`;
  }

  const proxyToken = asTrimmedString(input.proxyToken);
  if (proxyToken) {
    return `${input.requestedModel}:proxy:${proxyToken}`;
  }

  return null;
}

async function handleClaudeCountTokensRequest(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const rawBody = isRecord(request.body) ? { ...request.body } : null;
  if (!rawBody) {
    return reply.code(400).send({
      error: {
        message: 'Request body must be a JSON object',
        type: 'invalid_request_error',
      },
    });
  }

  const requestedModel = asTrimmedString(rawBody.model);
  if (!requestedModel) {
    return reply.code(400).send({
      error: {
        message: 'model is required',
        type: 'invalid_request_error',
      },
    });
  }

  if (!await ensureModelAllowedForDownstreamKey(request, reply, requestedModel)) return;
  const downstreamPath = '/v1/messages/count_tokens';
  const clientContext = detectDownstreamClientContext({
    downstreamPath,
    headers: request.headers as Record<string, unknown>,
    body: rawBody,
  });
  const downstreamPolicy = getDownstreamRoutingPolicy(request);
  const downstreamApiKeyId = getProxyAuthContext(request)?.keyId ?? null;
  const logDownstreamApiKeyId = downstreamApiKeyId !== null
    && await hasProxyLogDownstreamApiKeyIdColumn();
  const excludeChannelIds: number[] = [];
  let retryCount = 0;

  while (retryCount <= MAX_RETRIES) {
    let selected = retryCount === 0
      ? await tokenRouter.selectChannel(requestedModel, downstreamPolicy)
      : await tokenRouter.selectNextChannel(requestedModel, excludeChannelIds, downstreamPolicy);

    if (!selected && retryCount === 0) {
      await refreshModelsAndRebuildRoutes();
      selected = await tokenRouter.selectChannel(requestedModel, downstreamPolicy);
    }

    if (!selected) {
      await reportProxyAllFailed({
        model: requestedModel,
        reason: 'No available channels after retries',
      });
      return reply.code(503).send({
        error: { message: 'No available channels for this model', type: 'server_error' },
      });
    }

    excludeChannelIds.push(selected.channel.id);
    if (String(selected.site.platform || '').trim().toLowerCase() !== 'claude') {
      if (retryCount < MAX_RETRIES) {
        retryCount += 1;
        continue;
      }
      return reply.code(501).send({
        error: {
          message: 'Claude count_tokens compatibility is not implemented for this upstream',
          type: 'invalid_request_error',
        },
      });
    }

    const modelName = selected.actualModel || requestedModel;
    const oauth = getOauthInfoFromExtraConfig(selected.account.extraConfig);
    const startTime = Date.now();

    const buildRequest = () => {
      const upstreamRequest = buildClaudeCountTokensUpstreamRequest({
        modelName,
        tokenValue: selected.tokenValue,
        oauthProvider: oauth?.provider,
        sitePlatform: selected.site.platform,
        claudeBody: rawBody,
        downstreamHeaders: request.headers as Record<string, unknown>,
      });
      return {
        endpoint: 'messages' as const,
        path: upstreamRequest.path,
        headers: upstreamRequest.headers,
        body: upstreamRequest.body,
        runtime: upstreamRequest.runtime,
      };
    };

    try {
      let upstreamRequest = buildRequest();
      let upstream = await dispatchRuntimeRequest({
        siteUrl: selected.site.url,
        request: upstreamRequest,
        buildInit: (_requestUrl, requestForFetch) => withSiteRecordProxyRequestInit(selected.site, {
          method: 'POST',
          headers: requestForFetch.headers,
          body: JSON.stringify(requestForFetch.body),
        }),
      });

      if (upstream.status === 401 && oauth) {
        try {
          const refreshed = await refreshOauthAccessTokenSingleflight(selected.account.id);
          selected.tokenValue = refreshed.accessToken;
          selected.account = {
            ...selected.account,
            accessToken: refreshed.accessToken,
            extraConfig: refreshed.extraConfig ?? selected.account.extraConfig,
          };
          upstreamRequest = buildRequest();
          upstream = await dispatchRuntimeRequest({
            siteUrl: selected.site.url,
            request: upstreamRequest,
            buildInit: (_requestUrl, requestForFetch) => withSiteRecordProxyRequestInit(selected.site, {
              method: 'POST',
              headers: requestForFetch.headers,
              body: JSON.stringify(requestForFetch.body),
            }),
          });
        } catch {
          // Fall through to the regular upstream error handling below.
        }
      }

      const latency = Date.now() - startTime;
      const contentType = upstream.headers.get('content-type') || 'application/json';
      const text = await upstream.text();
      let payload: unknown = text;
      try {
        payload = JSON.parse(text);
      } catch {
        payload = text;
      }

      if (!upstream.ok) {
        tokenRouter.recordFailure(selected.channel.id);
        logProxy(
          selected,
          requestedModel,
          'failed',
          upstream.status,
          latency,
          typeof payload === 'string' ? payload : JSON.stringify(payload),
          retryCount,
          downstreamPath,
          0,
          0,
          0,
          0,
          null,
          upstreamRequest.path,
          clientContext,
          logDownstreamApiKeyId ? downstreamApiKeyId : null,
        );
        if (shouldRetryProxyRequest(upstream.status, typeof payload === 'string' ? payload : text) && retryCount < MAX_RETRIES) {
          retryCount += 1;
          continue;
        }
        return reply.code(upstream.status).type(contentType).send(payload);
      }

      tokenRouter.recordSuccess(selected.channel.id, latency, 0);
      recordDownstreamCostUsage(request, 0);
      logProxy(
        selected,
        requestedModel,
        'success',
        upstream.status,
        latency,
        null,
        retryCount,
        downstreamPath,
        0,
        0,
        0,
        0,
        null,
        upstreamRequest.path,
        clientContext,
        logDownstreamApiKeyId ? downstreamApiKeyId : null,
      );
      return reply.code(upstream.status).type(contentType).send(payload);
    } catch (error: any) {
      tokenRouter.recordFailure(selected.channel.id);
      logProxy(
        selected,
        requestedModel,
        'failed',
        0,
        Date.now() - startTime,
        error?.message || 'network error',
        retryCount,
        downstreamPath,
        0,
        0,
        0,
        0,
        null,
        null,
        clientContext,
        logDownstreamApiKeyId ? downstreamApiKeyId : null,
      );
      if (retryCount < MAX_RETRIES) {
        retryCount += 1;
        continue;
      }
      return reply.code(502).send({
        error: {
          message: `Upstream error: ${error?.message || 'network failure'}`,
          type: 'upstream_error',
        },
      });
    }
  }
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
  promptTokens = 0,
  completionTokens = 0,
  totalTokens = 0,
  estimatedCost = 0,
  billingDetails: unknown = null,
  upstreamPath: string | null = null,
  clientContext: DownstreamClientContext | null = null,
  downstreamApiKeyId: number | null = null,
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
    await db.insert(schema.proxyLogs).values({
      routeId: selected.channel.routeId,
      channelId: selected.channel.id,
      accountId: selected.account.id,
      ...(downstreamApiKeyId !== null ? { downstreamApiKeyId } : {}),
      modelRequested,
      modelActual: selected.actualModel,
      status,
      httpStatus,
      latencyMs,
      promptTokens,
      completionTokens,
      totalTokens,
      estimatedCost,
      billingDetails: billingDetails ? JSON.stringify(billingDetails) : null,
      errorMessage: normalizedErrorMessage,
      retryCount,
      createdAt,
    }).run();
  } catch (error) {
    console.warn('[proxy/chat] failed to write proxy log', error);
  }
}
