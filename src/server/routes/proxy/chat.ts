import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { tokenRouter } from '../../services/tokenRouter.js';
import { db, hasProxyLogDownstreamApiKeyIdColumn, schema } from '../../db/index.js';
import { fetch } from 'undici';
import { refreshModelsAndRebuildRoutes } from '../../services/modelService.js';
import { reportProxyAllFailed, reportTokenExpired } from '../../services/alertService.js';
import { isTokenExpiredError } from '../../services/alertRules.js';
import { shouldRetryProxyRequest } from '../../services/proxyRetryPolicy.js';
import { resolveProxyUsageWithSelfLogFallback } from '../../services/proxyUsageFallbackService.js';
import { mergeProxyUsage, parseProxyUsage } from '../../services/proxyUsageParser.js';
import { resolveProxyUrlForSite, withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import { type DownstreamFormat } from '../../transformers/shared/normalized.js';
import {
  buildUpstreamEndpointRequest,
  resolveUpstreamEndpointCandidates,
} from './upstreamEndpoint.js';
import {
  ensureModelAllowedForDownstreamKey,
  getDownstreamRoutingPolicy,
  recordDownstreamCostUsage,
} from './downstreamPolicy.js';
import { composeProxyLogMessage } from './logPathMeta.js';
import { executeEndpointFlow, withUpstreamPath } from './endpointFlow.js';
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

const MAX_RETRIES = 2;

export async function chatProxyRoute(app: FastifyInstance) {
  app.post('/v1/chat/completions', async (request: FastifyRequest, reply: FastifyReply) =>
    handleChatProxyRequest(request, reply, 'openai'));
}

export async function claudeMessagesProxyRoute(app: FastifyInstance) {
  app.post('/v1/messages', async (request: FastifyRequest, reply: FastifyReply) =>
    handleChatProxyRequest(request, reply, 'claude'));
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
    const buildEndpointRequest = (
      endpoint: 'chat' | 'messages' | 'responses',
      options: { forceNormalizeClaudeBody?: boolean } = {},
    ) => {
      const endpointRequest = buildUpstreamEndpointRequest({
        endpoint,
        modelName,
        stream: isStream,
        tokenValue: selected.tokenValue,
        sitePlatform: selected.site.platform,
        siteUrl: selected.site.url,
        openaiBody: resolvedOpenAiBody,
        downstreamFormat,
        claudeOriginalBody,
        forceNormalizeClaudeBody: options.forceNormalizeClaudeBody,
        downstreamHeaders: request.headers as Record<string, unknown>,
      });
      return {
        endpoint,
        path: endpointRequest.path,
        headers: endpointRequest.headers,
        body: endpointRequest.body as Record<string, unknown>,
      };
    };
    const endpointStrategy = downstreamTransformer.compatibility.createEndpointStrategy({
      downstreamFormat,
      endpointCandidates,
      modelName,
      requestedModelHint: requestedModel,
      sitePlatform: selected.site.platform,
      isStream,
      buildRequest: ({ endpoint, forceNormalizeClaudeBody }) => buildEndpointRequest(
        endpoint,
        { forceNormalizeClaudeBody },
      ),
      dispatchRequest: (compatibilityRequest, targetUrl) => fetch(
        targetUrl ?? `${selected.site.url}${compatibilityRequest.path}`,
        withSiteRecordProxyRequestInit(selected.site, {
          method: 'POST',
          headers: compatibilityRequest.headers,
          body: JSON.stringify(compatibilityRequest.body),
        }),
      ),
    });
    let startTime = Date.now();

    try {
      const endpointResult = await executeEndpointFlow({
        siteUrl: selected.site.url,
        proxyUrl: resolveProxyUrlForSite(selected.site),
        endpointCandidates,
        buildRequest: (endpoint) => buildEndpointRequest(endpoint),
        tryRecover: endpointStrategy.tryRecover,
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
        reply.hijack();
        reply.raw.statusCode = 200;
        reply.raw.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
        reply.raw.setHeader('Cache-Control', 'no-cache, no-transform');
        reply.raw.setHeader('Connection', 'keep-alive');
        reply.raw.setHeader('X-Accel-Buffering', 'no');

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

        const upstreamContentType = (upstream.headers.get('content-type') || '').toLowerCase();
        if (!upstreamContentType.includes('text/event-stream')) {
          const fallbackText = await upstream.text();
          let fallbackData: unknown = null;
          try {
            fallbackData = JSON.parse(fallbackText);
          } catch {
            fallbackData = fallbackText;
          }
          streamSession.consumeUpstreamFinalPayload(fallbackData, fallbackText, reply.raw);

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

        const reader = upstream.body?.getReader();
        await streamSession.run(reader, reply.raw);

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

      const rawText = await upstream.text();
      let upstreamData: unknown = rawText;
      try {
        upstreamData = JSON.parse(rawText);
      } catch {
        upstreamData = rawText;
      }

      const latency = Date.now() - startTime;
      const parsedUsage = parseProxyUsage(upstreamData);
      const failure = detectProxyFailure({ rawText, totalTokens: parsedUsage.totalTokens });
      if (failure) {
        const errText = withUpstreamPath(successfulUpstreamPath, failure.reason);
        tokenRouter.recordFailure(selected.channel.id);
        logProxy(
          selected,
          requestedModel,
          'failed',
          failure.status,
          latency,
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

        if (shouldRetryProxyRequest(failure.status, errText) && retryCount < MAX_RETRIES) {
          retryCount += 1;
          continue;
        }

        await reportProxyAllFailed({
          model: requestedModel,
          reason: failure.reason,
        });

        return reply.code(failure.status).send({
          error: { message: errText, type: 'upstream_error' },
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
