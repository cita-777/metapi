import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { db, hasProxyLogDownstreamApiKeyIdColumn, schema } from '../../db/index.js';
import { tokenRouter } from '../../services/tokenRouter.js';
import { refreshModelsAndRebuildRoutes } from '../../services/modelService.js';
import { reportProxyAllFailed, reportTokenExpired } from '../../services/alertService.js';
import { isTokenExpiredError } from '../../services/alertRules.js';
import { shouldRetryProxyRequest } from '../../services/proxyRetryPolicy.js';
import { resolveProxyUsageWithSelfLogFallback } from '../../services/proxyUsageFallbackService.js';
import { mergeProxyUsage, parseProxyUsage } from '../../services/proxyUsageParser.js';
import { resolveProxyUrlForSite, withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import { openAiResponsesTransformer } from '../../transformers/openai/responses/index.js';
import {
  buildUpstreamEndpointRequest,
  resolveUpstreamEndpointCandidates,
} from './upstreamEndpoint.js';
import { ensureModelAllowedForDownstreamKey, getDownstreamRoutingPolicy, recordDownstreamCostUsage } from './downstreamPolicy.js';
import { composeProxyLogMessage } from './logPathMeta.js';
import { executeEndpointFlow, withUpstreamPath, type BuiltEndpointRequest } from './endpointFlow.js';
import { detectProxyFailure } from './proxyFailureJudge.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';
import { resolveProxyLogBilling } from './proxyBilling.js';
import { getProxyAuthContext, getProxyResourceOwner } from '../../middleware/auth.js';
import { detectDownstreamClientContext, isCodexResponsesSurface, type DownstreamClientContext } from './downstreamClientContext.js';
import { dispatchRuntimeRequest } from './runtimeExecutor.js';
import { normalizeInputFileBlock } from '../../transformers/shared/inputFile.js';
import {
  ProxyInputFileResolutionError,
  hasNonImageFileInputInOpenAiBody,
  resolveResponsesBodyInputFiles,
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
import { ensureResponsesWebsocketTransport } from './responsesWebsocket.js';

const MAX_RETRIES = 2;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function normalizeIncludeList(value: unknown): string[] {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (typeof item === 'string' ? item.trim() : ''))
    .filter((item) => item.length > 0);
}

function hasExplicitInclude(body: Record<string, unknown>): boolean {
  return Object.prototype.hasOwnProperty.call(body, 'include');
}

function hasResponsesReasoningRequest(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const relevantKeys = ['effort', 'budget_tokens', 'budgetTokens', 'max_tokens', 'maxTokens', 'summary'];
  return relevantKeys.some((key) => {
    const entry = value[key];
    if (typeof entry === 'string') return entry.trim().length > 0;
    return entry !== undefined && entry !== null;
  });
}

function carriesResponsesReasoningContinuity(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.some((item) => carriesResponsesReasoningContinuity(item));
  }
  if (!isRecord(value)) return false;

  const type = typeof value.type === 'string' ? value.type.trim().toLowerCase() : '';
  if (type === 'reasoning') {
    if (typeof value.encrypted_content === 'string' && value.encrypted_content.trim()) {
      return true;
    }
    if (Array.isArray(value.summary) && value.summary.length > 0) {
      return true;
    }
  }

  if (typeof value.reasoning_signature === 'string' && value.reasoning_signature.trim()) {
    return true;
  }

  return carriesResponsesReasoningContinuity(value.input)
    || carriesResponsesReasoningContinuity(value.content);
}

function wantsNativeResponsesReasoning(body: unknown): boolean {
  if (!isRecord(body)) return false;
  const include = normalizeIncludeList(body.include);
  if (include.some((item) => item.toLowerCase() === 'reasoning.encrypted_content')) {
    return true;
  }
  if (carriesResponsesReasoningContinuity(body.input)) {
    return true;
  }
  if (hasExplicitInclude(body)) {
    return false;
  }
  return hasResponsesReasoningRequest(body.reasoning);
}

function carriesResponsesFileUrlInput(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.some((item) => carriesResponsesFileUrlInput(item));
  }
  if (!isRecord(value)) return false;

  const normalizedFile = normalizeInputFileBlock(value);
  if (normalizedFile?.fileUrl) return true;

  return Object.values(value).some((entry) => carriesResponsesFileUrlInput(entry));
}

type UsageSummary = ReturnType<typeof parseProxyUsage>;

function deriveCodexExplicitSessionId(body: Record<string, unknown>): string | null {
  const promptCacheKey = typeof body.prompt_cache_key === 'string'
    ? body.prompt_cache_key.trim()
    : '';
  return promptCacheKey || null;
}

export async function responsesProxyRoute(app: FastifyInstance) {
  ensureResponsesWebsocketTransport(app);
  const handleResponsesRequest = async (
    request: FastifyRequest,
    reply: FastifyReply,
    downstreamPath: string,
  ) => {
    const body = request.body as Record<string, unknown>;
    const clientContext = detectDownstreamClientContext({
      downstreamPath,
      headers: request.headers as Record<string, unknown>,
      body,
    });
    const defaultEncryptedReasoningInclude = isCodexResponsesSurface(
      request.headers as Record<string, unknown>,
    );
    const parsedRequestEnvelope = openAiResponsesTransformer.transformRequest(body, {
      defaultEncryptedReasoningInclude,
    });
    if (parsedRequestEnvelope.error) {
      return reply.code(parsedRequestEnvelope.error.statusCode).send(parsedRequestEnvelope.error.payload);
    }
    const requestEnvelope = parsedRequestEnvelope.value!;
    const requestedModel = requestEnvelope.model;
    const isStream = requestEnvelope.stream;
    const isCompactRequest = downstreamPath === '/v1/responses/compact';
    if (isCompactRequest && isStream) {
      return reply.code(400).send({
        error: {
          message: 'stream is not supported on /v1/responses/compact',
          type: 'invalid_request_error',
        },
      });
    }
    if (!await ensureModelAllowedForDownstreamKey(request, reply, requestedModel)) return;
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

      const modelName = selected.actualModel || requestedModel;
      const oauth = getOauthInfoFromExtraConfig(selected.account.extraConfig);
      const isCodexSite = String(selected.site.platform || '').trim().toLowerCase() === 'codex';
      const owner = getProxyResourceOwner(request);
      let normalizedResponsesBody: Record<string, unknown> = {
        ...requestEnvelope.parsed.normalizedBody,
        model: modelName,
        stream: isStream,
      };
      if (body.generate === false) {
        normalizedResponsesBody.generate = false;
      }
      if (owner) {
        try {
          normalizedResponsesBody = await resolveResponsesBodyInputFiles(normalizedResponsesBody, owner);
        } catch (error) {
          if (error instanceof ProxyInputFileResolutionError) {
            return reply.code(error.statusCode).send(error.payload);
          }
          throw error;
        }
      }
      const openAiBody = openAiResponsesTransformer.inbound.toOpenAiBody(
        normalizedResponsesBody,
        modelName,
        isStream,
        { defaultEncryptedReasoningInclude },
      );
      const hasNonImageFileInput = hasNonImageFileInputInOpenAiBody(openAiBody);
      const prefersNativeResponsesReasoning = wantsNativeResponsesReasoning(normalizedResponsesBody);
      const requiresNativeResponsesFileUrl = carriesResponsesFileUrlInput(normalizedResponsesBody.input);
      if (requiresNativeResponsesFileUrl && String(selected.site.platform || '').trim().toLowerCase() === 'claude') {
        return reply.code(400).send({
          error: {
            message: 'Responses input_file.file_url requires an upstream /v1/responses endpoint; current site only supports /v1/messages.',
            type: 'invalid_request_error',
          },
        });
      }
      const endpointCandidates = await resolveUpstreamEndpointCandidates(
        {
          site: selected.site,
          account: selected.account,
        },
        modelName,
        'responses',
        requestedModel,
        {
          hasNonImageFileInput,
          wantsNativeResponsesReasoning: prefersNativeResponsesReasoning,
        },
      );
      if (requiresNativeResponsesFileUrl) {
        endpointCandidates.splice(0, endpointCandidates.length, 'responses');
      }
      if (endpointCandidates.length === 0) {
        endpointCandidates.push('responses', 'chat', 'messages');
      }
      const buildProviderHeaders = () => (
        buildOauthProviderHeaders({
          extraConfig: typeof selected.account.extraConfig === 'string' ? selected.account.extraConfig : null,
          downstreamHeaders: request.headers as Record<string, unknown>,
        })
      );
      const buildEndpointRequest = (endpoint: 'chat' | 'messages' | 'responses') => {
        const upstreamStream = isStream || (isCodexSite && endpoint === 'responses');
        const codexExplicitSessionId = deriveCodexExplicitSessionId(normalizedResponsesBody);
        const endpointRequest = buildUpstreamEndpointRequest({
          endpoint,
          modelName,
          stream: upstreamStream,
          tokenValue: selected.tokenValue,
          oauthProvider: oauth?.provider,
          oauthProjectId: oauth?.projectId,
          sitePlatform: selected.site.platform,
          siteUrl: selected.site.url,
          openaiBody: openAiBody,
          downstreamFormat: 'responses',
          responsesOriginalBody: normalizedResponsesBody,
          downstreamHeaders: request.headers as Record<string, unknown>,
          providerHeaders: buildProviderHeaders(),
          codexExplicitSessionId,
        });
        const upstreamPath = (
          isCompactRequest && endpoint === 'responses'
            ? `${endpointRequest.path}/compact`
            : endpointRequest.path
        );
        return {
          endpoint,
          path: upstreamPath,
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
          buildInit: (_requestUrl, requestForFetch) => withSiteRecordProxyRequestInit(selected.site, {
            method: 'POST',
            headers: requestForFetch.headers,
            body: JSON.stringify(requestForFetch.body),
          }),
        })
      );
      const endpointStrategy = openAiResponsesTransformer.compatibility.createEndpointStrategy({
        isStream: isStream || isCodexSite,
        requiresNativeResponsesFileUrl,
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

      const startTime = Date.now();

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
          return reply.code(status).send({ error: { message: errText, type: 'upstream_error' } });
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
          let parsedUsage: UsageSummary = {
            promptTokens: 0,
            completionTokens: 0,
            totalTokens: 0,
            cacheReadTokens: 0,
            cacheCreationTokens: 0,
            promptTokensIncludeCache: null,
          };
          const writeLines = (lines: string[]) => {
            for (const line of lines) reply.raw.write(line);
          };
          const streamSession = openAiResponsesTransformer.proxyStream.createSession({
            modelName,
            successfulUpstreamPath,
            strictTerminalEvents: Object.entries(request.headers as Record<string, unknown>)
              .some(([rawKey, rawValue]) => rawKey.trim().toLowerCase() === 'x-metapi-responses-websocket-transport'
                && String(rawValue).trim() === '1'),
            getUsage: () => parsedUsage,
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

          if (!upstreamContentType.includes('text/event-stream')) {
            const rawText = await upstream.text();
            let upstreamData: unknown = rawText;
            try {
              upstreamData = JSON.parse(rawText);
            } catch {
              upstreamData = rawText;
            }
            if (String(selected.site.platform || '').trim().toLowerCase() === 'gemini-cli') {
              upstreamData = unwrapGeminiCliPayload(upstreamData);
            }

            parsedUsage = parseProxyUsage(upstreamData);
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
              return reply.code(failure.status).send({ error: { message: failure.reason, type: 'upstream_error' } });
            }

            startSseResponse();
            const streamResult = streamSession.consumeUpstreamFinalPayload(upstreamData, rawText, reply.raw);
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

            const resolvedUsage = await resolveProxyUsageWithSelfLogFallback({
              site: selected.site,
              account: selected.account,
              tokenValue: selected.tokenValue,
              tokenName: selected.tokenName,
              modelName: selected.actualModel || requestedModel,
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
              modelName: selected.actualModel || requestedModel,
              parsedUsage,
              resolvedUsage,
            });

            tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost);
            recordDownstreamCostUsage(request, estimatedCost);
            logProxy(
              selected, requestedModel, 'success', 200, latency, null, retryCount, downstreamPath,
              resolvedUsage.promptTokens, resolvedUsage.completionTokens, resolvedUsage.totalTokens, estimatedCost, billingDetails,
              successfulUpstreamPath,
              clientContext,
              logDownstreamApiKeyId ? downstreamApiKeyId : null,
            );
            return;
          }

          startSseResponse();

          const upstreamReader = upstream.body?.getReader();
          const baseReader = String(selected.site.platform || '').trim().toLowerCase() === 'gemini-cli' && upstreamReader
            ? createGeminiCliStreamReader(upstreamReader)
            : upstreamReader;
          let rawText = '';
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

          // Once SSE has been hijacked and bytes may already be on the wire, we
          // must not attempt to convert stream failures into a fresh HTTP error
          // response or retry on another channel. Responses stream failures are
          // handled in-band by the proxy stream session.

          const resolvedUsage = await resolveProxyUsageWithSelfLogFallback({
            site: selected.site,
            account: selected.account,
            tokenValue: selected.tokenValue,
            tokenName: selected.tokenName,
            modelName: selected.actualModel || requestedModel,
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
            modelName: selected.actualModel || requestedModel,
            parsedUsage,
            resolvedUsage,
          });
          tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost);
          recordDownstreamCostUsage(request, estimatedCost);
          logProxy(
            selected, requestedModel, 'success', 200, latency, null, retryCount, downstreamPath,
            resolvedUsage.promptTokens, resolvedUsage.completionTokens, resolvedUsage.totalTokens, estimatedCost, billingDetails,
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
          return reply.code(failure.status).send({ error: { message: failure.reason, type: 'upstream_error' } });
        }
        const normalized = openAiResponsesTransformer.transformFinalResponse(
          upstreamData,
          modelName,
          rawText,
        );
        const downstreamData = openAiResponsesTransformer.outbound.serializeFinal({
          upstreamPayload: upstreamData,
          normalized,
          usage: parsedUsage,
          serializationMode: isCompactRequest ? 'compact' : 'response',
        });
        const resolvedUsage = await resolveProxyUsageWithSelfLogFallback({
          site: selected.site,
          account: selected.account,
          tokenValue: selected.tokenValue,
          tokenName: selected.tokenName,
          modelName: selected.actualModel || requestedModel,
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
          modelName: selected.actualModel || requestedModel,
          parsedUsage,
          resolvedUsage,
        });

        tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost);
        recordDownstreamCostUsage(request, estimatedCost);
        logProxy(
          selected, requestedModel, 'success', 200, latency, null, retryCount, downstreamPath,
          resolvedUsage.promptTokens, resolvedUsage.completionTokens, resolvedUsage.totalTokens, estimatedCost, billingDetails,
          successfulUpstreamPath,
          clientContext,
          logDownstreamApiKeyId ? downstreamApiKeyId : null,
        );
        return reply.send(downstreamData);
      } catch (err: any) {
        tokenRouter.recordFailure(selected.channel.id);
        logProxy(
          selected,
          requestedModel,
          'failed',
          0,
          Date.now() - startTime,
          err.message,
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
          reason: err.message || 'network failure',
        });
        return reply.code(502).send({
          error: { message: `Upstream error: ${err.message}`, type: 'upstream_error' },
        });
      }
    }
  };

  app.post('/v1/responses', async (request: FastifyRequest, reply: FastifyReply) =>
    handleResponsesRequest(request, reply, '/v1/responses'));
  app.get('/v1/responses', async (_request: FastifyRequest, reply: FastifyReply) =>
    reply.code(426).send({
      error: {
        message: 'WebSocket upgrade required for GET /v1/responses',
        type: 'invalid_request_error',
      },
    }));
  app.post('/v1/responses/compact', async (request: FastifyRequest, reply: FastifyReply) =>
    handleResponsesRequest(request, reply, '/v1/responses/compact'));
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
    console.warn('[proxy/responses] failed to write proxy log', error);
  }
}
