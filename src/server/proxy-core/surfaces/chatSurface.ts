import { TextDecoder } from 'node:util';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { tokenRouter } from '../../services/tokenRouter.js';
import { reportProxyAllFailed } from '../../services/alertService.js';
import { mergeProxyUsage, parseProxyUsage } from '../../services/proxyUsageParser.js';
import { type DownstreamFormat } from '../../transformers/shared/normalized.js';
import {
  buildClaudeCountTokensUpstreamRequest,
  buildUpstreamEndpointRequest,
  recordUpstreamEndpointFailure,
  recordUpstreamEndpointSuccess,
  resolveUpstreamEndpointCandidates,
} from '../../routes/proxy/upstreamEndpoint.js';
import {
  ensureModelAllowedForDownstreamKey,
  getDownstreamRoutingPolicy,
  recordDownstreamCostUsage,
} from '../../routes/proxy/downstreamPolicy.js';
import { executeEndpointFlow, type BuiltEndpointRequest } from '../../routes/proxy/endpointFlow.js';
import { detectProxyFailure } from '../../routes/proxy/proxyFailureJudge.js';
import { openAiChatTransformer } from '../../transformers/openai/chat/index.js';
import { anthropicMessagesTransformer } from '../../transformers/anthropic/messages/index.js';
import { getProxyAuthContext, getProxyResourceOwner } from '../../middleware/auth.js';
import {
  ProxyInputFileResolutionError,
  resolveOpenAiBodyInputFiles,
} from '../../services/proxyInputFileResolver.js';
import {
  buildOauthProviderHeaders,
} from '../../services/oauth/service.js';
import { getOauthInfoFromAccount } from '../../services/oauth/oauthAccount.js';
import {
  collectResponsesFinalPayloadFromSse,
  collectResponsesFinalPayloadFromSseText,
  createSingleChunkStreamReader,
  looksLikeResponsesSseText,
} from '../../routes/proxy/responsesSseFinal.js';
import {
  createGeminiCliStreamReader,
  unwrapGeminiCliPayload,
} from '../../routes/proxy/geminiCliCompat.js';
import { summarizeConversationFileInputsInOpenAiBody } from '../capabilities/conversationFileCapabilities.js';
import { readRuntimeResponseText } from '../executors/types.js';
import { detectDownstreamClientContext } from '../../routes/proxy/downstreamClientContext.js';
import { canRetryProxyChannel, getProxyMaxChannelRetries } from '../../services/proxyChannelRetry.js';
import {
  acquireSurfaceChannelLease,
  bindSurfaceStickyChannel,
  buildSurfaceChannelBusyMessage,
  buildSurfaceStickySessionKey,
  clearSurfaceStickyChannel,
  createSurfaceFailureToolkit,
  createSurfaceDispatchRequest,
  recordSurfaceSuccess,
  selectSurfaceChannelForAttempt,
  trySurfaceOauthRefreshRecovery,
} from './sharedSurface.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function prioritizeEndpointCandidate(
  candidates: Array<'chat' | 'messages' | 'responses'>,
  preferred: 'chat' | 'messages' | 'responses',
): Array<'chat' | 'messages' | 'responses'> {
  if (!candidates.includes(preferred)) return candidates;
  return [
    preferred,
    ...candidates.filter((candidate) => candidate !== preferred),
  ];
}

export async function handleChatSurfaceRequest(
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
  const conversationFileSummary = summarizeConversationFileInputsInOpenAiBody(resolvedOpenAiBody);
  const hasNonImageFileInput = conversationFileSummary.hasDocument;
  const codexSessionCacheKey = deriveCodexSessionCacheKey({
    downstreamFormat,
    body: downstreamFormat === 'claude' ? claudeOriginalBody : request.body,
    requestedModel,
    proxyToken: getProxyAuthContext(request)?.token || null,
  });
  const downstreamApiKeyId = getProxyAuthContext(request)?.keyId ?? null;
  const maxRetries = getProxyMaxChannelRetries();
  const failureToolkit = createSurfaceFailureToolkit({
    warningScope: 'chat',
    downstreamPath,
    maxRetries,
    clientContext,
    downstreamApiKeyId,
  });
  const stickySessionKey = buildSurfaceStickySessionKey({
    clientContext,
    requestedModel,
    downstreamPath,
    downstreamApiKeyId,
  });

  const excludeChannelIds: number[] = [];
  let retryCount = 0;

  while (retryCount <= maxRetries) {
    const selected = await selectSurfaceChannelForAttempt({
      requestedModel,
      downstreamPolicy,
      excludeChannelIds,
      retryCount,
      stickySessionKey,
    });

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
    const oauth = getOauthInfoFromAccount(selected.account);
    const isCodexSite = String(selected.site.platform || '').trim().toLowerCase() === 'codex';
    let endpointCandidates = [
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
          conversationFileSummary,
        },
      ),
    ];
    if (oauth?.provider === 'codex' && downstreamFormat === 'openai') {
      endpointCandidates = prioritizeEndpointCandidate(endpointCandidates, 'responses');
    }
    const endpointRuntimeContext = {
      siteId: selected.site.id,
      modelName,
      downstreamFormat,
      requestedModelHint: requestedModel,
      requestCapabilities: {
        hasNonImageFileInput,
        conversationFileSummary,
      },
    };
    const buildProviderHeaders = () => (
      buildOauthProviderHeaders({
        account: selected.account,
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
    const dispatchRequest = createSurfaceDispatchRequest({
      site: selected.site,
      accountExtraConfig: selected.account.extraConfig,
    });
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
      if ((ctx.response.status === 401 || ctx.response.status === 403) && oauth) {
        const recovered = await trySurfaceOauthRefreshRecovery({
          ctx,
          selected,
          siteUrl: selected.site.url,
          buildRequest: (endpoint) => buildEndpointRequest(endpoint),
          dispatchRequest,
        });
        if (recovered?.upstream?.ok) {
          return recovered;
        }
      }
      return endpointStrategy.tryRecover(ctx);
    };
    let startTime = Date.now();
    const leaseResult = await acquireSurfaceChannelLease({
      selected,
    });
    if (leaseResult.status === 'timeout') {
      clearSurfaceStickyChannel({
        stickySessionKey,
        selected,
      });
      const busyMessage = buildSurfaceChannelBusyMessage(leaseResult.waitMs);
      await failureToolkit.log({
        selected,
        modelRequested: requestedModel,
        status: 'failed',
        httpStatus: 503,
        latencyMs: leaseResult.waitMs,
        errorMessage: busyMessage,
        retryCount,
      });
      if (canRetryProxyChannel(retryCount)) {
        retryCount += 1;
        continue;
      }
      return reply.code(503).send({
        error: {
          message: busyMessage,
          type: 'server_error',
        },
      });
    }
    const channelLease = leaseResult.lease;

    try {
        const endpointResult = await executeEndpointFlow({
          siteUrl: selected.site.url,
          endpointCandidates,
          buildRequest: (endpoint) => buildEndpointRequest(endpoint),
          dispatchRequest,
          tryRecover,
          onAttemptFailure: (ctx) => {
            recordUpstreamEndpointFailure({
              ...endpointRuntimeContext,
              endpoint: ctx.request.endpoint,
              status: ctx.response.status,
              errorText: ctx.rawErrText,
            });
          },
          onAttemptSuccess: (ctx) => {
            recordUpstreamEndpointSuccess({
              ...endpointRuntimeContext,
              endpoint: ctx.request.endpoint,
            });
          },
          shouldDowngrade: endpointStrategy.shouldDowngrade,
          onDowngrade: (ctx) => {
            return failureToolkit.log({
              selected,
              modelRequested: requestedModel,
              status: 'failed',
              httpStatus: ctx.response.status,
              latencyMs: Date.now() - startTime,
              errorMessage: ctx.errText,
              retryCount,
            });
          },
        });

      if (!endpointResult.ok) {
        clearSurfaceStickyChannel({
          stickySessionKey,
          selected,
        });
        const failureOutcome = await failureToolkit.handleUpstreamFailure({
          selected,
          requestedModel,
          modelName,
          status: endpointResult.status || 502,
          errText: endpointResult.errText || 'unknown error',
          rawErrText: endpointResult.rawErrText,
          latencyMs: Date.now() - startTime,
          retryCount,
        });
        if (failureOutcome.action === 'retry') {
          retryCount += 1;
          continue;
        }
        return reply.code(failureOutcome.status).send(failureOutcome.payload);
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
          const fallbackText = await readRuntimeResponseText(upstream);
          rawText = fallbackText;
          if (looksLikeResponsesSseText(fallbackText)) {
            startSseResponse();
            const streamResult = await streamSession.run(
              createSingleChunkStreamReader(fallbackText),
              reply.raw,
            );
            const latency = Date.now() - startTime;
            if (streamResult.status === 'failed') {
              clearSurfaceStickyChannel({
                stickySessionKey,
                selected,
              });
              await failureToolkit.recordStreamFailure({
                selected,
                requestedModel,
                modelName,
                errorMessage: streamResult.errorMessage,
                latencyMs: latency,
                retryCount,
                promptTokens: parsedUsage.promptTokens,
                completionTokens: parsedUsage.completionTokens,
                totalTokens: parsedUsage.totalTokens,
                upstreamPath: successfulUpstreamPath,
              });
              return;
            }
            bindSurfaceStickyChannel({
              stickySessionKey,
              selected,
            });
            return;
          }
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
            clearSurfaceStickyChannel({
              stickySessionKey,
              selected,
            });
            const failureOutcome = await failureToolkit.handleDetectedFailure({
              selected,
              requestedModel,
              modelName,
              failure,
              latencyMs: latency,
              retryCount,
              promptTokens: parsedUsage.promptTokens,
              completionTokens: parsedUsage.completionTokens,
              totalTokens: parsedUsage.totalTokens,
              upstreamPath: successfulUpstreamPath,
            });
            if (failureOutcome.action === 'retry') {
              retryCount += 1;
              continue;
            }
            return reply.code(failureOutcome.status).send(failureOutcome.payload);
          }

          startSseResponse();
          const streamResult = streamSession.consumeUpstreamFinalPayload(fallbackData, fallbackText, reply.raw);
          if (streamResult.status === 'failed') {
            clearSurfaceStickyChannel({
              stickySessionKey,
              selected,
            });
            await failureToolkit.recordStreamFailure({
              selected,
              requestedModel,
              modelName,
              errorMessage: streamResult.errorMessage,
              latencyMs: latency,
              retryCount,
              promptTokens: parsedUsage.promptTokens,
              completionTokens: parsedUsage.completionTokens,
              totalTokens: parsedUsage.totalTokens,
              upstreamPath: successfulUpstreamPath,
              runtimeFailureStatus: 502,
            });
            return;
          }
          bindSurfaceStickyChannel({
            stickySessionKey,
            selected,
          });
        } else {
          startSseResponse();
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
            clearSurfaceStickyChannel({
              stickySessionKey,
              selected,
            });
            await failureToolkit.recordStreamFailure({
              selected,
              requestedModel,
              modelName,
              errorMessage: streamResult.errorMessage,
              latencyMs: latency,
              retryCount,
              promptTokens: parsedUsage.promptTokens,
              completionTokens: parsedUsage.completionTokens,
              totalTokens: parsedUsage.totalTokens,
              upstreamPath: successfulUpstreamPath,
              runtimeFailureStatus: 502,
            });
            return;
          }

          // Once SSE has been hijacked and streamed downstream, we can no longer
          // safely fall back to an HTTP error response or retry by switching the
          // channel mid-flight. Stream-level failures must be handled in-band by
          // the proxy stream session itself.
        }

        const latency = Date.now() - startTime;
        await recordSurfaceSuccess({
          selected,
          requestedModel,
          modelName,
          parsedUsage,
          requestStartedAtMs: startTime,
          latencyMs: latency,
          retryCount,
          upstreamPath: successfulUpstreamPath,
          logSuccess: failureToolkit.log,
          recordDownstreamCost: (estimatedCost) => {
            recordDownstreamCostUsage(request, estimatedCost);
          },
          bestEffortMetrics: {
            errorLabel: '[proxy/chat] failed to record success metrics',
          },
        });
        bindSurfaceStickyChannel({
          stickySessionKey,
          selected,
        });
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
        rawText = await readRuntimeResponseText(upstream);
        if (looksLikeResponsesSseText(rawText)) {
          upstreamData = collectResponsesFinalPayloadFromSseText(rawText, modelName).payload;
        } else {
          upstreamData = rawText;
          try {
            upstreamData = JSON.parse(rawText);
          } catch {
            upstreamData = rawText;
          }
        }
      }
      if (String(selected.site.platform || '').trim().toLowerCase() === 'gemini-cli') {
        upstreamData = unwrapGeminiCliPayload(upstreamData);
      }

      const latency = Date.now() - startTime;
      const parsedUsage = parseProxyUsage(upstreamData);
      const failure = detectProxyFailure({ rawText, usage: parsedUsage });
      if (failure) {
        clearSurfaceStickyChannel({
          stickySessionKey,
          selected,
        });
        const failureOutcome = await failureToolkit.handleDetectedFailure({
          selected,
          requestedModel,
          modelName,
          failure,
          latencyMs: latency,
          retryCount,
          promptTokens: parsedUsage.promptTokens,
          completionTokens: parsedUsage.completionTokens,
          totalTokens: parsedUsage.totalTokens,
          upstreamPath: successfulUpstreamPath,
        });
        if (failureOutcome.action === 'retry') {
          retryCount += 1;
          continue;
        }
        return reply.code(failureOutcome.status).send(failureOutcome.payload);
      }
      const normalizedFinal = downstreamTransformer.transformFinalResponse(upstreamData, modelName, rawText);
      const downstreamResponse = downstreamTransformer.serializeFinalResponse(normalizedFinal, parsedUsage);

      await recordSurfaceSuccess({
        selected,
        requestedModel,
        modelName,
        parsedUsage,
        requestStartedAtMs: startTime,
        latencyMs: latency,
        retryCount,
        upstreamPath: successfulUpstreamPath,
        logSuccess: failureToolkit.log,
        recordDownstreamCost: (estimatedCost) => {
          recordDownstreamCostUsage(request, estimatedCost);
        },
        bestEffortMetrics: {
          errorLabel: '[proxy/chat] failed to record success metrics',
        },
      });
      bindSurfaceStickyChannel({
        stickySessionKey,
        selected,
      });

      return reply.send(downstreamResponse);
      } catch (err: any) {
        clearSurfaceStickyChannel({
          stickySessionKey,
          selected,
        });
        const failureOutcome = await failureToolkit.handleExecutionError({
          selected,
          requestedModel,
        modelName,
        errorMessage: err?.message || 'network failure',
        latencyMs: Date.now() - startTime,
        retryCount,
      });
      if (failureOutcome.action === 'retry') {
        retryCount += 1;
        continue;
        }
        return reply.code(failureOutcome.status).send(failureOutcome.payload);
      } finally {
        channelLease.release();
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

export async function handleClaudeCountTokensSurfaceRequest(
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
  const maxRetries = getProxyMaxChannelRetries();
  const failureToolkit = createSurfaceFailureToolkit({
    warningScope: 'chat',
    downstreamPath,
    maxRetries,
    clientContext,
    downstreamApiKeyId,
  });
  const stickySessionKey = buildSurfaceStickySessionKey({
    clientContext,
    requestedModel,
    downstreamPath,
    downstreamApiKeyId,
  });
  const excludeChannelIds: number[] = [];
  let retryCount = 0;

  while (retryCount <= maxRetries) {
    const selected = await selectSurfaceChannelForAttempt({
      requestedModel,
      downstreamPolicy,
      excludeChannelIds,
      retryCount,
      stickySessionKey,
    });

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
    const endpointCandidates = await resolveUpstreamEndpointCandidates(
      {
        site: selected.site,
        account: selected.account,
      },
      modelName,
      'claude',
      requestedModel,
    );
    if (!endpointCandidates.includes('messages')) {
      if (canRetryProxyChannel(retryCount)) {
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
    const oauth = getOauthInfoFromAccount(selected.account);
    const startTime = Date.now();
    const leaseResult = await acquireSurfaceChannelLease({
      selected,
    });
    if (leaseResult.status === 'timeout') {
      clearSurfaceStickyChannel({
        stickySessionKey,
        selected,
      });
      const busyMessage = buildSurfaceChannelBusyMessage(leaseResult.waitMs);
      await failureToolkit.log({
        selected,
        modelRequested: requestedModel,
        status: 'failed',
        httpStatus: 503,
        latencyMs: leaseResult.waitMs,
        errorMessage: busyMessage,
        retryCount,
      });
      if (canRetryProxyChannel(retryCount)) {
        retryCount += 1;
        continue;
      }
      return reply.code(503).send({
        error: {
          message: busyMessage,
          type: 'server_error',
        },
      });
    }
    const channelLease = leaseResult.lease;

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
      const dispatchRequest = createSurfaceDispatchRequest({
        site: selected.site,
        accountExtraConfig: selected.account.extraConfig,
      });
      let upstream = await dispatchRequest(upstreamRequest);

      if ((upstream.status === 401 || upstream.status === 403) && oauth) {
        const recoverContext = {
          request: upstreamRequest,
          response: upstream,
          rawErrText: '',
        };
        const recovered = await trySurfaceOauthRefreshRecovery({
          ctx: recoverContext,
          selected,
          siteUrl: selected.site.url,
          buildRequest: () => buildRequest(),
          dispatchRequest,
          captureFailureBody: false,
        });
        if (recovered?.upstream?.ok) {
          upstreamRequest = buildRequest();
          upstream = recovered.upstream;
        } else {
          upstreamRequest = recoverContext.request;
          upstream = recoverContext.response;
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
        clearSurfaceStickyChannel({
          stickySessionKey,
          selected,
        });
        const failureOutcome = await failureToolkit.handleUpstreamFailure({
          selected,
          requestedModel,
          modelName,
          status: upstream.status,
          errText: typeof payload === 'string' ? payload : JSON.stringify(payload),
          rawErrText: typeof payload === 'string' ? payload : text,
          latencyMs: latency,
          retryCount,
        });
        if (failureOutcome.action === 'retry') {
          retryCount += 1;
          continue;
        }
        return reply.code(failureOutcome.status).send(failureOutcome.payload);
      }

      tokenRouter.recordSuccess(selected.channel.id, latency, 0, modelName);
      recordDownstreamCostUsage(request, 0);
      await failureToolkit.log({
        selected,
        modelRequested: requestedModel,
        status: 'success',
        httpStatus: upstream.status,
        latencyMs: latency,
        errorMessage: null,
        retryCount,
        upstreamPath: upstreamRequest.path,
      });
      bindSurfaceStickyChannel({
        stickySessionKey,
        selected,
      });
      return reply.code(upstream.status).type(contentType).send(payload);
    } catch (error: any) {
      clearSurfaceStickyChannel({
        stickySessionKey,
        selected,
      });
      const failureOutcome = await failureToolkit.handleExecutionError({
        selected,
        requestedModel,
        modelName,
        errorMessage: error?.message || 'network failure',
        latencyMs: Date.now() - startTime,
        retryCount,
      });
      if (failureOutcome.action === 'retry') {
        retryCount += 1;
        continue;
      }
      return reply.code(failureOutcome.status).send(failureOutcome.payload);
    } finally {
      channelLease.release();
    }
  }
}
