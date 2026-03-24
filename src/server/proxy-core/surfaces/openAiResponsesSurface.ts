import { TextDecoder } from 'node:util';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { reportProxyAllFailed } from '../../services/alertService.js';
import { mergeProxyUsage, parseProxyUsage } from '../../services/proxyUsageParser.js';
import { openAiResponsesTransformer } from '../../transformers/openai/responses/index.js';
import {
  buildUpstreamEndpointRequest,
  recordUpstreamEndpointFailure,
  recordUpstreamEndpointSuccess,
  resolveUpstreamEndpointCandidates,
} from '../../routes/proxy/upstreamEndpoint.js';
import { ensureModelAllowedForDownstreamKey, getDownstreamRoutingPolicy, recordDownstreamCostUsage } from '../../routes/proxy/downstreamPolicy.js';
import { executeEndpointFlow, type BuiltEndpointRequest } from '../../routes/proxy/endpointFlow.js';
import { detectProxyFailure } from '../../routes/proxy/proxyFailureJudge.js';
import { getProxyAuthContext, getProxyResourceOwner } from '../../middleware/auth.js';
import { normalizeInputFileBlock } from '../../transformers/shared/inputFile.js';
import {
  ProxyInputFileResolutionError,
  resolveResponsesBodyInputFiles,
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
import { isCodexResponsesSurface } from '../cliProfiles/codexProfile.js';
import {
  summarizeConversationFileInputsInOpenAiBody,
  summarizeConversationFileInputsInResponsesBody,
} from '../capabilities/conversationFileCapabilities.js';
import { detectDownstreamClientContext } from '../../routes/proxy/downstreamClientContext.js';
import { getProxyMaxChannelRetries } from '../../services/proxyChannelRetry.js';
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

function shouldRefreshOauthResponsesRequest(input: {
  oauthProvider?: string;
  status: number;
  response: { headers: { get(name: string): string | null } };
  rawErrText: string;
}): boolean {
  if (input.status === 401) return true;
  if (input.status !== 403 || input.oauthProvider !== 'codex') return false;
  const authenticate = input.response.headers.get('www-authenticate') || '';
  const combined = `${authenticate}\n${input.rawErrText || ''}`;
  return /\b(invalid_token|expired_token|expired|invalid|unauthorized|account mismatch|authentication)\b/i.test(combined);
}

type UsageSummary = ReturnType<typeof parseProxyUsage>;

export async function handleOpenAiResponsesSurfaceRequest(
  request: FastifyRequest,
  reply: FastifyReply,
  downstreamPath: '/v1/responses' | '/v1/responses/compact',
) {
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
    const maxRetries = getProxyMaxChannelRetries();
	    const failureToolkit = createSurfaceFailureToolkit({
	      warningScope: 'responses',
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
      const conversationFileSummary = summarizeConversationFileInputsInOpenAiBody(openAiBody);
      const hasNonImageFileInput = conversationFileSummary.hasDocument;
      const prefersNativeResponsesReasoning = wantsNativeResponsesReasoning(normalizedResponsesBody);
      const responsesConversationFileSummary = summarizeConversationFileInputsInResponsesBody(normalizedResponsesBody);
      const requiresNativeResponsesFileUrl = responsesConversationFileSummary.hasRemoteDocumentUrl
        || carriesResponsesFileUrlInput(normalizedResponsesBody.input);
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
          conversationFileSummary,
          wantsNativeResponsesReasoning: prefersNativeResponsesReasoning,
        },
      );
      if (endpointCandidates.length === 0) {
        endpointCandidates.push('responses', 'chat', 'messages');
      }
      const endpointRuntimeContext = {
        siteId: selected.site.id,
        modelName,
        downstreamFormat: 'responses' as const,
        requestedModelHint: requestedModel,
        requestCapabilities: {
          hasNonImageFileInput,
          conversationFileSummary,
          wantsNativeResponsesReasoning: prefersNativeResponsesReasoning,
        },
      };
      const buildProviderHeaders = () => (
        buildOauthProviderHeaders({
          account: selected.account,
          downstreamHeaders: request.headers as Record<string, unknown>,
        })
      );
      const buildEndpointRequest = (endpoint: 'chat' | 'messages' | 'responses') => {
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
          openaiBody: openAiBody,
          downstreamFormat: 'responses',
          responsesOriginalBody: normalizedResponsesBody,
          downstreamHeaders: request.headers as Record<string, unknown>,
          providerHeaders: buildProviderHeaders(),
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
      const dispatchRequest = createSurfaceDispatchRequest({
        site: selected.site,
        accountExtraConfig: selected.account.extraConfig,
      });
      const endpointStrategy = openAiResponsesTransformer.compatibility.createEndpointStrategy({
        isStream: isStream || isCodexSite,
        requiresNativeResponsesFileUrl,
        dispatchRequest,
      });
      const tryRecover = async (ctx: Parameters<NonNullable<typeof endpointStrategy.tryRecover>>[0]) => {
        if (oauth && shouldRefreshOauthResponsesRequest({
          oauthProvider: oauth.provider,
          status: ctx.response.status,
          response: ctx.response,
          rawErrText: ctx.rawErrText || '',
        })) {
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
	        retryCount += 1;
	        if (retryCount <= maxRetries) {
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
      const finalizeStreamSuccess = async (parsedUsage: UsageSummary, latency: number) => {
        try {
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
              errorLabel: '[responses] post-stream bookkeeping failed:',
            },
          });
        } catch (error) {
          console.error('[responses] post-stream success logging failed:', error);
        }
      };

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
            if (looksLikeResponsesSseText(rawText)) {
              startSseResponse();
              const streamResult = await streamSession.run(
                createSingleChunkStreamReader(rawText),
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

	              await finalizeStreamSuccess(parsedUsage, latency);
	              bindSurfaceStickyChannel({
	                stickySessionKey,
	                selected,
	              });
	              return;
	            }
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
            const streamResult = streamSession.consumeUpstreamFinalPayload(upstreamData, rawText, reply.raw);
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

	            await finalizeStreamSuccess(parsedUsage, latency);
	            bindSurfaceStickyChannel({
	              stickySessionKey,
	              selected,
	            });
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

          // Once SSE has been hijacked and bytes may already be on the wire, we
          // must not attempt to convert stream failures into a fresh HTTP error
          // response or retry on another channel. Responses stream failures are
	          // handled in-band by the proxy stream session.

	          await finalizeStreamSuccess(parsedUsage, latency);
	          bindSurfaceStickyChannel({
	            stickySessionKey,
	            selected,
	          });
	          return;
	        }

        const upstreamContentType = (upstream.headers.get('content-type') || '').toLowerCase();
        let rawText = '';
        let upstreamData: unknown;
        if (
          upstreamContentType.includes('text/event-stream')
          && (
            successfulUpstreamPath.endsWith('/responses')
            || successfulUpstreamPath.endsWith('/responses/compact')
          )
        ) {
          const collected = await collectResponsesFinalPayloadFromSse(upstream, modelName);
          rawText = collected.rawText;
          upstreamData = collected.payload;
        } else {
          rawText = await upstream.text();
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
        try {
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
              errorLabel: '[responses] post-response bookkeeping failed:',
            },
          });
	        } catch (error) {
	          console.error('[responses] post-response success logging failed:', error);
	        }
	        bindSurfaceStickyChannel({
	          stickySessionKey,
	          selected,
	        });
	        return reply.send(downstreamData);
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
