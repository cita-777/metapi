import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { fetch } from 'undici';
import { config } from '../../config.js';
import { tokenRouter } from '../../services/tokenRouter.js';
import { reportProxyAllFailed, reportTokenExpired } from '../../services/alertService.js';
import { isTokenExpiredError } from '../../services/alertRules.js';
import { shouldRetryProxyRequest } from '../../services/proxyRetryPolicy.js';
import { resolveProxyUsageWithSelfLogFallback } from '../../services/proxyUsageFallbackService.js';
import { parseProxyUsage } from '../../services/proxyUsageParser.js';
import { ensureModelAllowedForDownstreamKey, getDownstreamRoutingPolicy, recordDownstreamCostUsage } from './downstreamPolicy.js';
import { withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import { getProxyUrlFromExtraConfig } from '../../services/accountExtraConfig.js';
import { composeProxyLogMessage } from '../../services/proxyLogMessage.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';
import { resolveProxyLogBilling } from './proxyBilling.js';
import { getProxyAuthContext } from '../../middleware/auth.js';
import { buildUpstreamUrl } from './upstreamUrl.js';
import { detectDownstreamClientContext, type DownstreamClientContext } from '../../proxy-core/downstreamClientContext.js';
import { insertProxyLog } from '../../services/proxyLogStore.js';
import { fetchWithObservedFirstByte, getObservedResponseMeta } from '../../proxy-core/firstByteTimeout.js';
import { getProxyMaxChannelRetries } from '../../services/proxyChannelRetry.js';
import { runWithSiteApiEndpointPool, SiteApiEndpointRequestError } from '../../services/siteApiEndpointService.js';
import {
  buildForcedChannelUnavailableMessage,
  canRetryChannelSelection,
  getTesterForcedChannelId,
  selectProxyChannelForAttempt,
} from '../../proxy-core/channelSelection.js';

/** 转发 OpenAI 兼容的 rerank 请求，并复用标准渠道重试与计费日志链路。 */
export async function rerankProxyRoute(app: FastifyInstance) {
  app.post('/v1/rerank', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = (request.body || {}) as Record<string, unknown>;
    const requestedModel = typeof body.model === 'string' ? body.model.trim() : '';
    if (!requestedModel) {
      return reply.code(400).send({
        error: { message: 'model is required', type: 'invalid_request_error' },
      });
    }
    if (!await ensureModelAllowedForDownstreamKey(request, reply, requestedModel)) return;

    const downstreamPolicy = getDownstreamRoutingPolicy(request);
    const forcedChannelId = getTesterForcedChannelId({
      headers: request.headers as Record<string, unknown>,
      clientIp: request.ip,
    });
    const downstreamApiKeyId = getProxyAuthContext(request)?.keyId ?? null;
    const downstreamPath = '/v1/rerank';
    const clientContext = detectDownstreamClientContext({
      downstreamPath,
      headers: request.headers as Record<string, unknown>,
      body,
    });
    const firstByteTimeoutMs = Math.max(0, Math.trunc((config.proxyFirstByteTimeoutSec || 0) * 1000));
    const excludeChannelIds: number[] = [];
    let retryCount = 0;

    while (retryCount <= getProxyMaxChannelRetries()) {
      const selected = await selectProxyChannelForAttempt({
        requestedModel,
        downstreamPolicy,
        excludeChannelIds,
        retryCount,
        forcedChannelId,
});
      if (!selected) {
        const noChannelMessage = buildForcedChannelUnavailableMessage(forcedChannelId);
        await reportProxyAllFailed({
          model: requestedModel,
          reason: forcedChannelId ? noChannelMessage : 'No available channels after retries',
        });
        return reply.code(503).send({ error: { message: noChannelMessage, type: 'server_error' } });
      }

      excludeChannelIds.push(selected.channel.id);
      const upstreamModel = selected.actualModel || requestedModel;
      const forwardBody = { ...body, model: upstreamModel };
      const startTime = Date.now();

      try {
        const { upstream, text, firstByteLatencyMs } = await runWithSiteApiEndpointPool(selected.site, async (target) => {
          const attemptStartedAtMs = Date.now();
          const targetUrl = buildUpstreamUrl(target.baseUrl, '/v1/rerank');
          const response = await fetchWithObservedFirstByte(
            async (signal) => fetch(targetUrl, withSiteRecordProxyRequestInit(selected.site, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${selected.tokenValue}`,
              },
              body: JSON.stringify(forwardBody),
              signal,
            }, getProxyUrlFromExtraConfig(selected.account.extraConfig))),
            { firstByteTimeoutMs, startedAtMs: attemptStartedAtMs },
          );
          const observedFirstByteLatencyMs = getObservedResponseMeta(response)?.firstByteLatencyMs ?? null;
          const responseText = await response.text();
          if (!response.ok) {
            throw new SiteApiEndpointRequestError(responseText || 'unknown error', {
              status: response.status,
              rawErrText: responseText || null,
              firstByteLatencyMs: observedFirstByteLatencyMs,
            });
          }
          return { upstream: response, text: responseText, firstByteLatencyMs: observedFirstByteLatencyMs };
        });

        let data: unknown;
        try {
          data = JSON.parse(text);
        } catch {
          data = text;
        }
        const latency = Date.now() - startTime;
        const parsedUsage = parseProxyUsage(data);
        const resolvedUsage = await resolveProxyUsageWithSelfLogFallback({
          site: selected.site,
          account: selected.account,
          tokenValue: selected.tokenValue,
          tokenName: selected.tokenName,
          modelName: upstreamModel,
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
          modelName: upstreamModel,
          parsedUsage,
          resolvedUsage,
        });

        await recordTokenRouterEventBestEffort('record channel success', () => (
          tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost, upstreamModel)
        ));
        recordDownstreamCostUsage(request, estimatedCost);
        void logProxy(
          selected,
          requestedModel,
          'success',
          upstream.status,
          latency,
          null,
          retryCount,
          downstreamApiKeyId,
          resolvedUsage.promptTokens,
          resolvedUsage.completionTokens,
          resolvedUsage.totalTokens,
          estimatedCost,
          billingDetails,
          clientContext,
          downstreamPath,
          resolvedUsage.usageSource,
          firstByteLatencyMs,
        );
        return reply.code(upstream.status).send(data);
      } catch (error: any) {
        const status = error instanceof SiteApiEndpointRequestError ? (error.status || 0) : 0;
        const errorText = error?.message || 'network failure';
        const firstByteLatencyMs = error instanceof SiteApiEndpointRequestError ? error.firstByteLatencyMs : null;
        await recordTokenRouterEventBestEffort('record channel failure', () => tokenRouter.recordFailure(selected.channel.id, {
          status,
          errorText,
          modelName: upstreamModel,
        }));
        void logProxy(selected, requestedModel, 'failed', status, Date.now() - startTime, errorText, retryCount,
          downstreamApiKeyId, 0, 0, 0, 0, null, clientContext, downstreamPath, null, firstByteLatencyMs);
        if (status > 0 && isTokenExpiredError({ status, message: errorText })) {
          await reportTokenExpired({
            accountId: selected.account.id,
            username: selected.account.username,
            siteName: selected.site.name,
            detail: `HTTP ${status}`,
          });
        }
        if ((status > 0 ? shouldRetryProxyRequest(status, errorText) : true)
          && canRetryChannelSelection(retryCount, forcedChannelId)) {
          retryCount += 1;
          continue;
        }
        await reportProxyAllFailed({ model: requestedModel, reason: errorText || 'network failure' });
        return reply.code(status || 502).send({
          error: {
            message: status > 0 ? errorText : `Upstream error: ${errorText}`,
            type: 'upstream_error',
          },
        });
      }
    }

    return reply.code(503).send({ error: { message: 'No available channels after retries', type: 'server_error' } });
  });
}

async function logProxy(
  selected: any,
  modelRequested: string,
  status: string,
  httpStatus: number,
  latencyMs: number,
  errorMessage: string | null,
  retryCount: number,
  downstreamApiKeyId: number | null,
  promptTokens: number,
  completionTokens: number,
  totalTokens: number,
  estimatedCost: number,
  billingDetails: unknown,
  clientContext: DownstreamClientContext | null,
  downstreamPath: string,
  usageSource: 'upstream' | 'self-log' | 'unknown' | null,
  firstByteLatencyMs: number | null,
) {
  try {
    await insertProxyLog({
      routeId: selected.channel.routeId,
      channelId: selected.channel.id,
      accountId: selected.account.id,
      downstreamApiKeyId,
      modelRequested,
      modelActual: selected.actualModel || modelRequested,
      status,
      httpStatus,
      isStream: false,
      firstByteLatencyMs,
      latencyMs,
      promptTokens,
      completionTokens,
      totalTokens,
      estimatedCost,
      billingDetails,
      clientFamily: clientContext?.clientKind || null,
      clientAppId: clientContext?.clientAppId || null,
      clientAppName: clientContext?.clientAppName || null,
      clientConfidence: clientContext?.clientConfidence || null,
      errorMessage: composeProxyLogMessage({
        clientKind: clientContext?.clientKind && clientContext.clientKind !== 'generic' ? clientContext.clientKind : null,
        sessionId: clientContext?.sessionId || null,
        traceHint: clientContext?.traceHint || null,
        downstreamPath,
        usageSource,
        errorMessage,
      }),
      retryCount,
      createdAt: formatUtcSqlDateTime(new Date()),
    });
  } catch (error) {
    console.warn('[proxy/rerank] failed to write proxy log', error);
  }
}

async function recordTokenRouterEventBestEffort(label: string, operation: () => Promise<unknown>): Promise<void> {
  try {
    await operation();
  } catch (error) {
    console.warn(`[proxy/rerank] failed to ${label}`, error);
  }
}
