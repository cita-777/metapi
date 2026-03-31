import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { fetch } from 'undici';
import { tokenRouter } from '../../services/tokenRouter.js';
import { reportProxyAllFailed, reportTokenExpired } from '../../services/alertService.js';
import { isTokenExpiredError } from '../../services/alertRules.js';
import { shouldRetryProxyRequest } from '../../services/proxyRetryPolicy.js';
import { ensureModelAllowedForDownstreamKey, getDownstreamRoutingPolicy, recordDownstreamCostUsage } from './downstreamPolicy.js';
import { withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import { getProxyUrlFromExtraConfig } from '../../services/accountExtraConfig.js';
import { composeProxyLogMessage } from './logPathMeta.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';
import { getProxyAuthContext } from '../../middleware/auth.js';
import { buildUpstreamUrl } from './upstreamUrl.js';
import { detectDownstreamClientContext, type DownstreamClientContext } from './downstreamClientContext.js';
import { insertProxyLog } from '../../services/proxyLogStore.js';
import { getProxyMaxChannelRetries } from '../../services/proxyChannelRetry.js';
import {
  buildForcedChannelUnavailableMessage,
  canRetryChannelSelection,
  getTesterForcedChannelId,
  selectProxyChannelForAttempt,
} from '../../proxy-core/channelSelection.js';
const DEFAULT_SEARCH_MODEL = '__search';
const DEFAULT_MAX_RESULTS = 10;
const MAX_MAX_RESULTS = 20;

export async function searchProxyRoute(app: FastifyInstance) {
  app.post('/v1/search', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = (request.body || {}) as Record<string, unknown>;
    const query = typeof body.query === 'string' ? body.query.trim() : '';
    if (!query) {
      return reply.code(400).send({
        error: { message: 'query is required', type: 'invalid_request_error' },
      });
    }
    if (body.stream === true) {
      return reply.code(400).send({
        error: { message: 'search does not support streaming', type: 'invalid_request_error' },
      });
    }
    const rawMaxResults = body.max_results;
    const maxResults = rawMaxResults == null
      ? DEFAULT_MAX_RESULTS
      : (typeof rawMaxResults === 'number' && Number.isInteger(rawMaxResults)
        ? rawMaxResults
        : NaN);
    if (!Number.isInteger(maxResults) || maxResults < 1 || maxResults > MAX_MAX_RESULTS) {
      return reply.code(400).send({
        error: {
          message: `max_results must be an integer between 1 and ${MAX_MAX_RESULTS}`,
          type: 'invalid_request_error',
        },
      });
    }

    const requestedModel = typeof body.model === 'string' && body.model.trim().length > 0
      ? body.model.trim()
      : DEFAULT_SEARCH_MODEL;

    if (!await ensureModelAllowedForDownstreamKey(request, reply, requestedModel)) return;
    const downstreamPolicy = getDownstreamRoutingPolicy(request);
    const forcedChannelId = getTesterForcedChannelId({
      headers: request.headers as Record<string, unknown>,
      clientIp: request.ip,
    });
    const downstreamApiKeyId = getProxyAuthContext(request)?.keyId ?? null;
    const downstreamPath = '/v1/search';
    const clientContext = detectDownstreamClientContext({
      downstreamPath,
      headers: request.headers as Record<string, unknown>,
      body,
    });
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
        return reply.code(503).send({
          error: { message: noChannelMessage, type: 'server_error' },
        });
      }

      excludeChannelIds.push(selected.channel.id);
      const targetUrl = buildUpstreamUrl(selected.site.url, '/v1/search');
      const upstreamModel = selected.actualModel || requestedModel;
      const forwardBody = {
        ...body,
        max_results: maxResults,
        model: upstreamModel,
      };
      const startTime = Date.now();

      try {
        const upstream = await fetch(targetUrl, withSiteRecordProxyRequestInit(selected.site, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${selected.tokenValue}`,
          },
          body: JSON.stringify(forwardBody),
        }, getProxyUrlFromExtraConfig(selected.account.extraConfig)));

        const text = await upstream.text();
        if (!upstream.ok) {
          await recordTokenRouterEventBestEffort('record channel failure', () => tokenRouter.recordFailure(selected.channel.id, {
            status: upstream.status,
            errorText: text,
            modelName: upstreamModel,
          }));
          logProxy(
            selected,
            requestedModel,
            'failed',
            upstream.status,
            Date.now() - startTime,
            text,
            retryCount,
            downstreamApiKeyId,
            clientContext,
            downstreamPath,
          );
          if (isTokenExpiredError({ status: upstream.status, message: text })) {
            await reportTokenExpired({
              accountId: selected.account.id,
              username: selected.account.username,
              siteName: selected.site.name,
              detail: `HTTP ${upstream.status}`,
            });
          }
          if (shouldRetryProxyRequest(upstream.status, text) && canRetryChannelSelection(retryCount, forcedChannelId)) {
            retryCount += 1;
            continue;
          }
          await reportProxyAllFailed({
            model: requestedModel,
            reason: `upstream returned HTTP ${upstream.status}`,
          });
          return reply.code(upstream.status).send({ error: { message: text, type: 'upstream_error' } });
        }

        let data: any = {};
        try { data = JSON.parse(text); } catch { data = { data: [] }; }

        const latency = Date.now() - startTime;
        await recordTokenRouterEventBestEffort('record channel success', () => (
          tokenRouter.recordSuccess(selected.channel.id, latency, 0, upstreamModel)
        ));
        recordDownstreamCostUsage(request, 0);
        logProxy(selected, requestedModel, 'success', upstream.status, latency, null, retryCount, downstreamApiKeyId, clientContext, downstreamPath);
        return reply.code(upstream.status).send(data);
      } catch (error: any) {
        await recordTokenRouterEventBestEffort('record channel failure', () => tokenRouter.recordFailure(selected.channel.id, {
          status: 0,
          errorText: error?.message || 'network error',
          modelName: upstreamModel,
        }));
        logProxy(
          selected,
          requestedModel,
          'failed',
          0,
          Date.now() - startTime,
          error?.message || 'network error',
          retryCount,
          downstreamApiKeyId,
          clientContext,
          downstreamPath,
        );
        if (canRetryChannelSelection(retryCount, forcedChannelId)) {
          retryCount += 1;
          continue;
        }
        await reportProxyAllFailed({
          model: requestedModel,
          reason: error?.message || 'network failure',
        });
        return reply.code(502).send({
          error: { message: error?.message || 'network failure', type: 'upstream_error' },
        });
      }
    }
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
  downstreamApiKeyId: number | null = null,
  clientContext: DownstreamClientContext | null = null,
  downstreamPath = '/v1/search',
) {
  try {
    const createdAt = formatUtcSqlDateTime(new Date());
    await insertProxyLog({
      routeId: selected.channel.routeId,
      channelId: selected.channel.id,
      accountId: selected.account.id,
      downstreamApiKeyId,
      modelRequested,
      modelActual: selected.actualModel || modelRequested,
      status,
      httpStatus,
      latencyMs,
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      estimatedCost: 0,
      errorMessage: composeProxyLogMessage({
        clientKind: clientContext?.clientKind && clientContext.clientKind !== 'generic'
          ? clientContext.clientKind
          : null,
        sessionId: clientContext?.sessionId || null,
        traceHint: clientContext?.traceHint || null,
        downstreamPath,
        errorMessage,
      }),
      clientFamily: clientContext?.clientKind || null,
      clientAppId: clientContext?.clientAppId || null,
      clientAppName: clientContext?.clientAppName || null,
      clientConfidence: clientContext?.clientConfidence || null,
      retryCount,
      createdAt,
    });
  } catch (error) {
    console.warn('[proxy/search] failed to write proxy log', error);
  }
}

async function recordTokenRouterEventBestEffort(
  label: string,
  operation: () => Promise<unknown>,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    console.warn(`[proxy/search] failed to ${label}`, error);
  }
}
