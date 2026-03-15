import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { fetch } from 'undici';
import { db, hasProxyLogDownstreamApiKeyIdColumn, schema } from '../../db/index.js';
import { tokenRouter } from '../../services/tokenRouter.js';
import { refreshModelsAndRebuildRoutes } from '../../services/modelService.js';
import { reportProxyAllFailed, reportTokenExpired } from '../../services/alertService.js';
import { isTokenExpiredError } from '../../services/alertRules.js';
import { estimateProxyCost } from '../../services/modelPricingService.js';
import { shouldRetryProxyRequest } from '../../services/proxyRetryPolicy.js';
import { ensureModelAllowedForDownstreamKey, getDownstreamRoutingPolicy, recordDownstreamCostUsage } from './downstreamPolicy.js';
import { withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import { composeProxyLogMessage } from './logPathMeta.js';
import { formatUtcSqlDateTime } from '../../services/localTimeService.js';
import { cloneFormDataWithOverrides, ensureMultipartBufferParser, parseMultipartFormData } from './multipart.js';
import { getProxyAuthContext } from '../../middleware/auth.js';
import { buildUpstreamUrl } from './upstreamUrl.js';

const MAX_RETRIES = 2;

export async function imagesProxyRoute(app: FastifyInstance) {
  ensureMultipartBufferParser(app);

  app.post('/v1/images/generations', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as any;
    const requestedModel = body?.model || 'gpt-image-1';
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

      const targetUrl = buildUpstreamUrl(selected.site.url, '/v1/images/generations');
      const forwardBody = { ...body, model: selected.actualModel };
      const startTime = Date.now();

      try {
        const upstream = await fetch(targetUrl, withSiteRecordProxyRequestInit(selected.site, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${selected.tokenValue}`,
          },
          body: JSON.stringify(forwardBody),
        }));

        const text = await upstream.text();
        if (!upstream.ok) {
          tokenRouter.recordFailure(selected.channel.id);
          logProxy(selected, requestedModel, 'failed', upstream.status, Date.now() - startTime, text, retryCount, logDownstreamApiKeyId ? downstreamApiKeyId : null);
          if (isTokenExpiredError({ status: upstream.status, message: text })) {
            await reportTokenExpired({
              accountId: selected.account.id,
              username: selected.account.username,
              siteName: selected.site.name,
              detail: `HTTP ${upstream.status}`,
            });
          }
          if (shouldRetryProxyRequest(upstream.status, text) && retryCount < MAX_RETRIES) {
            retryCount++;
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
        const estimatedCost = await estimateProxyCost({
          site: selected.site,
          account: selected.account,
          modelName: selected.actualModel || requestedModel,
          promptTokens: 0,
          completionTokens: 0,
          totalTokens: 0,
        });
        tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost);
        recordDownstreamCostUsage(request, estimatedCost);
        logProxy(selected, requestedModel, 'success', upstream.status, latency, null, retryCount, logDownstreamApiKeyId ? downstreamApiKeyId : null, estimatedCost);
        return reply.code(upstream.status).send(data);
      } catch (err: any) {
        tokenRouter.recordFailure(selected.channel.id);
        logProxy(selected, requestedModel, 'failed', 0, Date.now() - startTime, err.message, retryCount, logDownstreamApiKeyId ? downstreamApiKeyId : null);
        if (retryCount < MAX_RETRIES) {
          retryCount++;
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
  });

  app.post('/v1/images/edits', async (request: FastifyRequest, reply: FastifyReply) => {
    const multipartForm = await parseMultipartFormData(request);
    const jsonBody = (!multipartForm && request.body && typeof request.body === 'object')
      ? request.body as Record<string, unknown>
      : null;
    const requestedModel = typeof multipartForm?.get('model') === 'string'
      ? String(multipartForm.get('model')).trim()
      : (typeof jsonBody?.model === 'string' ? jsonBody.model.trim() : '') || 'gpt-image-1';

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
      const targetUrl = buildUpstreamUrl(selected.site.url, '/v1/images/edits');
      const startTime = Date.now();

      try {
        const requestInit = multipartForm
          ? withSiteRecordProxyRequestInit(selected.site, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${selected.tokenValue}`,
            },
            body: cloneFormDataWithOverrides(multipartForm, {
              model: selected.actualModel || requestedModel,
            }) as any,
          })
          : withSiteRecordProxyRequestInit(selected.site, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${selected.tokenValue}`,
            },
            body: JSON.stringify({
              ...(jsonBody || {}),
              model: selected.actualModel || requestedModel,
            }),
          });

        const upstream = await fetch(targetUrl, requestInit);
        const text = await upstream.text();
        if (!upstream.ok) {
          tokenRouter.recordFailure(selected.channel.id);
          logProxy(selected, requestedModel, 'failed', upstream.status, Date.now() - startTime, text, retryCount, logDownstreamApiKeyId ? downstreamApiKeyId : null, 0, '/v1/images/edits');
          if (isTokenExpiredError({ status: upstream.status, message: text })) {
            await reportTokenExpired({
              accountId: selected.account.id,
              username: selected.account.username,
              siteName: selected.site.name,
              detail: `HTTP ${upstream.status}`,
            });
          }
          if (shouldRetryProxyRequest(upstream.status, text) && retryCount < MAX_RETRIES) {
            retryCount++;
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
        const estimatedCost = await estimateProxyCost({
          site: selected.site,
          account: selected.account,
          modelName: selected.actualModel || requestedModel,
          promptTokens: 0,
          completionTokens: 0,
          totalTokens: 0,
        });
        tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost);
        recordDownstreamCostUsage(request, estimatedCost);
        logProxy(selected, requestedModel, 'success', upstream.status, latency, null, retryCount, logDownstreamApiKeyId ? downstreamApiKeyId : null, estimatedCost, '/v1/images/edits');
        return reply.code(upstream.status).send(data);
      } catch (err: any) {
        tokenRouter.recordFailure(selected.channel.id);
        logProxy(selected, requestedModel, 'failed', 0, Date.now() - startTime, err.message, retryCount, logDownstreamApiKeyId ? downstreamApiKeyId : null, 0, '/v1/images/edits');
        if (retryCount < MAX_RETRIES) {
          retryCount++;
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
  });

  app.post('/v1/images/variations', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.code(400).send({
      error: {
        message: 'Image variations are not supported',
        type: 'invalid_request_error',
      },
    });
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
  estimatedCost = 0,
  downstreamPath = '/v1/images/generations',
) {
  try {
    const createdAt = formatUtcSqlDateTime(new Date());
    const normalizedErrorMessage = composeProxyLogMessage({
      downstreamPath,
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
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      estimatedCost,
      errorMessage: normalizedErrorMessage,
      retryCount,
      createdAt,
    }).run();
  } catch (error) {
    console.warn('[proxy/images] failed to write proxy log', error);
  }
}

