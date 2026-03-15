import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { fetch } from 'undici';
import { tokenRouter } from '../../services/tokenRouter.js';
import { refreshModelsAndRebuildRoutes } from '../../services/modelService.js';
import { reportProxyAllFailed, reportTokenExpired } from '../../services/alertService.js';
import { isTokenExpiredError } from '../../services/alertRules.js';
import { estimateProxyCost } from '../../services/modelPricingService.js';
import { shouldRetryProxyRequest } from '../../services/proxyRetryPolicy.js';
import { ensureModelAllowedForDownstreamKey, getDownstreamRoutingPolicy, recordDownstreamCostUsage } from './downstreamPolicy.js';
import { withSiteProxyRequestInit, withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import { cloneFormDataWithOverrides, ensureMultipartBufferParser, parseMultipartFormData } from './multipart.js';
import { buildUpstreamUrl } from './upstreamUrl.js';
import {
  deleteProxyVideoTaskByPublicId,
  getProxyVideoTaskByPublicId,
  refreshProxyVideoTaskSnapshot,
  saveProxyVideoTask,
} from '../../services/proxyVideoTaskStore.js';

const MAX_RETRIES = 2;

function rewriteVideoResponsePublicId(payload: unknown, publicId: string): unknown {
  if (!payload || typeof payload !== 'object') return payload;
  return {
    ...(payload as Record<string, unknown>),
    id: publicId,
  };
}

export async function videosProxyRoute(app: FastifyInstance) {
  ensureMultipartBufferParser(app);

  app.post('/v1/videos', async (request: FastifyRequest, reply: FastifyReply) => {
    const multipartForm = await parseMultipartFormData(request);
    const jsonBody = (!multipartForm && request.body && typeof request.body === 'object')
      ? request.body as Record<string, unknown>
      : null;
    const requestedModel = typeof multipartForm?.get('model') === 'string'
      ? String(multipartForm.get('model')).trim()
      : (typeof jsonBody?.model === 'string' ? jsonBody.model.trim() : '');

    if (!requestedModel) {
      return reply.code(400).send({
        error: { message: 'model is required', type: 'invalid_request_error' },
      });
    }
    if (!await ensureModelAllowedForDownstreamKey(request, reply, requestedModel)) return;

    const downstreamPolicy = getDownstreamRoutingPolicy(request);
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
      const targetUrl = buildUpstreamUrl(selected.site.url, '/v1/videos');
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
          if (isTokenExpiredError({ status: upstream.status, message: text })) {
            await reportTokenExpired({
              accountId: selected.account.id,
              username: selected.account.username,
              siteName: selected.site.name,
              detail: `HTTP ${upstream.status}`,
            });
          }
          if (shouldRetryProxyRequest(upstream.status, text) && retryCount < MAX_RETRIES) {
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
        try { data = JSON.parse(text); } catch { data = {}; }
        const upstreamVideoId = typeof data?.id === 'string' ? data.id.trim() : '';
        if (!upstreamVideoId) {
          return reply.code(502).send({
            error: { message: 'Upstream video response did not include id', type: 'upstream_error' },
          });
        }

        const mapping = await saveProxyVideoTask({
          upstreamVideoId,
          siteUrl: selected.site.url,
          tokenValue: selected.tokenValue,
          requestedModel,
          actualModel: selected.actualModel || requestedModel,
          channelId: typeof selected.channel.id === 'number' ? selected.channel.id : null,
          accountId: typeof selected.account.id === 'number' ? selected.account.id : null,
          statusSnapshot: data,
          upstreamResponseMeta: {
            contentType: upstream.headers.get('content-type') || 'application/json',
          },
          lastUpstreamStatus: upstream.status,
        });

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
        return reply.code(upstream.status).send(rewriteVideoResponsePublicId(data, mapping.publicId));
      } catch (error: any) {
        tokenRouter.recordFailure(selected.channel.id);
        if (retryCount < MAX_RETRIES) {
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

  app.get('/v1/videos/:id', async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    const mapping = await getProxyVideoTaskByPublicId(request.params.id);
    if (!mapping) {
      return reply.code(404).send({
        error: { message: 'Video task not found', type: 'not_found_error' },
      });
    }

    const targetUrl = buildUpstreamUrl(mapping.siteUrl, `/v1/videos/${encodeURIComponent(mapping.upstreamVideoId)}`);
    const upstream = await fetch(targetUrl, await withSiteProxyRequestInit(targetUrl, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${mapping.tokenValue}`,
      },
    }));
    const text = await upstream.text();
    try {
      const data = JSON.parse(text);
      await refreshProxyVideoTaskSnapshot(mapping.publicId, {
        statusSnapshot: data,
        upstreamResponseMeta: {
          contentType: upstream.headers.get('content-type') || 'application/json',
        },
        lastUpstreamStatus: upstream.status,
      });
      return reply.code(upstream.status).send(rewriteVideoResponsePublicId(data, mapping.publicId));
    } catch {
      return reply.code(upstream.status).type(upstream.headers.get('content-type') || 'application/json').send(text);
    }
  });

  app.delete('/v1/videos/:id', async (request: FastifyRequest<{ Params: { id: string } }>, reply: FastifyReply) => {
    const mapping = await getProxyVideoTaskByPublicId(request.params.id);
    if (!mapping) {
      return reply.code(404).send({
        error: { message: 'Video task not found', type: 'not_found_error' },
      });
    }

    const targetUrl = buildUpstreamUrl(mapping.siteUrl, `/v1/videos/${encodeURIComponent(mapping.upstreamVideoId)}`);
    const upstream = await fetch(targetUrl, await withSiteProxyRequestInit(targetUrl, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${mapping.tokenValue}`,
      },
    }));
    if (upstream.ok) {
      await deleteProxyVideoTaskByPublicId(mapping.publicId);
      return reply.code(upstream.status).send();
    }

    const text = await upstream.text();
    return reply.code(upstream.status).send({
      error: { message: text || 'Upstream delete failed', type: 'upstream_error' },
    });
  });
}
