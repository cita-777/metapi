import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { fetch } from 'undici';
import { tokenRouter } from '../../services/tokenRouter.js';
import { reportProxyAllFailed, reportTokenExpired } from '../../services/alertService.js';
import { isTokenExpiredError } from '../../services/alertRules.js';
import { estimateProxyCost } from '../../services/modelPricingService.js';
import { shouldRetryProxyRequest } from '../../services/proxyRetryPolicy.js';
import { ensureModelAllowedForDownstreamKey, getDownstreamRoutingPolicy, recordDownstreamCostUsage } from './downstreamPolicy.js';
import { withSiteProxyRequestInit, withSiteRecordProxyRequestInit } from '../../services/siteProxy.js';
import { getProxyUrlFromExtraConfig } from '../../services/accountExtraConfig.js';
import { cloneFormDataWithOverrides, ensureMultipartBufferParser, parseMultipartFormData } from './multipart.js';
import { buildUpstreamUrl } from './upstreamUrl.js';
import {
  deleteProxyVideoTaskByPublicId,
  getProxyVideoTaskByPublicId,
  refreshProxyVideoTaskSnapshot,
  resolveProxyVideoTaskSite,
  saveProxyVideoTask,
} from '../../services/proxyVideoTaskStore.js';
import { getProxyMaxChannelRetries } from '../../services/proxyChannelRetry.js';
import {
  buildForcedChannelUnavailableMessage,
  canRetryChannelSelection,
  getTesterForcedChannelId,
  selectProxyChannelForAttempt,
} from '../../proxy-core/channelSelection.js';
import { runWithSiteApiEndpointPool, SiteApiEndpointRequestError } from '../../services/siteApiEndpointService.js';

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
    const forcedChannelId = getTesterForcedChannelId({
      headers: request.headers as Record<string, unknown>,
      clientIp: request.ip,
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
      const upstreamModel = selected.actualModel || requestedModel;
      const startTime = Date.now();

      try {
        const { upstream, text, baseUrl } = await runWithSiteApiEndpointPool(selected.site, async (target) => {
          const targetUrl = buildUpstreamUrl(target.baseUrl, '/v1/videos');
          const accountProxy = getProxyUrlFromExtraConfig(selected.account.extraConfig);
          const requestInit = multipartForm
            ? withSiteRecordProxyRequestInit(selected.site, {
              method: 'POST',
              headers: {
                Authorization: `Bearer ${selected.tokenValue}`,
              },
              body: cloneFormDataWithOverrides(multipartForm, {
                model: upstreamModel,
              }) as any,
            }, accountProxy)
            : withSiteRecordProxyRequestInit(selected.site, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${selected.tokenValue}`,
              },
              body: JSON.stringify({
                ...(jsonBody || {}),
                model: upstreamModel,
              }),
            }, accountProxy);
          const response = await fetch(targetUrl, requestInit);
          const responseText = await response.text();
          if (!response.ok) {
            throw new SiteApiEndpointRequestError(responseText || 'unknown error', {
              status: response.status,
              rawErrText: responseText || null,
            });
          }
          return {
            baseUrl: target.baseUrl,
            upstream: response,
            text: responseText,
          };
        });

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
          siteUrl: baseUrl,
          tokenValue: selected.tokenValue,
          requestedModel,
          actualModel: upstreamModel,
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
          modelName: upstreamModel,
          promptTokens: 0,
          completionTokens: 0,
          totalTokens: 0,
        });
        await recordTokenRouterEventBestEffort('record channel success', () => (
          tokenRouter.recordSuccess(selected.channel.id, latency, estimatedCost, upstreamModel)
        ));
        recordDownstreamCostUsage(request, estimatedCost);
        return reply.code(upstream.status).send(rewriteVideoResponsePublicId(data, mapping.publicId));
      } catch (error: any) {
        const status = error instanceof SiteApiEndpointRequestError ? (error.status || 0) : 0;
        const errorText = error?.message || 'network failure';
        await recordTokenRouterEventBestEffort('record channel failure', () => tokenRouter.recordFailure(selected.channel.id, {
          status,
          errorText,
          modelName: upstreamModel,
        }));
        if (status > 0 && isTokenExpiredError({ status, message: errorText })) {
          await reportTokenExpired({
            accountId: selected.account.id,
            username: selected.account.username,
            siteName: selected.site.name,
            detail: `HTTP ${status}`,
          });
        }
        if ((status > 0 ? shouldRetryProxyRequest(status, errorText) : true) && canRetryChannelSelection(retryCount, forcedChannelId)) {
          retryCount += 1;
          continue;
        }
        await reportProxyAllFailed({
          model: requestedModel,
          reason: errorText || 'network failure',
        });
        return reply.code(status || 502).send({
          error: {
            message: status > 0 ? errorText : `Upstream error: ${errorText}`,
            type: 'upstream_error',
          },
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

    let upstream: Awaited<ReturnType<typeof fetch>>;
    try {
      ({ upstream } = await requestMappedVideoTaskUpstream(mapping, 'GET'));
    } catch (error) {
      if (isSiteApiEndpointFailure(error)) {
        return sendVideoTaskEndpointFailure(reply, error);
      }
      throw error;
    }
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

    let upstream: Awaited<ReturnType<typeof fetch>>;
    try {
      ({ upstream } = await requestMappedVideoTaskUpstream(mapping, 'DELETE'));
    } catch (error) {
      if (isSiteApiEndpointFailure(error)) {
        return sendVideoTaskEndpointFailure(reply, error);
      }
      throw error;
    }
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

async function requestMappedVideoTaskUpstream(
  mapping: NonNullable<Awaited<ReturnType<typeof getProxyVideoTaskByPublicId>>>,
  method: 'GET' | 'DELETE',
): Promise<{ upstream: Awaited<ReturnType<typeof fetch>> }> {
  const buildRequest = async (baseUrl: string) => {
    const targetUrl = buildUpstreamUrl(baseUrl, `/v1/videos/${encodeURIComponent(mapping.upstreamVideoId)}`);
    const upstream = await fetch(targetUrl, await withSiteProxyRequestInit(targetUrl, {
      method,
      headers: {
        Authorization: `Bearer ${mapping.tokenValue}`,
      },
    }));
    if (!upstream.ok) {
      const errorText = await upstream.clone().text().catch(() => '');
      if (shouldRetryProxyRequest(upstream.status, errorText || `HTTP ${upstream.status}`)) {
        throw new SiteApiEndpointRequestError(errorText || `HTTP ${upstream.status}`, {
          status: upstream.status,
          rawErrText: errorText || null,
        });
      }
    }
    return { upstream };
  };

  const site = await resolveProxyVideoTaskSite(mapping.accountId);
  if (site) {
    return runWithSiteApiEndpointPool(site, (target) => buildRequest(target.baseUrl));
  }

  return buildRequest(mapping.siteUrl);
}

function isSiteApiEndpointFailure(error: unknown): error is SiteApiEndpointRequestError {
  return error instanceof SiteApiEndpointRequestError
    || (typeof error === 'object' && error !== null && (error as { name?: unknown }).name === 'SiteApiEndpointRequestError');
}

function sendVideoTaskEndpointFailure(
  reply: FastifyReply,
  error: { status?: number | null; rawErrText?: string | null; message?: string | null },
) {
  const status = typeof error.status === 'number' && error.status > 0 ? error.status : 502;
  const rawText = (typeof error.rawErrText === 'string' && error.rawErrText.trim())
    ? error.rawErrText
    : (typeof error.message === 'string' ? error.message.trim() : '');
  if (!rawText) {
    return reply.code(status).send({
      error: { message: 'Upstream request failed', type: 'upstream_error' },
    });
  }
  try {
    return reply.code(status).send(JSON.parse(rawText));
  } catch {
    return reply.code(status).type('text/plain').send(rawText);
  }
}

async function recordTokenRouterEventBestEffort(
  label: string,
  operation: () => Promise<unknown>,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    console.warn(`[proxy/videos] failed to ${label}`, error);
  }
}
