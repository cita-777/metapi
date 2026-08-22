import type { FastifyReply, FastifyRequest } from 'fastify';
import { config } from '../../config.js';
import { getProxyAuthContext } from '../../middleware/auth.js';
import { parseProxyUsage } from '../../services/proxyUsageParser.js';
import { getProxyMaxChannelRetries } from '../../services/proxyChannelRetry.js';
import {
  runWithSurfaceSiteConcurrency,
  createSurfaceDispatchRequest,
  createSurfaceFailureToolkit,
  getSurfaceRequestFailure,
  recordSurfaceSuccess,
  selectSurfaceChannelForAttempt,
} from './sharedSurface.js';
import { detectDownstreamClientContext } from '../downstreamClientContext.js';
import {
  buildForcedChannelUnavailableMessage,
  canRetryChannelSelection,
  getTesterForcedChannelId,
} from '../channelSelection.js';
import { executeEndpointFlow } from '../orchestration/endpointFlow.js';
import { readRuntimeResponseText } from '../executors/types.js';
import { SiteApiEndpointRequestError } from '../../services/siteApiEndpointService.js';
import { EMPTY_DOWNSTREAM_ROUTING_POLICY } from '../../services/downstreamPolicyTypes.js';
import { recordManagedKeyCostUsage } from '../../services/downstreamApiKeyService.js';
import { reportProxyAllFailed } from '../../services/alertService.js';

/**
 * 执行 Rerank 的完整代理链路：选渠道、站点并发租约、地址池、失败重试、用量计费和日志。
 * 路由层不直接持有这些状态，避免同一套编排在不同协议入口中分叉。
 */
export async function handleRerankSurfaceRequest(
  request: FastifyRequest,
  reply: FastifyReply,
  requestedModel: string,
) {
  const body = (request.body || {}) as Record<string, unknown>;
  const downstreamPath = '/v1/rerank';
  const clientContext = detectDownstreamClientContext({
    downstreamPath,
    headers: request.headers as Record<string, unknown>,
    body,
  });
  const downstreamPolicy = getProxyAuthContext(request)?.policy || EMPTY_DOWNSTREAM_ROUTING_POLICY;
  const forcedChannelId = getTesterForcedChannelId({
    headers: request.headers as Record<string, unknown>,
    clientIp: request.ip,
  });
  const downstreamApiKeyId = getProxyAuthContext(request)?.keyId ?? null;
  const firstByteTimeoutMs = Math.max(0, Math.trunc((config.proxyFirstByteTimeoutSec || 0) * 1000));
  const maxRetries = getProxyMaxChannelRetries();
  const failureToolkit = createSurfaceFailureToolkit({
    warningScope: 'rerank',
    downstreamPath,
    maxRetries,
    clientContext,
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
      forcedChannelId,
    });
    if (!selected) {
      const message = buildForcedChannelUnavailableMessage(forcedChannelId);
      await reportProxyAllFailed({ model: requestedModel, reason: message });
      return reply.code(503).send({ error: { message, type: 'server_error' } });
    }

    excludeChannelIds.push(selected.channel.id);
    const upstreamModel = selected.actualModel || requestedModel;
    const forwardBody = { ...body, model: upstreamModel };
    const startTime = Date.now();

    try {
      const endpointResult = await runWithSurfaceSiteConcurrency(selected.site, async (siteBaseUrl) => {
        const result = await executeEndpointFlow({
          siteUrl: siteBaseUrl,
          firstByteTimeoutMs,
          // executeEndpointFlow 统一处理首字节超时和响应体读取；Rerank 的路径由请求构造器明确指定。
          endpointCandidates: ['chat'],
          buildRequest: () => ({
            endpoint: 'chat',
            path: '/v1/rerank',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${selected.tokenValue}`,
            },
            body: forwardBody,
          }),
          dispatchRequest: createSurfaceDispatchRequest({
            site: selected.site,
            siteUrl: siteBaseUrl,
            accountExtraConfig: selected.account.extraConfig,
          }),
        });
        if (result.ok) return result;
        const failure = new SiteApiEndpointRequestError(result.errText || 'unknown error', {
          status: result.status || 502,
          rawErrText: result.rawErrText || result.errText || 'unknown error',
        }) as SiteApiEndpointRequestError & { siteApiEndpointUpstreamFailure?: boolean };
        failure.siteApiEndpointUpstreamFailure = true;
        throw failure;
      });

      const text = await readRuntimeResponseText(endpointResult.upstream);
      let data: unknown = text;
      try {
        data = JSON.parse(text);
      } catch {
        // 上游可能返回非 JSON 文本，保持原始响应，避免把成功响应误判为协议失败。
      }
      const latency = Date.now() - startTime;
      const parsedUsage = parseProxyUsage(data);
      await recordSurfaceSuccess({
        selected,
        requestedModel,
        modelName: upstreamModel,
        parsedUsage,
        requestStartedAtMs: startTime,
        latencyMs: latency,
        retryCount,
        upstreamPath: endpointResult.upstreamPath,
        upstreamHeaders: endpointResult.upstream.headers,
        logSuccess: failureToolkit.log,
        recordDownstreamCost: (estimatedCost) => {
          if (downstreamApiKeyId !== null) void recordManagedKeyCostUsage(downstreamApiKeyId, estimatedCost);
        },
        bestEffortMetrics: {
          errorLabel: '[proxy/rerank] failed to record success metrics',
        },
      });
      return reply.code(endpointResult.upstream.status).send(data);
    } catch (error) {
      const failure = getSurfaceRequestFailure(error);
      if (failure.isSiteConcurrencyBusy) {
        await failureToolkit.log({
          selected,
          modelRequested: requestedModel,
          status: 'failed',
          httpStatus: failure.status,
          latencyMs: Date.now() - startTime,
          errorMessage: failure.message,
          retryCount,
        });
        if (canRetryChannelSelection(retryCount, forcedChannelId)) {
          retryCount += 1;
          continue;
        }
        return reply.code(failure.status).send({
          error: { message: failure.message, type: 'server_error' },
        });
      }

      const outcome = await failureToolkit.handleUpstreamFailure({
        selected,
        requestedModel,
        modelName: upstreamModel,
        status: failure.status,
        errText: failure.message,
        rawErrText: (error as { rawErrText?: string | null })?.rawErrText || failure.message,
        latencyMs: Date.now() - startTime,
        retryCount,
      });
      if (outcome.action === 'retry' && canRetryChannelSelection(retryCount, forcedChannelId)) {
        retryCount += 1;
        continue;
      }
      if (outcome.action === 'retry') {
        return reply.code(failure.status).send({
          error: { message: failure.message, type: 'upstream_error' },
        });
      }
      return reply.code(outcome.status).send(outcome.payload);
    }
  }

  return reply.code(503).send({
    error: { message: 'No available channels after retries', type: 'server_error' },
  });
}
