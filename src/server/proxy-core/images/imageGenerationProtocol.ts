/**
 * OpenAI Images 生成接口的请求和响应协议处理。
 * 路由层只负责请求上下文和代理编排，避免把协议规则绑定在 Fastify 路由中。
 */

export type ImageGenerationRequest = {
  body: Record<string, unknown>;
  requestedModel: string;
};

export type ImageGenerationRequestResult =
  | { ok: true; value: ImageGenerationRequest }
  | { ok: false; message: string };

export type ImageGenerationResponseResult =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; message: string };

/**
 * 校验并规范化图像生成请求，避免把明显无效的请求发送到上游。
 * 图像模型的可选参数由上游决定，这里只约束 OpenAI Images API 的必填字段。
 */
export function normalizeImageGenerationRequest(body: unknown): ImageGenerationRequestResult {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, message: 'request body must be a JSON object' };
  }

  const normalizedBody = body as Record<string, unknown>;
  const rawModel = normalizedBody.model;
  if (rawModel !== undefined && typeof rawModel !== 'string') {
    return { ok: false, message: 'model must be a string' };
  }

  const prompt = normalizedBody.prompt;
  if (typeof prompt !== 'string' || prompt.trim().length === 0) {
    return { ok: false, message: 'prompt is required' };
  }

  const requestedModel = (rawModel || 'gpt-image-1').trim();
  if (!requestedModel) {
    return { ok: false, message: 'model must not be empty' };
  }

  return {
    ok: true,
    value: {
      body: {
        ...normalizedBody,
        model: requestedModel,
        prompt: prompt.trim(),
      },
      requestedModel,
    },
  };
}

/**
 * 解析上游 Images 响应并确认至少返回一个可展示的图像结果。
 * 不符合协议的 2xx 响应会进入既有渠道重试链路，而不是静默返回空数据。
 */
export function parseUpstreamImageResponse(text: string): ImageGenerationResponseResult {
  try {
    const value = JSON.parse(text) as unknown;
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return { ok: false, message: 'Upstream returned an invalid image response' };
    }

    const data = (value as Record<string, unknown>).data;
    if (!Array.isArray(data) || data.length === 0) {
      return { ok: false, message: 'Upstream image response did not include data' };
    }

    const hasImage = data.some((item) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) return false;
      const record = item as Record<string, unknown>;
      return (typeof record.url === 'string' && record.url.trim().length > 0)
        || (typeof record.b64_json === 'string' && record.b64_json.trim().length > 0);
    });
    if (!hasImage) {
      return { ok: false, message: 'Upstream image response did not include an image' };
    }

    return { ok: true, value: value as Record<string, unknown> };
  } catch {
    return { ok: false, message: text || 'Upstream returned malformed JSON' };
  }
}
