import type { FastifyReply, FastifyRequest } from 'fastify';
import { RateLimiterMemory, RateLimiterRes } from 'rate-limiter-flexible';

type RateLimitOptions = {
  bucket: string;
  max: number;
  windowMs: number;
  message?: string;
};

const DEFAULT_MESSAGE = '请求过于频繁，请稍后再试';
let rateLimiterGeneration = 0;

function normalizeIp(rawIp: string | null | undefined): string {
  const ip = (rawIp || '').trim();
  if (!ip) return 'unknown';
  if (ip.startsWith('::ffff:')) return ip.slice('::ffff:'.length).trim() || 'unknown';
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

export function resetRequestRateLimitStore(): void {
  rateLimiterGeneration += 1;
}

type RateLimitGuard = ((request: FastifyRequest, reply: FastifyReply) => Promise<void>) & {
  __metapiLimiter?: RateLimiterMemory;
  __metapiLimiterGeneration?: number;
};

function buildRateLimiter(options: RateLimitOptions): RateLimiterMemory {
  return new RateLimiterMemory({
    keyPrefix: options.bucket,
    points: Math.max(1, Math.trunc(options.max)),
    duration: Math.max(1, Math.ceil(options.windowMs / 1000)),
  });
}

function getGuardLimiter(guard: RateLimitGuard, options: RateLimitOptions): RateLimiterMemory {
  if (!guard.__metapiLimiter || guard.__metapiLimiterGeneration !== rateLimiterGeneration) {
    guard.__metapiLimiter = buildRateLimiter(options);
    guard.__metapiLimiterGeneration = rateLimiterGeneration;
  }
  return guard.__metapiLimiter;
}

export function createRateLimitGuard(options: RateLimitOptions) {
  const message = options.message || DEFAULT_MESSAGE;
  const rateLimitGuard: RateLimitGuard = async (request, reply) => {
    const limiter = getGuardLimiter(rateLimitGuard, options);
    const forwarded = request.headers['x-forwarded-for'];
    let key = request.ip;
    if (Array.isArray(forwarded)) {
      const first = forwarded.find((value) => typeof value === 'string' && value.trim().length > 0);
      if (first) {
        key = first.split(',')[0] || key;
      }
    } else if (typeof forwarded === 'string' && forwarded.trim().length > 0) {
      key = forwarded.split(',')[0] || key;
    }
    key = normalizeIp(key);

    try {
      await limiter.consume(key);
    } catch (error) {
      const retryState = error instanceof RateLimiterRes ? error : null;
      const retryAfterSec = Math.max(
        1,
        Math.ceil((retryState?.msBeforeNext ?? options.windowMs) / 1000),
      );
      reply
        .code(429)
        .header('retry-after', String(retryAfterSec))
        .send({ success: false, message });
    }
  };

  return rateLimitGuard;
}
