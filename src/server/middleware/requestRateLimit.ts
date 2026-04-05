import type { FastifyReply, FastifyRequest } from 'fastify';

type RateLimitOptions = {
  bucket: string;
  max: number;
  windowMs: number;
  message?: string;
};

type RateLimitEntry = {
  count: number;
  resetAt: number;
};

const DEFAULT_MESSAGE = '请求过于频繁，请稍后再试';
const rateLimitStore = new Map<string, RateLimitEntry>();

function normalizeIp(rawIp: string | null | undefined): string {
  const ip = (rawIp || '').trim();
  if (!ip) return 'unknown';
  if (ip.startsWith('::ffff:')) return ip.slice('::ffff:'.length).trim() || 'unknown';
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

function extractClientIp(request: FastifyRequest): string {
  const forwarded = request.headers['x-forwarded-for'];
  if (Array.isArray(forwarded)) {
    const first = forwarded.find((value) => typeof value === 'string' && value.trim().length > 0);
    if (first) return normalizeIp(first.split(',')[0]);
  }

  if (typeof forwarded === 'string' && forwarded.trim().length > 0) {
    return normalizeIp(forwarded.split(',')[0]);
  }

  return normalizeIp(request.ip);
}

function getRateLimitKey(bucket: string, request: FastifyRequest): string {
  return `${bucket}:${extractClientIp(request)}`;
}

function pruneExpiredEntries(nowMs: number): void {
  for (const [key, entry] of rateLimitStore.entries()) {
    if (entry.resetAt > nowMs) continue;
    rateLimitStore.delete(key);
  }
}

export function resetRequestRateLimitStore(): void {
  rateLimitStore.clear();
}

export function createRateLimitGuard(options: RateLimitOptions) {
  const message = options.message || DEFAULT_MESSAGE;
  return async function rateLimitGuard(request: FastifyRequest, reply: FastifyReply) {
    const nowMs = Date.now();
    pruneExpiredEntries(nowMs);

    const key = getRateLimitKey(options.bucket, request);
    const current = rateLimitStore.get(key);

    if (!current || current.resetAt <= nowMs) {
      rateLimitStore.set(key, {
        count: 1,
        resetAt: nowMs + options.windowMs,
      });
      return;
    }

    if (current.count >= options.max) {
      const retryAfterSec = Math.max(1, Math.ceil((current.resetAt - nowMs) / 1000));
      reply
        .code(429)
        .header('retry-after', String(retryAfterSec))
        .send({ success: false, message });
      return;
    }

    current.count += 1;
    rateLimitStore.set(key, current);
  };
}
