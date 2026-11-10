import { isIP } from 'node:net';
import { FastifyRequest, FastifyReply } from 'fastify';
import { config } from '../config.js';
import { authorizeDownstreamToken, consumeManagedKeyRequest } from '../services/downstreamApiKeyService.js';
import { EMPTY_DOWNSTREAM_ROUTING_POLICY, type DownstreamRoutingPolicy } from '../services/downstreamPolicyTypes.js';

export interface ProxyAuthContext {
  token: string;
  source: 'managed' | 'global';
  keyId: number | null;
  keyName: string;
  policy: DownstreamRoutingPolicy;
}

export interface ProxyResourceOwner {
  ownerType: 'managed_key' | 'global_proxy_token';
  ownerId: string;
}

const proxyAuthContextByRequest = new WeakMap<FastifyRequest, ProxyAuthContext>();

type ParsedAllowlistEntry =
  | { kind: 'exact'; normalizedIp: string }
  | { kind: 'cidr'; network: number; mask: number };

function normalizeIp(rawIp: string | null | undefined): string {
  const ip = (rawIp || '').trim();
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) return ip.slice('::ffff:'.length).trim();
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

function parseIpv4Value(rawIp: string): number | null {
  const normalizedIp = normalizeIp(rawIp);
  if (isIP(normalizedIp) !== 4) return null;

  let value = 0;
  for (const part of normalizedIp.split('.')) {
    value = (value << 8) + Number(part);
  }

  return value >>> 0;
}

function parseAllowlistEntry(rawEntry: string): ParsedAllowlistEntry | null {
  const entry = (rawEntry || '').trim();
  if (!entry) return null;

  const slashIndex = entry.indexOf('/');
  if (slashIndex === -1) {
    const normalizedIp = normalizeIp(entry);
    return isIP(normalizedIp) > 0
      ? { kind: 'exact', normalizedIp }
      : null;
  }

  if (entry.indexOf('/', slashIndex + 1) !== -1) return null;

  const networkIp = normalizeIp(entry.slice(0, slashIndex));
  const prefixText = entry.slice(slashIndex + 1).trim();
  if (isIP(networkIp) !== 4 || !/^\d+$/.test(prefixText)) return null;

  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;

  const networkValue = parseIpv4Value(networkIp);
  if (networkValue === null) return null;

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return {
    kind: 'cidr',
    network: networkValue & mask,
    mask,
  };
}

export function findInvalidIpAllowlistEntries(allowlist: string[]): string[] {
  return allowlist.filter((item) => parseAllowlistEntry(item) === null);
}

function joinHeaderValues(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value.filter((item) => item && item.trim().length > 0).join(',');
  return typeof value === 'string' ? value : '';
}

/**
 * Resolve the client IP. Forwarded headers are only honored when the direct
 * socket peer is a configured trusted proxy; the chain is then walked from the
 * right, skipping trusted hops, so a client cannot prepend a spoofed address.
 */
export function extractClientIp(
  remoteIp: string | null | undefined,
  xForwardedFor?: string | string[] | undefined,
  trustedProxies: string[] = config.trustedProxies,
): string {
  const peerIp = normalizeIp(remoteIp);
  if (!trustedProxies || trustedProxies.length === 0) return peerIp;
  if (!peerIp || !isIpAllowed(peerIp, trustedProxies)) return peerIp;

  const forwardedChain = joinHeaderValues(xForwardedFor)
    .split(',')
    .map((item) => normalizeIp(item))
    .filter((item) => item.length > 0);

  let clientIp = peerIp;
  for (let i = forwardedChain.length - 1; i >= 0; i -= 1) {
    const hop = forwardedChain[i];
    if (isIP(hop) === 0) break;
    clientIp = hop;
    if (!isIpAllowed(hop, trustedProxies)) break;
  }
  return clientIp;
}

export function isIpAllowed(clientIp: string, allowlist: string[]): boolean {
  if (!allowlist || allowlist.length === 0) return true;
  const normalizedClientIp = normalizeIp(clientIp);
  if (!normalizedClientIp) return false;
  const clientIpv4Value = parseIpv4Value(normalizedClientIp);

  return allowlist.some((item) => {
    const entry = parseAllowlistEntry(item);
    if (!entry) return false;
    if (entry.kind === 'exact') return entry.normalizedIp === normalizedClientIp;
    if (clientIpv4Value === null) return false;
    return (clientIpv4Value & entry.mask) === entry.network;
  });
}

export function getRequestClientIp(request: FastifyRequest): string {
  return extractClientIp(request.socket?.remoteAddress ?? request.ip, request.headers['x-forwarded-for']);
}

export async function authMiddleware(request: FastifyRequest, reply: FastifyReply) {
  const clientIp = getRequestClientIp(request);
  if (!isIpAllowed(clientIp, config.adminIpAllowlist)) {
    reply.code(403).send({ error: 'IP not allowed' });
    return;
  }

  const auth = request.headers.authorization;
  if (!auth) {
    reply.code(401).send({ error: 'Missing Authorization header' });
    return;
  }
  const token = auth.replace('Bearer ', '');
  if (token !== config.authToken) {
    reply.code(403).send({ error: 'Invalid token' });
    return;
  }
}

export async function proxyAuthMiddleware(request: FastifyRequest, reply: FastifyReply) {
  const auth = typeof request.headers.authorization === 'string'
    ? request.headers.authorization
    : '';
  const apiKeyHeader = typeof request.headers['x-api-key'] === 'string'
    ? request.headers['x-api-key']
    : '';
  const googApiKeyHeader = typeof request.headers['x-goog-api-key'] === 'string'
    ? request.headers['x-goog-api-key']
    : '';
  const queryKey = (
    request.query
    && typeof request.query === 'object'
    && typeof (request.query as Record<string, unknown>).key === 'string'
  )
    ? String((request.query as Record<string, unknown>).key).trim()
    : '';
  const token = auth
    ? auth.replace(/^Bearer\s+/i, '').trim()
    : (apiKeyHeader.trim() || googApiKeyHeader.trim() || queryKey);

  if (!token) {
    reply.code(401).send({ error: 'Missing Authorization, x-api-key, x-goog-api-key, or key query parameter' });
    return;
  }

  const authResult = await authorizeDownstreamToken(token);
  if (!authResult.ok) {
    reply.code(authResult.statusCode).send({ error: authResult.error });
    return;
  }

  if (authResult.source === 'managed' && authResult.key) {
    await consumeManagedKeyRequest(authResult.key.id);
  }

  proxyAuthContextByRequest.set(request, {
    token: authResult.token,
    source: authResult.source,
    keyId: authResult.key?.id ?? null,
    keyName: authResult.key?.name || 'global',
    policy: authResult.policy || EMPTY_DOWNSTREAM_ROUTING_POLICY,
  });
}

export function getProxyAuthContext(request: FastifyRequest): ProxyAuthContext | null {
  return proxyAuthContextByRequest.get(request) || null;
}

export function getProxyResourceOwner(request: FastifyRequest): ProxyResourceOwner | null {
  const auth = getProxyAuthContext(request);
  if (!auth) return null;

  if (auth.source === 'managed') {
    return {
      ownerType: 'managed_key',
      ownerId: auth.keyId === null ? auth.token : String(auth.keyId),
    };
  }

  return {
    ownerType: 'global_proxy_token',
    ownerId: 'global',
  };
}
