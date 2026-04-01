import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { db, schema } from '../../db/index.js';
import { upsertSetting } from '../../db/upsertSetting.js';
import { config } from '../../config.js';
import { eq } from 'drizzle-orm';
import { createRateLimitGuard } from '../../middleware/requestRateLimit.js';
import { parseMonitorConfigPayload } from '../../contracts/supportRoutePayloads.js';

const MONITOR_AUTH_COOKIE = 'meta_monitor_auth';
const LDOH_BASE_URL = 'https://ldoh.105117.xyz';
const LDOH_COOKIE_SETTING_KEY = 'monitor_ldoh_cookie';

const limitMonitorConfigRead = createRateLimitGuard({
  bucket: 'monitor-config-read',
  max: 30,
  windowMs: 60_000,
});

const limitMonitorConfigWrite = createRateLimitGuard({
  bucket: 'monitor-config-write',
  max: 10,
  windowMs: 60_000,
});

const limitMonitorSession = createRateLimitGuard({
  bucket: 'monitor-session',
  max: 10,
  windowMs: 60_000,
});

const limitMonitorProxy = createRateLimitGuard({
  bucket: 'monitor-proxy',
  max: 60,
  windowMs: 60_000,
});



async function getSettingString(key: string): Promise<string> {
  const row = await db.select().from(schema.settings).where(eq(schema.settings.key, key)).get();
  if (!row?.value) return '';
  try {
    const parsed = JSON.parse(row.value);
    return typeof parsed === 'string' ? parsed : '';
  } catch {
    return '';
  }
}

function parseCookies(raw: string | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!raw) return result;
  for (const part of raw.split(';')) {
    const entry = part.trim();
    if (!entry) continue;
    const idx = entry.indexOf('=');
    if (idx <= 0) continue;
    const key = entry.slice(0, idx).trim();
    const value = entry.slice(idx + 1).trim();
    if (!key) continue;
    result[key] = value;
  }
  return result;
}

function maskCookieValue(cookieText: string): string {
  const value = cookieText.trim();
  if (!value) return '';
  const idx = value.indexOf('=');
  const raw = idx >= 0 ? value.slice(idx + 1) : value;
  if (raw.length <= 10) return `${raw.slice(0, 2)}****`;
  return `${raw.slice(0, 6)}****${raw.slice(-4)}`;
}

function normalizeLdohCookie(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (trimmed.includes('ld_auth_session=')) {
    const firstPair = trimmed.split(';')[0].trim();
    if (firstPair.startsWith('ld_auth_session=')) return firstPair;
  }
  return `ld_auth_session=${trimmed}`;
}

function rewriteProxyText(text: string): string {
  return text
    .replaceAll('https://ldoh.105117.xyz/', '/monitor-proxy/ldoh/')
    .replaceAll('https:\\/\\/ldoh.105117.xyz\\/', '\\/monitor-proxy\\/ldoh\\/')
    .replaceAll('src="/', 'src="/monitor-proxy/ldoh/')
    .replaceAll("src='/", "src='/monitor-proxy/ldoh/")
    .replaceAll('href="/', 'href="/monitor-proxy/ldoh/')
    .replaceAll("href='/", "href='/monitor-proxy/ldoh/")
    .replaceAll('action="/', 'action="/monitor-proxy/ldoh/')
    .replaceAll("action='/", "action='/monitor-proxy/ldoh/")
    .replaceAll('"/_next/', '"/monitor-proxy/ldoh/_next/')
    .replaceAll("'/_next/", "'/monitor-proxy/ldoh/_next/")
    .replaceAll('"\\/api/', '"\\/monitor-proxy\\/ldoh\\/api/')
    .replaceAll("'/api/", "'/monitor-proxy/ldoh/api/")
    .replaceAll('"/api/', '"/monitor-proxy/ldoh/api/');
}

function rewriteLocationHeader(location: string | null): string | null {
  if (!location) return null;
  if (location.startsWith(`${LDOH_BASE_URL}/`)) {
    return `/monitor-proxy/ldoh/${location.slice(LDOH_BASE_URL.length + 1)}`;
  }
  if (location.startsWith('/')) {
    return `/monitor-proxy/ldoh${location}`;
  }
  return location;
}

function ensureMonitorAuth(request: FastifyRequest, reply: FastifyReply): boolean {
  const cookies = parseCookies(request.headers.cookie);
  if (cookies[MONITOR_AUTH_COOKIE] !== config.authToken) {
    reply.code(401).send({ error: 'Missing or invalid monitor session' });
    return false;
  }
  return true;
}

function resolveLdohProxyPath(request: FastifyRequest): string {
  const rawUrl = String(request.url || '');
  const cleanPath = rawUrl.split('?')[0] || '';
  const prefix = '/monitor-proxy/ldoh';
  if (cleanPath === prefix || cleanPath === `${prefix}/`) return '';
  if (cleanPath.startsWith(`${prefix}/`)) return cleanPath.slice(prefix.length + 1);
  return String((request.params as Record<string, unknown>)['*'] || '');
}

export async function monitorRoutes(app: FastifyInstance) {
  app.get('/api/monitor/config', { preHandler: [limitMonitorConfigRead] }, async () => {
    const ldohCookie = await getSettingString(LDOH_COOKIE_SETTING_KEY);
    return {
      ldohCookieConfigured: !!ldohCookie,
      ldohCookieMasked: ldohCookie ? maskCookieValue(ldohCookie) : '',
    };
  });

  app.put<{ Body: unknown }>(
    '/api/monitor/config',
    { preHandler: [limitMonitorConfigWrite] },
    async (request, reply) => {
    const parsedBody = parseMonitorConfigPayload(request.body);
    if (!parsedBody.success) {
      return reply.code(400).send({ success: false, message: parsedBody.error });
    }

    const raw = String(parsedBody.data.ldohCookie || '').trim();
    if (!raw) {
      await upsertSetting(LDOH_COOKIE_SETTING_KEY, '');
      return { success: true, message: 'LDOH Cookie 已清空', ldohCookieConfigured: false };
    }

    const normalized = normalizeLdohCookie(raw);
    if (!normalized.startsWith('ld_auth_session=') || normalized.length < 24) {
      return reply.code(400).send({ success: false, message: 'Cookie 格式无效，请填写 ld_auth_session 或其值' });
    }

    await upsertSetting(LDOH_COOKIE_SETTING_KEY, normalized);
    return {
      success: true,
      message: 'LDOH Cookie 已保存',
      ldohCookieConfigured: true,
      ldohCookieMasked: maskCookieValue(normalized),
    };
    },
  );

  app.post('/api/monitor/session', { preHandler: [limitMonitorSession] }, async (_, reply) => {
    // HttpOnly cookie for iframe proxy auth within current origin.
    reply.header(
      'Set-Cookie',
      `${MONITOR_AUTH_COOKIE}=${config.authToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=7200`,
    );
    return { success: true };
  });

  const handleLdohProxy = async (request: FastifyRequest, reply: FastifyReply) => {
    if (!ensureMonitorAuth(request, reply)) return;

    const storedCookie = await getSettingString(LDOH_COOKIE_SETTING_KEY);
    if (!storedCookie) {
      return reply.code(400).send('LDOH cookie not configured');
    }

    const wildcardPath = resolveLdohProxyPath(request);
    const targetUrl = new URL(`${LDOH_BASE_URL}/${wildcardPath}`);
    for (const [key, value] of Object.entries(request.query as Record<string, unknown>)) {
      if (value == null) continue;
      targetUrl.searchParams.set(key, String(value));
    }

    const upstreamHeaders: Record<string, string> = {
      cookie: storedCookie,
      accept: String(request.headers.accept || '*/*'),
      'accept-language': String(request.headers['accept-language'] || 'zh-CN,zh;q=0.9,en;q=0.8'),
      'user-agent': String(request.headers['user-agent'] || 'metapiMonitorProxy/1.0'),
    };
    if (request.headers['content-type']) {
      upstreamHeaders['content-type'] = String(request.headers['content-type']);
    }
    if (request.headers.referer) {
      upstreamHeaders.referer = String(request.headers.referer).replace('/monitor-proxy/ldoh', '');
    }

    const method = request.method.toUpperCase();
    const bodyAllowed = !['GET', 'HEAD'].includes(method);
    const upstreamResponse = await fetch(targetUrl, {
      method,
      headers: upstreamHeaders,
      body: bodyAllowed ? (request.body as BodyInit | null | undefined) : undefined,
      redirect: 'manual',
    });

    const contentType = upstreamResponse.headers.get('content-type') || '';
    const location = rewriteLocationHeader(upstreamResponse.headers.get('location'));
    if (location) reply.header('location', location);
    if (contentType) reply.header('content-type', contentType);
    const cacheControl = upstreamResponse.headers.get('cache-control');
    if (cacheControl) reply.header('cache-control', cacheControl);

    reply.code(upstreamResponse.status);

    if (
      contentType.includes('text/html')
      || contentType.includes('application/javascript')
      || contentType.includes('text/javascript')
      || contentType.includes('text/css')
      || contentType.includes('application/json')
    ) {
      const text = await upstreamResponse.text();
      return reply.send(rewriteProxyText(text));
    }

    const buffer = Buffer.from(await upstreamResponse.arrayBuffer());
    return reply.send(buffer);
  };

  app.all('/monitor-proxy/ldoh', { preHandler: [limitMonitorProxy] }, handleLdohProxy);
  app.all('/monitor-proxy/ldoh/', { preHandler: [limitMonitorProxy] }, handleLdohProxy);
  app.all('/monitor-proxy/ldoh/*', { preHandler: [limitMonitorProxy] }, handleLdohProxy);
}
