import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import {
  getSub2ApiAuthFromExtraConfig,
  mergeAccountExtraConfig,
  resolveProxyUrlFromExtraConfig,
} from './accountExtraConfig.js';
import { withSiteRecordProxyRequestInit } from './siteProxy.js';

export const SUB2API_MANAGED_REFRESH_LEAD_MS = 120 * 1000;

type Sub2ApiRefreshedCredentials = {
  accessToken: string;
  refreshToken: string;
  tokenExpiresAt: number;
};

function normalizeNonEmptyString(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.trim();
}

function normalizeErrorSnippet(value: string): string {
  const normalized = value.replace(/\s+/g, ' ').trim();
  if (!normalized) return '';
  return normalized.length > 200
    ? `${normalized.slice(0, 197)}...`
    : normalized;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function parseSub2ApiRefreshPayload(payload: unknown): Sub2ApiRefreshedCredentials | null {
  if (!isRecord(payload)) return null;
  const code = typeof payload.code === 'number'
    ? payload.code
    : (typeof payload.code === 'string' ? Number.parseInt(payload.code.trim(), 10) : Number.NaN);
  if (!Number.isFinite(code) || code !== 0) return null;
  if (!isRecord(payload.data)) return null;
  const data = payload.data;

  const accessToken = normalizeNonEmptyString(data.access_token);
  const refreshToken = normalizeNonEmptyString(data.refresh_token);
  const expiresInSeconds = typeof data.expires_in === 'number' && Number.isFinite(data.expires_in)
    ? data.expires_in
    : (typeof data.expires_in === 'string' ? Number.parseInt(data.expires_in.trim(), 10) : Number.NaN);

  if (!accessToken || !refreshToken || !Number.isFinite(expiresInSeconds) || expiresInSeconds <= 0) {
    return null;
  }

  return {
    accessToken,
    refreshToken,
    tokenExpiresAt: Date.now() + Math.trunc(expiresInSeconds) * 1000,
  };
}

function parseJsonPayload(rawText: string): unknown {
  if (!rawText.trim()) return null;
  try {
    return JSON.parse(rawText) as unknown;
  } catch {
    return null;
  }
}

function buildSub2ApiRefreshFailureMessage(input: {
  status?: number;
  rawText?: string;
  payload?: unknown;
}): string {
  const prefix = typeof input.status === 'number' && Number.isFinite(input.status) && input.status > 0
    ? `sub2api token refresh failed: HTTP ${Math.trunc(input.status)}`
    : 'sub2api token refresh failed';

  if (isRecord(input.payload)) {
    const message = normalizeNonEmptyString(
      input.payload.message
      ?? input.payload.error
      ?? input.payload.error_description,
    );
    const reason = normalizeNonEmptyString(input.payload.reason);
    if (message && reason && reason.toLowerCase() !== message.toLowerCase()) {
      return `${prefix}: ${message} (${reason})`;
    }
    if (message) {
      return `${prefix}: ${message}`;
    }
    if (reason) {
      return `${prefix}: ${reason}`;
    }
  }

  const fallbackSnippet = normalizeErrorSnippet(input.rawText || '');
  if (fallbackSnippet) {
    return `${prefix}: ${fallbackSnippet}`;
  }

  return prefix;
}

export function isSub2ApiPlatform(platform?: string | null): boolean {
  return (platform || '').trim().toLowerCase() === 'sub2api';
}

export function isManagedSub2ApiTokenDue(
  tokenExpiresAt?: number,
  nowMs = Date.now(),
): boolean {
  if (!(typeof tokenExpiresAt === 'number' && Number.isFinite(tokenExpiresAt) && tokenExpiresAt > 0)) {
    return false;
  }
  return tokenExpiresAt - nowMs <= SUB2API_MANAGED_REFRESH_LEAD_MS;
}

export async function refreshSub2ApiManagedSession(params: {
  account: typeof schema.accounts.$inferSelect;
  site: typeof schema.sites.$inferSelect;
  currentAccessToken: string;
  currentExtraConfig: string | null;
}): Promise<{ accessToken: string; extraConfig: string }> {
  const managedAuth = getSub2ApiAuthFromExtraConfig(params.currentExtraConfig);
  const refreshToken = managedAuth?.refreshToken || '';
  if (!refreshToken) throw new Error('sub2api managed refresh token missing');

  const endpoint = `${params.site.url.replace(/\/+$/, '')}/api/v1/auth/refresh`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const authHeaderToken = normalizeNonEmptyString(params.currentAccessToken);
  if (authHeaderToken) {
    headers.Authorization = `Bearer ${authHeaderToken}`;
  }

  const { fetch } = await import('undici');
  let status = 0;
  let rawText = '';
  let payload: unknown = null;
  try {
    const response = await fetch(endpoint, withSiteRecordProxyRequestInit(params.site, {
      method: 'POST',
      headers,
      body: JSON.stringify({ refresh_token: refreshToken }),
    }, resolveProxyUrlFromExtraConfig(params.currentExtraConfig)));
    status = response.status;
    if (typeof response.text === 'function') {
      rawText = await response.text().catch(() => '');
      payload = parseJsonPayload(rawText);
    } else if (typeof response.json === 'function') {
      payload = await response.json().catch(() => null);
      rawText = payload == null ? '' : JSON.stringify(payload);
    }
  } catch (err: any) {
    throw new Error(err?.message || 'sub2api token refresh request failed');
  }

  const refreshed = parseSub2ApiRefreshPayload(payload);
  if (!refreshed) {
    throw new Error(buildSub2ApiRefreshFailureMessage({
      status,
      rawText,
      payload,
    }));
  }

  const nextExtraConfig = mergeAccountExtraConfig(params.currentExtraConfig, {
    sub2apiAuth: {
      refreshToken: refreshed.refreshToken,
      tokenExpiresAt: refreshed.tokenExpiresAt,
    },
  });
  await db.update(schema.accounts)
    .set({
      accessToken: refreshed.accessToken,
      extraConfig: nextExtraConfig,
      status: params.account.status === 'expired' ? 'active' : params.account.status,
      updatedAt: new Date().toISOString(),
    })
    .where(eq(schema.accounts.id, params.account.id))
    .run();

  return {
    accessToken: refreshed.accessToken,
    extraConfig: nextExtraConfig,
  };
}
