import { createHash, randomBytes } from 'node:crypto';

export type OAuthSessionStatus = 'pending' | 'success' | 'error';

export type OAuthSessionRecord = {
  provider: string;
  state: string;
  status: OAuthSessionStatus;
  codeVerifier: string;
  redirectUri: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  accountId?: number;
  siteId?: number;
  error?: string;
  rebindAccountId?: number;
};

const SESSION_TTL_MS = 10 * 60 * 1000;
const oauthSessions = new Map<string, OAuthSessionRecord>();

function nowIso(): string {
  return new Date().toISOString();
}

function toBase64Url(input: Buffer): string {
  return input.toString('base64url');
}

function pruneExpiredSessions(nowMs = Date.now()) {
  for (const [state, session] of oauthSessions.entries()) {
    if (Date.parse(session.expiresAt) <= nowMs) {
      oauthSessions.delete(state);
    }
  }
}

function createPkceVerifier(): string {
  return toBase64Url(randomBytes(48));
}

export function createPkceChallenge(codeVerifier: string): string {
  return createHash('sha256').update(codeVerifier).digest('base64url');
}

export function createOauthSession(input: {
  provider: string;
  redirectUri: string;
  rebindAccountId?: number;
}): OAuthSessionRecord {
  pruneExpiredSessions();
  const state = toBase64Url(randomBytes(24));
  const codeVerifier = createPkceVerifier();
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const record: OAuthSessionRecord = {
    provider: input.provider,
    state,
    status: 'pending',
    codeVerifier,
    redirectUri: input.redirectUri,
    createdAt,
    updatedAt: createdAt,
    expiresAt,
    rebindAccountId: input.rebindAccountId,
  };
  oauthSessions.set(state, record);
  return record;
}

export function getOauthSession(state: string): OAuthSessionRecord | null {
  pruneExpiredSessions();
  return oauthSessions.get(state) || null;
}

export function markOauthSessionSuccess(
  state: string,
  patch: { accountId: number; siteId: number },
): OAuthSessionRecord | null {
  const existing = getOauthSession(state);
  if (!existing) return null;
  const next: OAuthSessionRecord = {
    ...existing,
    status: 'success',
    updatedAt: nowIso(),
    accountId: patch.accountId,
    siteId: patch.siteId,
    error: undefined,
  };
  oauthSessions.set(state, next);
  return next;
}

export function markOauthSessionError(state: string, error: string): OAuthSessionRecord | null {
  const existing = getOauthSession(state);
  if (!existing) return null;
  const next: OAuthSessionRecord = {
    ...existing,
    status: 'error',
    updatedAt: nowIso(),
    error: error.trim() || 'OAuth failed',
  };
  oauthSessions.set(state, next);
  return next;
}
