import { randomBytes, webcrypto } from 'node:crypto';

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
  projectId?: string;
  proxyUrl?: string | null;
  useSystemProxy?: boolean;
};

export interface OAuthSessionStore {
  create(input: {
    provider: string;
    redirectUri: string;
    rebindAccountId?: number;
    projectId?: string;
    proxyUrl?: string | null;
    useSystemProxy?: boolean;
  }): OAuthSessionRecord;
  get(state: string): OAuthSessionRecord | null;
  markSuccess(state: string, patch: { accountId: number; siteId: number }): OAuthSessionRecord | null;
  markError(state: string, error: string): OAuthSessionRecord | null;
}

const SESSION_TTL_MS = 10 * 60 * 1000;

function nowIso(): string {
  return new Date().toISOString();
}

function toBase64Url(input: Buffer): string {
  return input.toString('base64url');
}

function createPkceVerifier(): string {
  return toBase64Url(randomBytes(48));
}

export async function createPkceChallenge(codeVerifier: string): Promise<string> {
  const digest = await webcrypto.subtle.digest('SHA-256', Buffer.from(codeVerifier, 'utf8'));
  return Buffer.from(digest).toString('base64url');
}

class MemoryOAuthSessionStore implements OAuthSessionStore {
  private readonly sessions = new Map<string, OAuthSessionRecord>();

  private pruneExpiredSessions(nowMs = Date.now()) {
    for (const [state, session] of this.sessions.entries()) {
      if (Date.parse(session.expiresAt) <= nowMs) {
        this.sessions.delete(state);
      }
    }
  }

  create(input: {
    provider: string;
    redirectUri: string;
    rebindAccountId?: number;
    projectId?: string;
    proxyUrl?: string | null;
    useSystemProxy?: boolean;
  }): OAuthSessionRecord {
    this.pruneExpiredSessions();
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
      projectId: input.projectId,
      proxyUrl: input.proxyUrl,
      useSystemProxy: input.useSystemProxy,
    };
    this.sessions.set(state, record);
    return record;
  }

  get(state: string): OAuthSessionRecord | null {
    this.pruneExpiredSessions();
    return this.sessions.get(state) || null;
  }

  markSuccess(state: string, patch: { accountId: number; siteId: number }): OAuthSessionRecord | null {
    const existing = this.get(state);
    if (!existing) return null;
    const next: OAuthSessionRecord = {
      ...existing,
      status: 'success',
      updatedAt: nowIso(),
      accountId: patch.accountId,
      siteId: patch.siteId,
      error: undefined,
    };
    this.sessions.set(state, next);
    return next;
  }

  markError(state: string, error: string): OAuthSessionRecord | null {
    const existing = this.get(state);
    if (!existing) return null;
    const next: OAuthSessionRecord = {
      ...existing,
      status: 'error',
      updatedAt: nowIso(),
      error: error.trim() || 'OAuth failed',
    };
    this.sessions.set(state, next);
    return next;
  }
}

let oauthSessionStore: OAuthSessionStore = new MemoryOAuthSessionStore();

export function setOauthSessionStore(store: OAuthSessionStore) {
  oauthSessionStore = store;
}

export function createOauthSession(input: {
  provider: string;
  redirectUri: string;
  rebindAccountId?: number;
  projectId?: string;
  proxyUrl?: string | null;
  useSystemProxy?: boolean;
}): OAuthSessionRecord {
  return oauthSessionStore.create(input);
}

export function getOauthSession(state: string): OAuthSessionRecord | null {
  return oauthSessionStore.get(state);
}

export function markOauthSessionSuccess(
  state: string,
  patch: { accountId: number; siteId: number },
): OAuthSessionRecord | null {
  return oauthSessionStore.markSuccess(state, patch);
}

export function markOauthSessionError(state: string, error: string): OAuthSessionRecord | null {
  return oauthSessionStore.markError(state, error);
}
