import { fetch } from 'undici';
import { config } from '../../config.js';
import { createPkceChallenge } from './sessionStore.js';
import type { OAuthProviderDefinition } from './providers.js';

export const CODEX_OAUTH_PROVIDER = 'codex';
export const CODEX_AUTH_URL = 'https://auth.openai.com/oauth/authorize';
export const CODEX_TOKEN_URL = 'https://auth.openai.com/oauth/token';
export const CODEX_CLIENT_ID = config.codexClientId;
export const CODEX_CALLBACK_PATH = '/api/oauth/callback/codex';
export const CODEX_LOOPBACK_CALLBACK_PATH = '/auth/callback';
export const CODEX_LOOPBACK_CALLBACK_PORT = 1455;
export const CODEX_LOOPBACK_REDIRECT_URI = `http://localhost:${CODEX_LOOPBACK_CALLBACK_PORT}${CODEX_LOOPBACK_CALLBACK_PATH}`;
export const CODEX_UPSTREAM_BASE_URL = 'https://chatgpt.com/backend-api/codex';

function requireCodexClientId(): string {
  if (!CODEX_CLIENT_ID) {
    throw new Error('CODEX_CLIENT_ID is not configured');
  }
  return CODEX_CLIENT_ID;
}

type CodexJwtClaims = {
  email?: unknown;
  'https://api.openai.com/auth'?: {
    chatgpt_account_id?: unknown;
    chatgpt_plan_type?: unknown;
  };
};

export type CodexTokenExchangeResult = {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  accountId?: string;
  email?: string;
  planType?: string;
  tokenExpiresAt: number;
};

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function parseJwtClaims(token: string): CodexJwtClaims | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1] || '', 'base64url').toString('utf8')) as unknown;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    return payload as CodexJwtClaims;
  } catch {
    return null;
  }
}

export async function buildCodexAuthorizationUrl(input: {
  state: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<string> {
  const params = new URLSearchParams({
    client_id: requireCodexClientId(),
    response_type: 'code',
    redirect_uri: input.redirectUri,
    scope: 'openid email profile offline_access',
    state: input.state,
    code_challenge: await createPkceChallenge(input.codeVerifier),
    code_challenge_method: 'S256',
    prompt: 'login',
    id_token_add_organizations: 'true',
    codex_cli_simplified_flow: 'true',
  });
  return `${CODEX_AUTH_URL}?${params.toString()}`;
}

function parseTokenResponsePayload(payload: unknown): CodexTokenExchangeResult {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('codex token exchange returned invalid payload');
  }
  const body = payload as Record<string, unknown>;
  const accessToken = asTrimmedString(body.access_token);
  const refreshToken = asTrimmedString(body.refresh_token);
  const idToken = asTrimmedString(body.id_token);
  const expiresIn = typeof body.expires_in === 'number' && Number.isFinite(body.expires_in)
    ? Math.trunc(body.expires_in)
    : (typeof body.expires_in === 'string' ? Number.parseInt(body.expires_in.trim(), 10) : NaN);
  if (!accessToken || !refreshToken || !idToken || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw new Error('codex token exchange response missing required fields');
  }
  const claims = parseJwtClaims(idToken);
  return {
    accessToken,
    refreshToken,
    idToken,
    accountId: asTrimmedString(claims?.['https://api.openai.com/auth']?.chatgpt_account_id),
    email: asTrimmedString(claims?.email),
    planType: asTrimmedString(claims?.['https://api.openai.com/auth']?.chatgpt_plan_type),
    tokenExpiresAt: Date.now() + expiresIn * 1000,
  };
}

async function exchangeCodexToken(form: URLSearchParams): Promise<CodexTokenExchangeResult> {
  const response = await fetch(CODEX_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: form.toString(),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(text || `codex token exchange failed with status ${response.status}`);
  }
  return parseTokenResponsePayload(await response.json());
}

export async function exchangeCodexAuthorizationCode(input: {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}): Promise<CodexTokenExchangeResult> {
  return exchangeCodexToken(new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: requireCodexClientId(),
    code: input.code,
    redirect_uri: input.redirectUri,
    code_verifier: input.codeVerifier,
  }));
}

export async function refreshCodexTokens(refreshToken: string): Promise<CodexTokenExchangeResult> {
  return exchangeCodexToken(new URLSearchParams({
    client_id: requireCodexClientId(),
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    scope: 'openid profile email',
  }));
}

function getHeaderValue(headers: Record<string, unknown> | undefined, key: string): string | undefined {
  if (!headers) return undefined;
  const loweredKey = key.toLowerCase();
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    if (rawKey.toLowerCase() !== loweredKey) continue;
    if (typeof rawValue === 'string') {
      const trimmed = rawValue.trim();
      if (trimmed) return trimmed;
    }
    if (Array.isArray(rawValue)) {
      for (const item of rawValue) {
        if (typeof item !== 'string') continue;
        const trimmed = item.trim();
        if (trimmed) return trimmed;
      }
    }
  }
  return undefined;
}

export const codexOauthProvider: OAuthProviderDefinition = {
  metadata: {
    provider: CODEX_OAUTH_PROVIDER,
    label: 'Codex',
    platform: 'codex',
    enabled: true,
    loginType: 'oauth',
    requiresProjectId: false,
    supportsDirectAccountRouting: true,
    supportsCloudValidation: true,
    supportsNativeProxy: true,
  },
  site: {
    name: 'ChatGPT Codex OAuth',
    url: CODEX_UPSTREAM_BASE_URL,
    platform: 'codex',
  },
  loopback: {
    host: '127.0.0.1',
    port: CODEX_LOOPBACK_CALLBACK_PORT,
    path: CODEX_LOOPBACK_CALLBACK_PATH,
    redirectUri: CODEX_LOOPBACK_REDIRECT_URI,
  },
  buildAuthorizationUrl: ({ state, redirectUri, codeVerifier }) => buildCodexAuthorizationUrl({
    state,
    redirectUri,
    codeVerifier,
  }),
  exchangeAuthorizationCode: async ({ code, redirectUri, codeVerifier }) => {
    const exchange = await exchangeCodexAuthorizationCode({
      code,
      redirectUri,
      codeVerifier,
    });
    return {
      accessToken: exchange.accessToken,
      refreshToken: exchange.refreshToken,
      tokenExpiresAt: exchange.tokenExpiresAt,
      email: exchange.email,
      accountId: exchange.accountId,
      accountKey: exchange.accountId,
      planType: exchange.planType,
      idToken: exchange.idToken,
    };
  },
  refreshAccessToken: async ({ refreshToken }) => {
    const refreshed = await refreshCodexTokens(refreshToken);
    return {
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
      tokenExpiresAt: refreshed.tokenExpiresAt,
      email: refreshed.email,
      accountId: refreshed.accountId,
      accountKey: refreshed.accountId,
      planType: refreshed.planType,
      idToken: refreshed.idToken,
    };
  },
  buildProxyHeaders: ({ oauth, downstreamHeaders }) => {
    const accountId = getHeaderValue(downstreamHeaders, 'chatgpt-account-id') || oauth.accountId || oauth.accountKey;
    const originator = getHeaderValue(downstreamHeaders, 'originator') || 'codex_cli_rs';
    const headers: Record<string, string> = {
      Originator: originator,
    };
    if (accountId) {
      headers['Chatgpt-Account-Id'] = accountId;
    }
    return headers;
  },
};
