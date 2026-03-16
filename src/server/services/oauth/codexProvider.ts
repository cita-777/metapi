import { fetch } from 'undici';
import { createPkceChallenge } from './sessionStore.js';

export const CODEX_OAUTH_PROVIDER = 'codex';
export const CODEX_AUTH_URL = 'https://auth.openai.com/oauth/authorize';
export const CODEX_TOKEN_URL = 'https://auth.openai.com/oauth/token';
export const CODEX_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
export const CODEX_CALLBACK_PATH = '/api/oauth/callback/codex';
export const CODEX_LOOPBACK_CALLBACK_PATH = '/auth/callback';
export const CODEX_LOOPBACK_CALLBACK_PORT = 1455;
export const CODEX_LOOPBACK_REDIRECT_URI = `http://localhost:${CODEX_LOOPBACK_CALLBACK_PORT}${CODEX_LOOPBACK_CALLBACK_PATH}`;
export const CODEX_UPSTREAM_BASE_URL = 'https://chatgpt.com/backend-api/codex';

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

export function buildCodexAuthorizationUrl(input: {
  state: string;
  redirectUri: string;
  codeVerifier: string;
}): string {
  const params = new URLSearchParams({
    client_id: CODEX_CLIENT_ID,
    response_type: 'code',
    redirect_uri: input.redirectUri,
    scope: 'openid email profile offline_access',
    state: input.state,
    code_challenge: createPkceChallenge(input.codeVerifier),
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
    client_id: CODEX_CLIENT_ID,
    code: input.code,
    redirect_uri: input.redirectUri,
    code_verifier: input.codeVerifier,
  }));
}

export async function refreshCodexTokens(refreshToken: string): Promise<CodexTokenExchangeResult> {
  return exchangeCodexToken(new URLSearchParams({
    client_id: CODEX_CLIENT_ID,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    scope: 'openid profile email',
  }));
}
