import { fetch } from 'undici';
import { config } from '../../config.js';
import { createPkceChallenge } from './sessionStore.js';
import type { OAuthProviderDefinition } from './providers.js';

export const CLAUDE_OAUTH_PROVIDER = 'claude';
export const CLAUDE_AUTH_URL = 'https://claude.ai/oauth/authorize';
export const CLAUDE_TOKEN_URL = 'https://api.anthropic.com/v1/oauth/token';
export const CLAUDE_CLIENT_ID = config.claudeClientId;
export const CLAUDE_LOOPBACK_CALLBACK_PORT = 54545;
export const CLAUDE_LOOPBACK_CALLBACK_PATH = '/callback';
export const CLAUDE_LOOPBACK_REDIRECT_URI = `http://localhost:${CLAUDE_LOOPBACK_CALLBACK_PORT}${CLAUDE_LOOPBACK_CALLBACK_PATH}`;
export const CLAUDE_UPSTREAM_BASE_URL = 'https://api.anthropic.com';
export const CLAUDE_DEFAULT_ANTHROPIC_VERSION = '2023-06-01';

function requireClaudeClientId(): string {
  if (!CLAUDE_CLIENT_ID) {
    throw new Error('CLAUDE_CLIENT_ID is not configured');
  }
  return CLAUDE_CLIENT_ID;
}

type ClaudeTokenResponse = {
  access_token?: unknown;
  refresh_token?: unknown;
  token_type?: unknown;
  expires_in?: unknown;
  organization?: {
    uuid?: unknown;
    name?: unknown;
  };
  account?: {
    uuid?: unknown;
    email_address?: unknown;
  };
};

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function parseExpiresAt(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return Date.now() + Math.trunc(value) * 1000;
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return Date.now() + parsed * 1000;
    }
  }
  return undefined;
}

function parseClaudeTokenPayload(payload: unknown) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('claude token exchange returned invalid payload');
  }
  const body = payload as ClaudeTokenResponse;
  const accessToken = asTrimmedString(body.access_token);
  if (!accessToken) {
    throw new Error('claude token exchange response missing access token');
  }
  return {
    accessToken,
    refreshToken: asTrimmedString(body.refresh_token),
    tokenExpiresAt: parseExpiresAt(body.expires_in),
    email: asTrimmedString(body.account?.email_address),
    accountId: asTrimmedString(body.account?.uuid),
    accountKey: asTrimmedString(body.account?.uuid) || asTrimmedString(body.account?.email_address),
    providerData: {
      organizationId: asTrimmedString(body.organization?.uuid),
      organizationName: asTrimmedString(body.organization?.name),
    },
  };
}

async function postClaudeToken(body: Record<string, unknown>) {
  const response = await fetch(CLAUDE_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(text || `claude token exchange failed with status ${response.status}`);
  }
  return parseClaudeTokenPayload(await response.json());
}

export const claudeOauthProvider: OAuthProviderDefinition = {
  metadata: {
    provider: CLAUDE_OAUTH_PROVIDER,
    label: 'Claude',
    platform: 'claude',
    enabled: true,
    loginType: 'oauth',
    requiresProjectId: false,
    supportsDirectAccountRouting: true,
    supportsCloudValidation: true,
    supportsNativeProxy: true,
  },
  site: {
    name: 'Anthropic Claude OAuth',
    url: CLAUDE_UPSTREAM_BASE_URL,
    platform: 'claude',
  },
  loopback: {
    host: '127.0.0.1',
    port: CLAUDE_LOOPBACK_CALLBACK_PORT,
    path: CLAUDE_LOOPBACK_CALLBACK_PATH,
    redirectUri: CLAUDE_LOOPBACK_REDIRECT_URI,
  },
  buildAuthorizationUrl: async ({ state, redirectUri, codeVerifier }) => {
    const params = new URLSearchParams({
      code: 'true',
      client_id: requireClaudeClientId(),
      response_type: 'code',
      redirect_uri: redirectUri,
      scope: 'org:create_api_key user:profile user:inference',
      code_challenge: await createPkceChallenge(codeVerifier),
      code_challenge_method: 'S256',
      state,
    });
    return `${CLAUDE_AUTH_URL}?${params.toString()}`;
  },
  exchangeAuthorizationCode: async ({ code, state, redirectUri, codeVerifier }) => {
    return postClaudeToken({
      code,
      state,
      grant_type: 'authorization_code',
      client_id: requireClaudeClientId(),
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    });
  },
  refreshAccessToken: async ({ refreshToken }) => {
    return postClaudeToken({
      client_id: requireClaudeClientId(),
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    });
  },
  buildProxyHeaders: () => ({
    'anthropic-version': CLAUDE_DEFAULT_ANTHROPIC_VERSION,
  }),
};
