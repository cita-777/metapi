import { fetch } from 'undici';
import type { OAuthProviderDefinition } from './providers.js';

export const ANTIGRAVITY_OAUTH_PROVIDER = 'antigravity';
export const ANTIGRAVITY_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
export const ANTIGRAVITY_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const ANTIGRAVITY_USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json';
export const ANTIGRAVITY_CLIENT_ID = '1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com';
export const ANTIGRAVITY_CLIENT_SECRET = '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';
export const ANTIGRAVITY_LOOPBACK_CALLBACK_PORT = 51121;
export const ANTIGRAVITY_LOOPBACK_CALLBACK_PATH = '/oauth-callback';
export const ANTIGRAVITY_LOOPBACK_REDIRECT_URI = `http://localhost:${ANTIGRAVITY_LOOPBACK_CALLBACK_PORT}${ANTIGRAVITY_LOOPBACK_CALLBACK_PATH}`;
export const ANTIGRAVITY_UPSTREAM_BASE_URL = 'https://cloudcode-pa.googleapis.com';
export const ANTIGRAVITY_DAILY_UPSTREAM_BASE_URL = 'https://daily-cloudcode-pa.googleapis.com';
export const ANTIGRAVITY_SANDBOX_DAILY_UPSTREAM_BASE_URL = 'https://daily-cloudcode-pa.sandbox.googleapis.com';
export const ANTIGRAVITY_GOOGLE_API_CLIENT = 'google-cloud-sdk vscode_cloudshelleditor/0.1';
export const ANTIGRAVITY_USER_AGENT = 'google-api-nodejs-client/9.15.1';
export const ANTIGRAVITY_MODELS_USER_AGENT = 'antigravity/1.19.6 darwin/arm64';
export const ANTIGRAVITY_CLIENT_METADATA = '{"ideType":"IDE_UNSPECIFIED","platform":"PLATFORM_UNSPECIFIED","pluginType":"GEMINI"}';
export const ANTIGRAVITY_INTERNAL_API_VERSION = 'v1internal';
export const ANTIGRAVITY_ONBOARD_POLL_INTERVAL_MS = 2_000;
export const ANTIGRAVITY_ONBOARD_MAX_ATTEMPTS = 5;

const ANTIGRAVITY_SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/cclog',
  'https://www.googleapis.com/auth/experimentsandconfigs',
];

type AntigravityOAuthTokenPayload = {
  access_token?: unknown;
  refresh_token?: unknown;
  token_type?: unknown;
  expires_in?: unknown;
  scope?: unknown;
  expiry?: unknown;
};

type AntigravityLoadCodeAssistPayload = {
  cloudaicompanionProject?: unknown;
  allowedTiers?: unknown;
};

type AntigravityOnboardUserPayload = {
  done?: unknown;
  response?: unknown;
};

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function parseExpiresAt(payload: AntigravityOAuthTokenPayload): number | undefined {
  if (typeof payload.expires_in === 'number' && Number.isFinite(payload.expires_in) && payload.expires_in > 0) {
    return Date.now() + Math.trunc(payload.expires_in) * 1000;
  }
  if (typeof payload.expires_in === 'string') {
    const parsed = Number.parseInt(payload.expires_in.trim(), 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return Date.now() + parsed * 1000;
    }
  }
  if (typeof payload.expiry === 'string') {
    const parsed = Date.parse(payload.expiry);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return undefined;
}

function buildAntigravityMetadata() {
  return {
    ideType: 'ANTIGRAVITY',
    platform: 'PLATFORM_UNSPECIFIED',
    pluginType: 'GEMINI',
  };
}

function extractAntigravityProjectId(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return asTrimmedString(value);
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return asTrimmedString((value as { id?: unknown }).id);
  }
  return undefined;
}

function extractAntigravityDefaultTierId(payload: AntigravityLoadCodeAssistPayload): string {
  const allowedTiers = Array.isArray(payload.allowedTiers) ? payload.allowedTiers : [];
  for (const rawTier of allowedTiers) {
    if (!rawTier || typeof rawTier !== 'object' || Array.isArray(rawTier)) continue;
    const tier = rawTier as { id?: unknown; isDefault?: unknown };
    if (tier.isDefault === true) {
      const tierId = asTrimmedString(tier.id);
      if (tierId) return tierId;
    }
  }
  return 'legacy-tier';
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function callAntigravityInternalApi<T>(
  accessToken: string,
  method: 'loadCodeAssist' | 'onboardUser',
  body: Record<string, unknown>,
): Promise<T | undefined> {
  const response = await fetch(
    `${ANTIGRAVITY_UPSTREAM_BASE_URL}/${ANTIGRAVITY_INTERNAL_API_VERSION}:${method}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': ANTIGRAVITY_USER_AGENT,
        'X-Goog-Api-Client': ANTIGRAVITY_GOOGLE_API_CLIENT,
        'Client-Metadata': ANTIGRAVITY_CLIENT_METADATA,
      },
      body: JSON.stringify(body),
    },
  );
  if (!response.ok) return undefined;
  return response.json() as Promise<T>;
}

async function postAntigravityToken(body: URLSearchParams) {
  const response = await fetch(ANTIGRAVITY_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(text || `antigravity token exchange failed with status ${response.status}`);
  }
  const payload = await response.json() as AntigravityOAuthTokenPayload;
  const accessToken = asTrimmedString(payload.access_token);
  if (!accessToken) {
    throw new Error('antigravity token exchange response missing access token');
  }
  return {
    accessToken,
    refreshToken: asTrimmedString(payload.refresh_token),
    tokenExpiresAt: parseExpiresAt(payload),
    providerData: {
      tokenType: asTrimmedString(payload.token_type),
      scope: asTrimmedString(payload.scope),
    },
  };
}

async function fetchAntigravityUserEmail(accessToken: string): Promise<string | undefined> {
  const response = await fetch(ANTIGRAVITY_USERINFO_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });
  if (!response.ok) return undefined;
  const payload = await response.json() as { email?: unknown };
  return asTrimmedString(payload.email);
}

async function fetchAntigravityProjectId(accessToken: string): Promise<string | undefined> {
  const metadata = buildAntigravityMetadata();
  const payload = await callAntigravityInternalApi<AntigravityLoadCodeAssistPayload>(
    accessToken,
    'loadCodeAssist',
    { metadata },
  );
  if (!payload) return undefined;

  const discoveredFromLoad = extractAntigravityProjectId(payload.cloudaicompanionProject);
  if (discoveredFromLoad) {
    return discoveredFromLoad;
  }

  const tierId = extractAntigravityDefaultTierId(payload);
  for (let attempt = 0; attempt < ANTIGRAVITY_ONBOARD_MAX_ATTEMPTS; attempt += 1) {
    const onboardPayload = await callAntigravityInternalApi<AntigravityOnboardUserPayload>(
      accessToken,
      'onboardUser',
      {
        tierId,
        metadata,
      },
    );
    if (!onboardPayload) return undefined;
    if (onboardPayload.done === true) {
      const response = (
        onboardPayload.response
        && typeof onboardPayload.response === 'object'
        && !Array.isArray(onboardPayload.response)
      )
        ? onboardPayload.response as { cloudaicompanionProject?: unknown }
        : undefined;
      return extractAntigravityProjectId(response?.cloudaicompanionProject);
    }
    if ((attempt + 1) < ANTIGRAVITY_ONBOARD_MAX_ATTEMPTS) {
      await sleep(ANTIGRAVITY_ONBOARD_POLL_INTERVAL_MS);
    }
  }

  return undefined;
}

export const antigravityOauthProvider: OAuthProviderDefinition = {
  metadata: {
    provider: ANTIGRAVITY_OAUTH_PROVIDER,
    label: 'Antigravity',
    platform: 'antigravity',
    enabled: true,
    loginType: 'oauth',
    requiresProjectId: false,
    supportsDirectAccountRouting: true,
    supportsCloudValidation: true,
    supportsNativeProxy: false,
  },
  site: {
    name: 'Google Antigravity OAuth',
    url: ANTIGRAVITY_UPSTREAM_BASE_URL,
    platform: 'antigravity',
  },
  loopback: {
    host: '127.0.0.1',
    port: ANTIGRAVITY_LOOPBACK_CALLBACK_PORT,
    path: ANTIGRAVITY_LOOPBACK_CALLBACK_PATH,
    redirectUri: ANTIGRAVITY_LOOPBACK_REDIRECT_URI,
  },
  buildAuthorizationUrl: async ({ state, redirectUri }) => {
    const params = new URLSearchParams({
      client_id: ANTIGRAVITY_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: 'code',
      access_type: 'offline',
      prompt: 'consent',
      scope: ANTIGRAVITY_SCOPES.join(' '),
      state,
    });
    return `${ANTIGRAVITY_AUTH_URL}?${params.toString()}`;
  },
  exchangeAuthorizationCode: async ({ code, redirectUri }) => {
    const token = await postAntigravityToken(new URLSearchParams({
      code,
      client_id: ANTIGRAVITY_CLIENT_ID,
      client_secret: ANTIGRAVITY_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }));
    const email = await fetchAntigravityUserEmail(token.accessToken);
    const projectId = await fetchAntigravityProjectId(token.accessToken);
    return {
      ...token,
      email,
      accountKey: email,
      accountId: email,
      projectId,
    };
  },
  refreshAccessToken: async ({ refreshToken, oauth }) => {
    const token = await postAntigravityToken(new URLSearchParams({
      client_id: ANTIGRAVITY_CLIENT_ID,
      client_secret: ANTIGRAVITY_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    }));
    const email = await fetchAntigravityUserEmail(token.accessToken);
    return {
      ...token,
      email,
      accountKey: email,
      accountId: email,
      projectId: oauth?.projectId ?? await fetchAntigravityProjectId(token.accessToken),
    };
  },
  buildProxyHeaders: () => ({
    'User-Agent': ANTIGRAVITY_USER_AGENT,
    'X-Goog-Api-Client': ANTIGRAVITY_GOOGLE_API_CLIENT,
    'Client-Metadata': ANTIGRAVITY_CLIENT_METADATA,
  }),
};
