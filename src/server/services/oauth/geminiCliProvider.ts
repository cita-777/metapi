import { fetch } from 'undici';
import { config } from '../../config.js';
import type { OAuthProviderDefinition } from './providers.js';

export const GEMINI_CLI_OAUTH_PROVIDER = 'gemini-cli';
export const GEMINI_CLI_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
export const GEMINI_CLI_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const GEMINI_CLI_USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json';
export const GEMINI_CLI_PROJECTS_URL = 'https://cloudresourcemanager.googleapis.com/v1/projects';
export const GEMINI_CLI_SERVICE_USAGE_URL = 'https://serviceusage.googleapis.com/v1';
export const GEMINI_CLI_CLIENT_ID = config.geminiCliClientId;
export const GEMINI_CLI_CLIENT_SECRET = config.geminiCliClientSecret;
export const GEMINI_CLI_LOOPBACK_CALLBACK_PORT = 8085;
export const GEMINI_CLI_LOOPBACK_CALLBACK_PATH = '/oauth2callback';
export const GEMINI_CLI_LOOPBACK_REDIRECT_URI = `http://localhost:${GEMINI_CLI_LOOPBACK_CALLBACK_PORT}${GEMINI_CLI_LOOPBACK_CALLBACK_PATH}`;
export const GEMINI_CLI_UPSTREAM_BASE_URL = 'https://cloudcode-pa.googleapis.com';
export const GEMINI_CLI_GOOGLE_API_CLIENT = 'google-genai-sdk/1.41.0 gl-node/v22.19.0';
export const GEMINI_CLI_USER_AGENT = 'GeminiCLI/0.31.0/unknown (win32; x64)';
export const GEMINI_CLI_REQUIRED_SERVICE = 'cloudaicompanion.googleapis.com';
export const GEMINI_CLI_INTERNAL_API_VERSION = 'v1internal';
export const GEMINI_CLI_AUTO_ONBOARD_POLL_INTERVAL_MS = 2_000;
export const GEMINI_CLI_AUTO_ONBOARD_MAX_ATTEMPTS = 15;
export const GEMINI_CLI_ONBOARD_POLL_INTERVAL_MS = 5_000;
export const GEMINI_CLI_ONBOARD_MAX_ATTEMPTS = 6;

function requireGeminiCliOAuthConfig() {
  if (!GEMINI_CLI_CLIENT_ID) {
    throw new Error('GEMINI_CLI_CLIENT_ID is not configured');
  }
  if (!GEMINI_CLI_CLIENT_SECRET) {
    throw new Error('GEMINI_CLI_CLIENT_SECRET is not configured');
  }
  return {
    clientId: GEMINI_CLI_CLIENT_ID,
    clientSecret: GEMINI_CLI_CLIENT_SECRET,
  };
}

const GEMINI_CLI_SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

type GeminiOAuthTokenPayload = {
  access_token?: unknown;
  refresh_token?: unknown;
  token_type?: unknown;
  expires_in?: unknown;
  scope?: unknown;
  expiry?: unknown;
};

type GeminiLoadCodeAssistPayload = {
  cloudaicompanionProject?: unknown;
  allowedTiers?: unknown;
};

type GeminiOnboardUserPayload = {
  done?: unknown;
  response?: unknown;
};

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function parseExpiresAt(payload: GeminiOAuthTokenPayload): number | undefined {
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

function buildGeminiCliMetadata() {
  return {
    ideType: 'IDE_UNSPECIFIED',
    platform: 'PLATFORM_UNSPECIFIED',
    pluginType: 'GEMINI',
  };
}

function extractGeminiProjectId(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return asTrimmedString(value);
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return asTrimmedString((value as { id?: unknown }).id);
  }
  return undefined;
}

function extractGeminiDefaultTierId(payload: GeminiLoadCodeAssistPayload): string {
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

function isGeminiFreeUserProject(input: {
  requestedProjectId?: string;
  tierId: string;
}) {
  const projectId = (input.requestedProjectId || '').trim();
  const tierId = input.tierId.trim();
  return projectId.startsWith('gen-lang-client-')
    || tierId.toUpperCase() === 'FREE'
    || tierId.toUpperCase() === 'LEGACY';
}

function isSameGeminiProjectId(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

function extractGeminiServiceErrorMessage(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  try {
    const parsed = JSON.parse(trimmed) as {
      error?: { message?: unknown };
    };
    return asTrimmedString(parsed.error?.message) || trimmed;
  } catch {
    return trimmed;
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function postGeminiToken(body: URLSearchParams) {
  const response = await fetch(GEMINI_CLI_TOKEN_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(text || `gemini token exchange failed with status ${response.status}`);
  }
  const payload = await response.json() as GeminiOAuthTokenPayload;
  const accessToken = asTrimmedString(payload.access_token);
  if (!accessToken) {
    throw new Error('gemini token exchange response missing access token');
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

async function fetchGeminiUserEmail(accessToken: string): Promise<string | undefined> {
  const response = await fetch(GEMINI_CLI_USERINFO_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });
  if (!response.ok) return undefined;
  const payload = await response.json() as { email?: unknown };
  return asTrimmedString(payload.email);
}

async function callGeminiCliInternalApi<T>(
  accessToken: string,
  method: 'loadCodeAssist' | 'onboardUser',
  body: Record<string, unknown>,
): Promise<T> {
  const response = await fetch(
    `${GEMINI_CLI_UPSTREAM_BASE_URL}/${GEMINI_CLI_INTERNAL_API_VERSION}:${method}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': GEMINI_CLI_USER_AGENT,
        'X-Goog-Api-Client': GEMINI_CLI_GOOGLE_API_CLIENT,
      },
      body: JSON.stringify(body),
    },
  );
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(text || `api request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function fetchGcpProjects(accessToken: string): Promise<string[]> {
  const response = await fetch(GEMINI_CLI_PROJECTS_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(text || `project list request failed with status ${response.status}`);
  }
  const payload = await response.json() as { projects?: Array<{ projectId?: unknown }> };
  return (payload.projects || [])
    .map((project) => asTrimmedString(project.projectId))
    .filter((projectId): projectId is string => !!projectId);
}

async function checkCloudAIAPIEnabled(accessToken: string, projectId: string): Promise<void> {
  const checkResponse = await fetch(
    `${GEMINI_CLI_SERVICE_USAGE_URL}/projects/${encodeURIComponent(projectId)}/services/${encodeURIComponent(GEMINI_CLI_REQUIRED_SERVICE)}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'User-Agent': GEMINI_CLI_USER_AGENT,
        'X-Goog-Api-Client': GEMINI_CLI_GOOGLE_API_CLIENT,
      },
    },
  );
  if (checkResponse.ok) {
    const payload = await checkResponse.json() as { state?: unknown };
    const state = asTrimmedString(payload.state);
    if ((state || '').toUpperCase() === 'ENABLED') {
      return;
    }
  }

  const response = await fetch(
    `${GEMINI_CLI_SERVICE_USAGE_URL}/projects/${encodeURIComponent(projectId)}/services/${encodeURIComponent(GEMINI_CLI_REQUIRED_SERVICE)}:enable`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': GEMINI_CLI_USER_AGENT,
        'X-Goog-Api-Client': GEMINI_CLI_GOOGLE_API_CLIENT,
      },
      body: '{}',
    },
  );
  const text = await response.text().catch(() => '');
  if (response.ok) {
    return;
  }
  if (response.status === 400 && extractGeminiServiceErrorMessage(text).toLowerCase().includes('already enabled')) {
    return;
  }
  throw new Error(`project activation required: ${extractGeminiServiceErrorMessage(text) || `HTTP ${response.status}`}`);
}

async function performGeminiCliSetup(
  accessToken: string,
  requestedProjectId: string,
): Promise<string> {
  const trimmedRequest = requestedProjectId.trim();
  const explicitProject = !!trimmedRequest;
  const metadata = buildGeminiCliMetadata();
  const loadResponse = await callGeminiCliInternalApi<GeminiLoadCodeAssistPayload>(
    accessToken,
    'loadCodeAssist',
    explicitProject
      ? {
        metadata,
        cloudaicompanionProject: trimmedRequest,
      }
      : { metadata },
  );

  const tierId = extractGeminiDefaultTierId(loadResponse);
  let projectId = trimmedRequest || extractGeminiProjectId(loadResponse.cloudaicompanionProject) || '';

  if (!projectId) {
    for (let attempt = 0; attempt < GEMINI_CLI_AUTO_ONBOARD_MAX_ATTEMPTS; attempt += 1) {
      const onboardResponse = await callGeminiCliInternalApi<GeminiOnboardUserPayload>(
        accessToken,
        'onboardUser',
        {
          tierId,
          metadata,
        },
      );
      if (onboardResponse.done === true) {
        const response = (
          onboardResponse.response
          && typeof onboardResponse.response === 'object'
          && !Array.isArray(onboardResponse.response)
        )
          ? onboardResponse.response as { cloudaicompanionProject?: unknown }
          : undefined;
        projectId = extractGeminiProjectId(response?.cloudaicompanionProject) || '';
        break;
      }
      if ((attempt + 1) < GEMINI_CLI_AUTO_ONBOARD_MAX_ATTEMPTS) {
        await sleep(GEMINI_CLI_AUTO_ONBOARD_POLL_INTERVAL_MS);
      }
    }
  }

  if (!projectId) {
    throw new Error('gemini cli: project selection required');
  }

  let finalProjectId = projectId;
  for (let attempt = 0; attempt < GEMINI_CLI_ONBOARD_MAX_ATTEMPTS; attempt += 1) {
    const onboardResponse = await callGeminiCliInternalApi<GeminiOnboardUserPayload>(
      accessToken,
      'onboardUser',
      {
        tierId,
        metadata,
        cloudaicompanionProject: projectId,
      },
    );
    if (onboardResponse.done === true) {
      const response = (
        onboardResponse.response
        && typeof onboardResponse.response === 'object'
        && !Array.isArray(onboardResponse.response)
      )
        ? onboardResponse.response as { cloudaicompanionProject?: unknown }
        : undefined;
      const responseProjectId = extractGeminiProjectId(response?.cloudaicompanionProject) || '';
      if (responseProjectId) {
        if (explicitProject && !isSameGeminiProjectId(responseProjectId, projectId)) {
          finalProjectId = isGeminiFreeUserProject({ requestedProjectId: projectId, tierId })
            ? responseProjectId
            : projectId;
        } else {
          finalProjectId = responseProjectId;
        }
      }
      return finalProjectId || projectId;
    }
    if ((attempt + 1) < GEMINI_CLI_ONBOARD_MAX_ATTEMPTS) {
      await sleep(GEMINI_CLI_ONBOARD_POLL_INTERVAL_MS);
    }
  }

  if (finalProjectId) {
    return finalProjectId;
  }
  throw new Error('gemini cli: onboarding timed out');
}

async function ensureGeminiProjectAndOnboard(
  accessToken: string,
  requestedProjectId?: string,
): Promise<string> {
  const explicitProject = asTrimmedString(requestedProjectId);
  if (explicitProject) {
    return performGeminiCliSetup(accessToken, explicitProject);
  }

  const projects = await fetchGcpProjects(accessToken);
  const firstProject = projects[0];
  if (!firstProject) {
    throw new Error('no Google Cloud projects available for this account');
  }
  return performGeminiCliSetup(accessToken, firstProject);
}

export const geminiCliOauthProvider: OAuthProviderDefinition = {
  metadata: {
    provider: GEMINI_CLI_OAUTH_PROVIDER,
    label: 'Gemini CLI',
    platform: 'gemini-cli',
    enabled: true,
    loginType: 'oauth',
    requiresProjectId: true,
    supportsDirectAccountRouting: true,
    supportsCloudValidation: true,
    supportsNativeProxy: true,
  },
  site: {
    name: 'Google Gemini CLI OAuth',
    url: GEMINI_CLI_UPSTREAM_BASE_URL,
    platform: 'gemini-cli',
  },
  loopback: {
    host: '127.0.0.1',
    port: GEMINI_CLI_LOOPBACK_CALLBACK_PORT,
    path: GEMINI_CLI_LOOPBACK_CALLBACK_PATH,
    redirectUri: GEMINI_CLI_LOOPBACK_REDIRECT_URI,
  },
  buildAuthorizationUrl: async ({ state, redirectUri }) => {
    const oauthConfig = requireGeminiCliOAuthConfig();
    const params = new URLSearchParams({
      client_id: oauthConfig.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      access_type: 'offline',
      prompt: 'consent',
      scope: GEMINI_CLI_SCOPES.join(' '),
      state,
    });
    return `${GEMINI_CLI_AUTH_URL}?${params.toString()}`;
  },
  exchangeAuthorizationCode: async ({ code, redirectUri, projectId }) => {
    const oauthConfig = requireGeminiCliOAuthConfig();
    const token = await postGeminiToken(new URLSearchParams({
      code,
      client_id: oauthConfig.clientId,
      client_secret: oauthConfig.clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }));
    const resolvedProjectId = await ensureGeminiProjectAndOnboard(token.accessToken, projectId);
    await checkCloudAIAPIEnabled(token.accessToken, resolvedProjectId);
    const email = await fetchGeminiUserEmail(token.accessToken);
    return {
      ...token,
      email,
      accountKey: email,
      accountId: email,
      projectId: resolvedProjectId,
    };
  },
  refreshAccessToken: async ({ refreshToken, oauth }) => {
    const oauthConfig = requireGeminiCliOAuthConfig();
    const token = await postGeminiToken(new URLSearchParams({
      client_id: oauthConfig.clientId,
      client_secret: oauthConfig.clientSecret,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    }));
    const nextProjectId = oauth?.projectId
      ? oauth.projectId
      : await ensureGeminiProjectAndOnboard(token.accessToken);
    await checkCloudAIAPIEnabled(token.accessToken, nextProjectId);
    const email = await fetchGeminiUserEmail(token.accessToken);
    return {
      ...token,
      email,
      accountKey: email,
      accountId: email,
      projectId: nextProjectId,
    };
  },
  buildProxyHeaders: () => ({
    'User-Agent': GEMINI_CLI_USER_AGENT,
    'X-Goog-Api-Client': GEMINI_CLI_GOOGLE_API_CLIENT,
  }),
};
