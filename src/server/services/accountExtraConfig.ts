type AutoReloginConfig = {
  username?: unknown;
  passwordCipher?: unknown;
  updatedAt?: unknown;
};

type Sub2ApiAuthConfig = {
  refreshToken?: unknown;
  tokenExpiresAt?: unknown;
};

export type AccountCredentialMode = 'auto' | 'session' | 'apikey';

const VALID_CREDENTIAL_MODES = new Set<AccountCredentialMode>([
  'auto',
  'session',
  'apikey',
]);

type AccountExtraConfig = {
  platformUserId?: unknown;
  credentialMode?: unknown;
  oauth?: {
    provider?: unknown;
    [key: string]: unknown;
  };
  autoRelogin?: AutoReloginConfig;
  sub2apiAuth?: Sub2ApiAuthConfig;
  [key: string]: unknown;
};

function parseExtraConfig(extraConfig?: string | null): AccountExtraConfig {
  if (!extraConfig) return {};
  try {
    const parsed = JSON.parse(extraConfig) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return parsed as AccountExtraConfig;
  } catch {
    return {};
  }
}

function normalizeUserId(raw: unknown): number | undefined {
  if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) return Math.trunc(raw);
  if (typeof raw === 'string') {
    const n = Number.parseInt(raw.trim(), 10);
    if (!Number.isNaN(n) && n > 0) return n;
  }
  return undefined;
}

function normalizeNonEmptyString(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeTimestampMs(raw: unknown): number | undefined {
  if (typeof raw === 'number' && Number.isFinite(raw) && raw > 0) return Math.trunc(raw);
  if (typeof raw === 'string') {
    const parsed = Number.parseInt(raw.trim(), 10);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return undefined;
}

export function normalizeCredentialMode(raw: unknown): AccountCredentialMode | undefined {
  if (typeof raw !== 'string') return undefined;
  const normalized = raw.trim().toLowerCase();
  if (!VALID_CREDENTIAL_MODES.has(normalized as AccountCredentialMode)) return undefined;
  return normalized as AccountCredentialMode;
}

export function getPlatformUserIdFromExtraConfig(extraConfig?: string | null): number | undefined {
  const parsed = parseExtraConfig(extraConfig);
  return normalizeUserId(parsed.platformUserId);
}

export function getCredentialModeFromExtraConfig(extraConfig?: string | null): AccountCredentialMode | undefined {
  const parsed = parseExtraConfig(extraConfig);
  return normalizeCredentialMode(parsed.credentialMode);
}

export function getOauthProviderFromExtraConfig(extraConfig?: string | null): string | undefined {
  const parsed = parseExtraConfig(extraConfig);
  return normalizeNonEmptyString(parsed.oauth?.provider);
}

export function hasOauthProvider(extraConfig?: string | null): boolean {
  return !!getOauthProviderFromExtraConfig(extraConfig);
}

type DirectAccountRoutingInput = {
  accessToken?: string | null;
  apiToken?: string | null;
  extraConfig?: string | null;
};

function hasCredentialValue(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}

export function supportsDirectAccountRoutingConnection(account: DirectAccountRoutingInput): boolean {
  const credentialMode = getCredentialModeFromExtraConfig(account.extraConfig);
  if (credentialMode === 'apikey') {
    return hasCredentialValue(account.apiToken);
  }
  if (hasOauthProvider(account.extraConfig)) {
    return hasCredentialValue(account.accessToken);
  }
  return false;
}

export function requiresManagedAccountTokens(account: DirectAccountRoutingInput): boolean {
  const credentialMode = getCredentialModeFromExtraConfig(account.extraConfig);
  if (credentialMode === 'apikey') return false;
  if (hasOauthProvider(account.extraConfig)) return false;
  return true;
}

export type ManagedSub2ApiAuth = {
  refreshToken: string;
  tokenExpiresAt?: number;
};

export function getSub2ApiAuthFromExtraConfig(extraConfig?: string | null): ManagedSub2ApiAuth | null {
  const parsed = parseExtraConfig(extraConfig);
  const raw = parsed.sub2apiAuth;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const refreshToken = normalizeNonEmptyString(raw.refreshToken);
  if (!refreshToken) return null;
  const tokenExpiresAt = normalizeTimestampMs(raw.tokenExpiresAt);
  return tokenExpiresAt
    ? { refreshToken, tokenExpiresAt }
    : { refreshToken };
}

export function guessPlatformUserIdFromUsername(username?: string | null): number | undefined {
  const text = (username || '').trim();
  if (!text) return undefined;
  const match = text.match(/(\d{3,8})$/);
  if (!match?.[1]) return undefined;
  return normalizeUserId(match[1]);
}

export function resolvePlatformUserId(extraConfig?: string | null, username?: string | null): number | undefined {
  return getPlatformUserIdFromExtraConfig(extraConfig) || guessPlatformUserIdFromUsername(username);
}

export function mergeAccountExtraConfig(
  extraConfig: string | null | undefined,
  patch: Record<string, unknown>,
): string {
  const merged: Record<string, unknown> = {
    ...parseExtraConfig(extraConfig),
    ...patch,
  };
  return JSON.stringify(merged);
}

export function getAutoReloginConfig(extraConfig?: string | null): {
  username: string;
  passwordCipher: string;
} | null {
  const parsed = parseExtraConfig(extraConfig);
  const relogin = parsed.autoRelogin;
  if (!relogin || typeof relogin !== 'object' || Array.isArray(relogin)) return null;

  const username = typeof relogin.username === 'string' ? relogin.username.trim() : '';
  const passwordCipher = typeof relogin.passwordCipher === 'string' ? relogin.passwordCipher.trim() : '';
  if (!username || !passwordCipher) return null;

  return { username, passwordCipher };
}
