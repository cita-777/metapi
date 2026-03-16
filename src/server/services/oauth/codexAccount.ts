import { schema } from '../../db/index.js';

type ParsedOauthInfo = {
  provider?: unknown;
  accountId?: unknown;
  email?: unknown;
  planType?: unknown;
  tokenExpiresAt?: unknown;
  refreshToken?: unknown;
  idToken?: unknown;
  modelDiscoveryStatus?: unknown;
  lastModelSyncAt?: unknown;
  lastModelSyncError?: unknown;
  lastDiscoveredModels?: unknown;
};

type ParsedExtraConfig = {
  oauth?: ParsedOauthInfo;
};

export type CodexOauthInfo = {
  provider: 'codex';
  accountId?: string;
  email?: string;
  planType?: string;
  tokenExpiresAt?: number;
  refreshToken?: string;
  idToken?: string;
  modelDiscoveryStatus?: 'healthy' | 'abnormal';
  lastModelSyncAt?: string;
  lastModelSyncError?: string;
  lastDiscoveredModels?: string[];
};

function parseExtraConfig(extraConfig?: string | null): ParsedExtraConfig {
  if (!extraConfig) return {};
  try {
    const parsed = JSON.parse(extraConfig) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return parsed as ParsedExtraConfig;
  } catch {
    return {};
  }
}

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function asPositiveInteger(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed) && parsed > 0) return parsed;
  }
  return undefined;
}

function asIsoDateTime(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const parsed = Date.parse(trimmed);
  return Number.isNaN(parsed) ? undefined : new Date(parsed).toISOString();
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const normalized = value
    .map((item) => asTrimmedString(item))
    .filter((item): item is string => !!item);
  return normalized.length > 0 ? normalized : [];
}

function asModelDiscoveryStatus(value: unknown): 'healthy' | 'abnormal' | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'healthy') return 'healthy';
  if (normalized === 'abnormal') return 'abnormal';
  return undefined;
}

export function getCodexOauthInfoFromExtraConfig(extraConfig?: string | null): CodexOauthInfo | null {
  const parsed = parseExtraConfig(extraConfig).oauth;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const provider = asTrimmedString(parsed.provider);
  if (provider !== 'codex') return null;
  return {
    provider: 'codex',
    accountId: asTrimmedString(parsed.accountId),
    email: asTrimmedString(parsed.email),
    planType: asTrimmedString(parsed.planType),
    tokenExpiresAt: asPositiveInteger(parsed.tokenExpiresAt),
    refreshToken: asTrimmedString(parsed.refreshToken),
    idToken: asTrimmedString(parsed.idToken),
    modelDiscoveryStatus: asModelDiscoveryStatus(parsed.modelDiscoveryStatus),
    lastModelSyncAt: asIsoDateTime(parsed.lastModelSyncAt),
    lastModelSyncError: asTrimmedString(parsed.lastModelSyncError),
    lastDiscoveredModels: asStringArray(parsed.lastDiscoveredModels),
  };
}

export function isCodexPlatform(account: Pick<typeof schema.accounts.$inferSelect, 'extraConfig'> | string | null | undefined): boolean {
  const extraConfig = typeof account === 'string' || account == null
    ? account
    : account.extraConfig;
  return getCodexOauthInfoFromExtraConfig(extraConfig)?.provider === 'codex';
}

export function buildCodexOauthInfo(
  extraConfig?: string | null,
  patch: Partial<CodexOauthInfo> = {},
): CodexOauthInfo {
  const current = getCodexOauthInfoFromExtraConfig(extraConfig);
  return {
    provider: 'codex',
    ...(current || {}),
    ...patch,
  };
}
