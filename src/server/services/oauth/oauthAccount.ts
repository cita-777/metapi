import { schema } from '../../db/index.js';
import type { OauthQuotaSnapshot } from './quotaTypes.js';

type ParsedOauthInfo = {
  provider?: unknown;
  accountId?: unknown;
  accountKey?: unknown;
  email?: unknown;
  planType?: unknown;
  projectId?: unknown;
  tokenExpiresAt?: unknown;
  refreshToken?: unknown;
  idToken?: unknown;
  providerData?: unknown;
  quota?: unknown;
  modelDiscoveryStatus?: unknown;
  lastModelSyncAt?: unknown;
  lastModelSyncError?: unknown;
  lastDiscoveredModels?: unknown;
};

type ParsedExtraConfig = {
  oauth?: ParsedOauthInfo;
};

export type OauthModelDiscoveryStatus = 'healthy' | 'abnormal';

export type OauthInfo = {
  provider: string;
  accountId?: string;
  accountKey?: string;
  email?: string;
  planType?: string;
  projectId?: string;
  tokenExpiresAt?: number;
  refreshToken?: string;
  idToken?: string;
  providerData?: Record<string, unknown>;
  quota?: OauthQuotaSnapshot;
  modelDiscoveryStatus?: OauthModelDiscoveryStatus;
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
  return value
    .map((item) => asTrimmedString(item))
    .filter((item): item is string => !!item);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function asQuotaSnapshot(value: unknown): OauthQuotaSnapshot | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as OauthQuotaSnapshot;
}

function asModelDiscoveryStatus(value: unknown): OauthModelDiscoveryStatus | undefined {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'healthy') return 'healthy';
  if (normalized === 'abnormal') return 'abnormal';
  return undefined;
}

export function getOauthInfoFromExtraConfig(extraConfig?: string | null): OauthInfo | null {
  const parsed = parseExtraConfig(extraConfig).oauth;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const provider = asTrimmedString(parsed.provider);
  if (!provider) return null;
  const accountKey = asTrimmedString(parsed.accountKey) || asTrimmedString(parsed.accountId);
  return {
    provider,
    accountId: asTrimmedString(parsed.accountId) || accountKey,
    accountKey,
    email: asTrimmedString(parsed.email),
    planType: asTrimmedString(parsed.planType),
    projectId: asTrimmedString(parsed.projectId),
    tokenExpiresAt: asPositiveInteger(parsed.tokenExpiresAt),
    refreshToken: asTrimmedString(parsed.refreshToken),
    idToken: asTrimmedString(parsed.idToken),
    providerData: asRecord(parsed.providerData),
    quota: asQuotaSnapshot(parsed.quota),
    modelDiscoveryStatus: asModelDiscoveryStatus(parsed.modelDiscoveryStatus),
    lastModelSyncAt: asIsoDateTime(parsed.lastModelSyncAt),
    lastModelSyncError: asTrimmedString(parsed.lastModelSyncError),
    lastDiscoveredModels: asStringArray(parsed.lastDiscoveredModels),
  };
}

export function buildOauthInfo(
  extraConfig?: string | null,
  patch: Partial<OauthInfo> = {},
): OauthInfo {
  const provider = patch.provider || getOauthInfoFromExtraConfig(extraConfig)?.provider;
  if (!provider) {
    throw new Error('oauth provider is required');
  }
  const current = getOauthInfoFromExtraConfig(extraConfig);
  const next: OauthInfo = {
    provider,
    ...(current || {}),
    ...patch,
  };
  if (!next.accountKey && next.accountId) {
    next.accountKey = next.accountId;
  }
  if (!next.accountId && next.accountKey) {
    next.accountId = next.accountKey;
  }
  return next;
}

export function isOauthProvider(
  account: Pick<typeof schema.accounts.$inferSelect, 'extraConfig'> | string | null | undefined,
  provider?: string,
): boolean {
  const extraConfig = typeof account === 'string' || account == null
    ? account
    : account.extraConfig;
  const oauth = getOauthInfoFromExtraConfig(extraConfig);
  if (!oauth) return false;
  if (!provider) return true;
  return oauth.provider === provider;
}
