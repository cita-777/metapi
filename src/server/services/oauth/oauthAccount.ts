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

type ExtraConfigInput = string | Record<string, unknown> | null | undefined;

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

export type StoredOauthState = Omit<OauthInfo, 'provider' | 'accountId' | 'accountKey' | 'projectId'>;

type OauthIdentityCarrier = {
  extraConfig?: ExtraConfigInput;
  oauthProvider?: string | null;
  oauthAccountKey?: string | null;
  oauthProjectId?: string | null;
};

type StoredOauthIdentity = Pick<OauthInfo, 'provider' | 'accountId' | 'accountKey' | 'projectId'>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function parseExtraConfig(extraConfig?: ExtraConfigInput): ParsedExtraConfig {
  if (!extraConfig) return {};
  if (isRecord(extraConfig)) return extraConfig as ParsedExtraConfig;
  if (typeof extraConfig !== 'string') return {};
  try {
    const parsed = JSON.parse(extraConfig) as unknown;
    if (!isRecord(parsed)) return {};
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

function parseStoredOauthIdentity(extraConfig?: ExtraConfigInput): StoredOauthIdentity | null {
  const parsed = parseExtraConfig(extraConfig).oauth;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const accountKey = asTrimmedString(parsed.accountKey) || asTrimmedString(parsed.accountId);
  const provider = asTrimmedString(parsed.provider);
  if (!provider) return null;
  return {
    provider,
    accountId: asTrimmedString(parsed.accountId) || accountKey,
    accountKey,
    projectId: asTrimmedString(parsed.projectId),
  };
}

function parseStoredOauthRuntimeState(extraConfig?: ExtraConfigInput): Partial<OauthInfo> | null {
  const parsed = parseExtraConfig(extraConfig).oauth;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  return {
    email: asTrimmedString(parsed.email),
    planType: asTrimmedString(parsed.planType),
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

export function getOauthInfoFromExtraConfig(extraConfig?: ExtraConfigInput): OauthInfo | null {
  const identity = parseStoredOauthIdentity(extraConfig);
  const runtime = parseStoredOauthRuntimeState(extraConfig);
  const provider = identity?.provider;
  if (!provider) return null;
  return {
    provider,
    accountId: identity?.accountId || identity?.accountKey,
    accountKey: identity?.accountKey,
    projectId: identity?.projectId,
    email: runtime?.email,
    planType: runtime?.planType,
    tokenExpiresAt: runtime?.tokenExpiresAt,
    refreshToken: runtime?.refreshToken,
    idToken: runtime?.idToken,
    providerData: runtime?.providerData,
    quota: runtime?.quota,
    modelDiscoveryStatus: runtime?.modelDiscoveryStatus,
    lastModelSyncAt: runtime?.lastModelSyncAt,
    lastModelSyncError: runtime?.lastModelSyncError,
    lastDiscoveredModels: runtime?.lastDiscoveredModels,
  };
}

export function getOauthInfoFromAccount(account?: OauthIdentityCarrier | null): OauthInfo | null {
  if (!account) return null;
  const storedIdentity = parseStoredOauthIdentity(account.extraConfig);
  const storedRuntime = parseStoredOauthRuntimeState(account.extraConfig);
  const provider = asTrimmedString(account.oauthProvider) || storedIdentity?.provider;
  if (!provider) return null;
  const structuredAccountKey = asTrimmedString(account.oauthAccountKey);
  const accountKey = structuredAccountKey || storedIdentity?.accountKey || storedIdentity?.accountId;
  const accountId = storedIdentity?.accountId || structuredAccountKey || accountKey;
  const projectId = asTrimmedString(account.oauthProjectId) || storedIdentity?.projectId;
  return {
    ...(storedRuntime || {}),
    provider,
    accountId,
    accountKey,
    projectId,
  };
}

export function buildOauthIdentityBackfillPatch(
  account?: OauthIdentityCarrier | null,
): Partial<Pick<OauthIdentityCarrier, 'oauthProvider' | 'oauthAccountKey' | 'oauthProjectId'>> | null {
  if (!account) return null;
  const legacyIdentity = parseStoredOauthIdentity(account.extraConfig);
  if (!legacyIdentity?.provider) return null;

  const patch: Partial<Pick<OauthIdentityCarrier, 'oauthProvider' | 'oauthAccountKey' | 'oauthProjectId'>> = {};
  if (!asTrimmedString(account.oauthProvider)) {
    patch.oauthProvider = legacyIdentity.provider;
  }
  if (!asTrimmedString(account.oauthAccountKey) && (legacyIdentity.accountKey || legacyIdentity.accountId)) {
    patch.oauthAccountKey = legacyIdentity.accountKey || legacyIdentity.accountId;
  }
  if (!asTrimmedString(account.oauthProjectId) && legacyIdentity.projectId) {
    patch.oauthProjectId = legacyIdentity.projectId;
  }

  return Object.keys(patch).length > 0 ? patch : null;
}

export function buildOauthInfo(
  extraConfig?: ExtraConfigInput,
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

export function buildOauthInfoFromAccount(
  account?: OauthIdentityCarrier | null,
  patch: Partial<OauthInfo> = {},
): OauthInfo {
  const provider = patch.provider || getOauthInfoFromAccount(account)?.provider;
  if (!provider) {
    throw new Error('oauth provider is required');
  }
  const current = getOauthInfoFromAccount(account);
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

export function buildStoredOauthState(oauth: OauthInfo): StoredOauthState {
  const {
    provider: _provider,
    accountId: _accountId,
    accountKey: _accountKey,
    projectId: _projectId,
    ...stored
  } = oauth;
  return stored;
}

export function buildStoredOauthStateFromAccount(
  account?: OauthIdentityCarrier | null,
  patch: Partial<OauthInfo> = {},
): StoredOauthState {
  return buildStoredOauthState(buildOauthInfoFromAccount(account, patch));
}

export function isOauthProvider(
  account: OauthIdentityCarrier | string | null | undefined,
  provider?: string,
): boolean {
  const oauth = typeof account === 'string' || account == null
    ? getOauthInfoFromExtraConfig(account)
    : getOauthInfoFromAccount(account);
  if (!oauth) return false;
  if (!provider) return true;
  return oauth.provider === provider;
}
