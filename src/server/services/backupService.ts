import { asc } from 'drizzle-orm';
import cron from 'node-cron';
import { db, schema } from '../db/index.js';
import { upsertSetting } from '../db/upsertSetting.js';
import { mergeAccountExtraConfig } from './accountExtraConfig.js';
import { getOauthInfoFromExtraConfig } from './oauth/oauthAccount.js';

const BACKUP_VERSION = '2.0';

export type BackupExportType = 'all' | 'accounts' | 'preferences';

type SiteRow = typeof schema.sites.$inferSelect;
type AccountRow = typeof schema.accounts.$inferSelect;
type AccountTokenRow = typeof schema.accountTokens.$inferSelect;
type TokenRouteRow = typeof schema.tokenRoutes.$inferSelect;
type RouteChannelRow = typeof schema.routeChannels.$inferSelect;
type RouteGroupSourceRow = typeof schema.routeGroupSources.$inferSelect;

interface AccountsBackupSection {
  sites: SiteRow[];
  accounts: AccountRow[];
  accountTokens: AccountTokenRow[];
  tokenRoutes: TokenRouteRow[];
  routeChannels: RouteChannelRow[];
  routeGroupSources: RouteGroupSourceRow[];
}

interface PreferencesBackupSection {
  settings: Array<{ key: string; value: unknown }>;
}

interface BackupFullV2 {
  version: string;
  timestamp: number;
  accounts: AccountsBackupSection;
  preferences: PreferencesBackupSection;
}

interface BackupAccountsPartialV2 {
  version: string;
  timestamp: number;
  type: 'accounts';
  accounts: AccountsBackupSection;
}

interface BackupPreferencesPartialV2 {
  version: string;
  timestamp: number;
  type: 'preferences';
  preferences: PreferencesBackupSection;
}

type BackupV2 = BackupFullV2 | BackupAccountsPartialV2 | BackupPreferencesPartialV2;

type RawBackupData = Record<string, unknown>;

interface BackupImportResult {
  allImported: boolean;
  sections: {
    accounts: boolean;
    preferences: boolean;
  };
  appliedSettings: Array<{ key: string; value: unknown }>;
  summary?: {
    importedSites: number;
    importedAccounts: number;
    importedProfiles: number;
    importedApiKeyConnections: number;
    skippedAccounts: number;
    ignoredSections: string[];
  };
  warnings?: string[];
}

const EXCLUDED_SETTING_KEYS = new Set<string>([
  // Keep current admin login credential unchanged to avoid accidental lock-out.
  'auth_token',
]);

const DIRECT_API_PLATFORMS = new Set([
  'openai',
  'claude',
  'gemini',
  'cliproxyapi',
  'codex',
  'gemini-cli',
  'antigravity',
]);

const IMPORT_PLATFORM_ALIASES: Record<string, string> = {
  anyrouter: 'anyrouter',
  'wong-gongyi': 'new-api',
  'vo-api': 'new-api',
  'super-api': 'new-api',
  'rix-api': 'new-api',
  'neo-api': 'new-api',
  newapi: 'new-api',
  'new api': 'new-api',
  'new-api': 'new-api',
  oneapi: 'one-api',
  'one api': 'one-api',
  'one-api': 'one-api',
  onehub: 'one-hub',
  'one-hub': 'one-hub',
  donehub: 'done-hub',
  'done-hub': 'done-hub',
  veloera: 'veloera',
  sub2api: 'sub2api',
  openai: 'openai',
  anthropic: 'claude',
  claude: 'claude',
  google: 'gemini',
  gemini: 'gemini',
  cliproxyapi: 'cliproxyapi',
  cpa: 'cliproxyapi',
  'cli-proxy-api': 'cliproxyapi',
  codex: 'codex',
  'gemini-cli': 'gemini-cli',
  antigravity: 'antigravity',
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asString(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.trim();
}

function asBoolean(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') return value;
  return fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function toIsoString(value: unknown): string {
  if (typeof value === 'string' && value.trim()) {
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  }
  return new Date().toISOString();
}

function normalizeLegacyQuota(raw: unknown): number {
  const value = asNumber(raw, 0);
  if (!Number.isFinite(value) || value <= 0) return 0;
  // ref-all-api-hub stores quota in raw units for NewAPI-like sites.
  // Convert obvious raw values to display currency units.
  if (value >= 10_000) return value / 500_000;
  return value;
}

function resolveImportedOauthColumns(row: Pick<AccountRow, 'oauthProvider' | 'oauthAccountKey' | 'oauthProjectId' | 'extraConfig'>) {
  const oauth = getOauthInfoFromExtraConfig(row.extraConfig);
  const oauthProvider = row.oauthProvider || oauth?.provider || null;
  const oauthAccountKey = row.oauthAccountKey || oauth?.accountKey || oauth?.accountId || null;
  const oauthProjectId = row.oauthProjectId || oauth?.projectId || null;
  return {
    oauthProvider,
    oauthAccountKey,
    oauthProjectId,
  };
}

function normalizeLegacyPlatform(raw: string): string {
  const value = raw.trim().toLowerCase();
  if (!value) return 'new-api';

  const supported = new Set([
    'new-api',
    'one-api',
    'anyrouter',
    'one-hub',
    'done-hub',
    'sub2api',
    'veloera',
  ]);
  if (supported.has(value)) return value;

  if (value.includes('wong')) return 'new-api';
  if (value.includes('anyrouter')) return 'anyrouter';
  if (value.includes('done')) return 'done-hub';

  return 'new-api';
}

function normalizeOriginUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  try {
    return new URL(trimmed).origin;
  } catch {
    return trimmed.replace(/\/+$/, '');
  }
}

function detectLocalPlatformByUrlHint(url: string): string | undefined {
  const normalized = url.trim().toLowerCase();
  if (!normalized) return undefined;

  if (normalized.includes('api.openai.com')) return 'openai';
  if (normalized.includes('chatgpt.com/backend-api/codex')) return 'codex';
  if (normalized.includes('api.anthropic.com') || normalized.includes('anthropic.com/v1')) return 'claude';
  if (
    normalized.includes('generativelanguage.googleapis.com')
    || normalized.includes('googleapis.com/v1beta/openai')
    || normalized.includes('gemini.google.com')
  ) {
    return 'gemini';
  }
  if (normalized.includes('cloudcode-pa.googleapis.com')) return 'gemini-cli';
  if (normalized.includes('anyrouter')) return 'anyrouter';
  if (normalized.includes('donehub') || normalized.includes('done-hub')) return 'done-hub';
  if (normalized.includes('onehub') || normalized.includes('one-hub')) return 'one-hub';
  if (normalized.includes('veloera')) return 'veloera';
  if (normalized.includes('sub2api')) return 'sub2api';
  if (normalized.includes('127.0.0.1:8317') || normalized.includes('localhost:8317')) return 'cliproxyapi';

  return undefined;
}

function resolveImportedPlatform(rawPlatform: unknown, rawUrl: string): string {
  const normalizedPlatform = typeof rawPlatform === 'string'
    ? IMPORT_PLATFORM_ALIASES[rawPlatform.trim().toLowerCase()]
    : undefined;
  if (normalizedPlatform) return normalizedPlatform;

  const urlHint = detectLocalPlatformByUrlHint(rawUrl);
  if (urlHint) return urlHint;

  return normalizeLegacyPlatform(asString(rawPlatform));
}

function resolveImportedProfilePlatform(apiType: unknown, baseUrl: string): string {
  const normalizedType = asString(apiType).toLowerCase();
  if (normalizedType === 'openai') return 'openai';
  if (normalizedType === 'anthropic') return 'claude';
  if (normalizedType === 'google') return 'gemini';
  if (normalizedType === 'openai-compatible') {
    return detectLocalPlatformByUrlHint(baseUrl) || 'openai';
  }
  return detectLocalPlatformByUrlHint(baseUrl) || 'openai';
}

function pushDefaultImportedToken(
  rows: AccountTokenRow[],
  nextId: () => number,
  accountId: number,
  token: string | null,
  createdAt: string,
  updatedAt: string,
) {
  if (!token) return;
  rows.push({
    id: nextId(),
    accountId,
    name: 'default',
    token,
    tokenGroup: 'default',
    valueStatus: 'ready',
    source: 'legacy',
    enabled: true,
    isDefault: true,
    createdAt,
    updatedAt,
  });
}

function buildAllApiHubV2AccountsSection(data: RawBackupData): {
  section: AccountsBackupSection;
  summary: NonNullable<BackupImportResult['summary']>;
  warnings: string[];
} | null {
  const accountsContainer = isRecord(data.accounts) ? data.accounts : null;
  if (!accountsContainer || !Array.isArray(accountsContainer.accounts)) return null;

  if (coerceAccountsSection(accountsContainer)) return null;

  const looksLikeLegacyAccountRow = accountsContainer.accounts.some((row) => (
    isRecord(row) && (
      Object.prototype.hasOwnProperty.call(row, 'site_url')
      || Object.prototype.hasOwnProperty.call(row, 'site_type')
      || Object.prototype.hasOwnProperty.call(row, 'account_info')
      || Object.prototype.hasOwnProperty.call(row, 'cookieAuth')
      || Object.prototype.hasOwnProperty.call(row, 'authType')
      || Object.prototype.hasOwnProperty.call(row, 'sub2apiAuth')
    )
  ));

  const looksLikeV2 =
    looksLikeLegacyAccountRow
    && (
      (typeof data.version === 'string' && data.version.startsWith('2'))
      || Object.prototype.hasOwnProperty.call(accountsContainer, 'last_updated')
      || Array.isArray(accountsContainer.bookmarks)
      || Array.isArray(accountsContainer.pinnedAccountIds)
      || Array.isArray(accountsContainer.orderedAccountIds)
      || (isRecord(data.apiCredentialProfiles) && Array.isArray(data.apiCredentialProfiles.profiles))
    );

  if (!looksLikeV2) return null;

  const section: AccountsBackupSection = {
    sites: [],
    accounts: [],
    accountTokens: [],
    tokenRoutes: [],
    routeChannels: [],
    routeGroupSources: [],
  };
  const siteIdByKey = new Map<string, number>();
  let nextSiteId = 1;
  let nextAccountId = 1;
  let nextTokenId = 1;
  const warnings: string[] = [];
  const ignoredSections: string[] = [];
  let importedAccounts = 0;
  let importedProfiles = 0;
  let importedApiKeyConnections = 0;
  let skippedAccounts = 0;

  const nextToken = () => nextTokenId++;
  const ensureSite = (input: {
    platform: string;
    url: string;
    name?: string;
    createdAt: string;
    updatedAt: string;
  }) => {
    const normalizedUrl = normalizeOriginUrl(input.url);
    if (!normalizedUrl) return null;
    const key = `${input.platform}::${normalizedUrl}`;
    const existingId = siteIdByKey.get(key);
    if (existingId) return existingId;

    const siteId = nextSiteId++;
    siteIdByKey.set(key, siteId);
    section.sites.push({
      id: siteId,
      name: asString(input.name) || normalizedUrl,
      url: normalizedUrl,
      externalCheckinUrl: null,
      platform: input.platform,
      proxyUrl: null,
      useSystemProxy: false,
      customHeaders: null,
      status: 'active',
      isPinned: false,
      sortOrder: section.sites.length,
      globalWeight: 1,
      apiKey: null,
      createdAt: input.createdAt,
      updatedAt: input.updatedAt,
    });
    return siteId;
  };

  const addIgnoredSection = (name: string, active: boolean) => {
    if (active && !ignoredSections.includes(name)) ignoredSections.push(name);
  };

  addIgnoredSection('accounts.bookmarks', Array.isArray(accountsContainer.bookmarks) && accountsContainer.bookmarks.length > 0);
  addIgnoredSection('channelConfigs', isRecord(data.channelConfigs));
  addIgnoredSection('tagStore', isRecord(data.tagStore));

  for (const row of accountsContainer.accounts) {
    if (!isRecord(row)) continue;

    const createdAt = toIsoString(row.created_at);
    const updatedAt = toIsoString(row.updated_at);
    const siteUrl = normalizeOriginUrl(asString(row.site_url));
    const siteName = asString(row.site_name) || siteUrl;
    const platform = resolveImportedPlatform(row.site_type, siteUrl);
    const authType = asString(row.authType).toLowerCase();
    const accountInfo = isRecord(row.account_info) ? row.account_info : {};
    const cookieAuth = isRecord(row.cookieAuth) ? row.cookieAuth : {};
    const sub2apiAuth = isRecord(row.sub2apiAuth) ? row.sub2apiAuth : {};
    const rawAccountId = asString(row.id) || asString(row.username) || siteName || `account-${nextAccountId}`;
    const username = asString(accountInfo.username) || asString(row.username) || rawAccountId;
    const platformUserId = asNumber(accountInfo.id, 0);
    const checkin = isRecord(row.checkIn) ? row.checkIn : {};
    const accessTokenCandidate = asString(accountInfo.access_token) || asString(row.access_token);
    const cookieSession = asString(cookieAuth.sessionCookie);
    const isDirectApiPlatform = DIRECT_API_PLATFORMS.has(platform);

    let accessToken = '';
    let apiToken: string | null = null;
    let credentialMode: 'session' | 'apikey' | null = null;

    if (authType === 'cookie') {
      if (!cookieSession) {
        skippedAccounts += 1;
        warnings.push(`跳过 ALL-API-Hub 账号 ${rawAccountId}：cookieAuth.sessionCookie 缺失`);
        continue;
      }
      accessToken = cookieSession;
      credentialMode = 'session';
    } else if (authType === 'access_token') {
      if (!accessTokenCandidate) {
        skippedAccounts += 1;
        warnings.push(`跳过 ALL-API-Hub 账号 ${rawAccountId}：access_token 缺失`);
        continue;
      }
      if (isDirectApiPlatform) {
        accessToken = '';
        apiToken = accessTokenCandidate;
        credentialMode = 'apikey';
      } else {
        accessToken = accessTokenCandidate;
        credentialMode = 'session';
      }
    } else {
      skippedAccounts += 1;
      warnings.push(`跳过 ALL-API-Hub 账号 ${rawAccountId}：authType=${authType || 'unknown'} 不支持离线迁移`);
      continue;
    }

    const siteId = ensureSite({
      platform,
      url: siteUrl,
      name: siteName,
      createdAt,
      updatedAt,
    });
    if (!siteId) {
      skippedAccounts += 1;
      warnings.push(`跳过 ALL-API-Hub 账号 ${rawAccountId}：site_url 无效`);
      continue;
    }

    const importedBalance = normalizeLegacyQuota(accountInfo.quota);
    const importedUsed = normalizeLegacyQuota(accountInfo.today_quota_consumption);
    const importedQuota = importedBalance + importedUsed;
    const extraConfigPatch: Record<string, unknown> = {
      credentialMode,
      source: 'all-api-hub',
    };
    if (platformUserId > 0) {
      extraConfigPatch.platformUserId = platformUserId;
    }
    const refreshToken = asString(sub2apiAuth.refreshToken);
    const tokenExpiresAt = asNumber(sub2apiAuth.tokenExpiresAt, 0);
    if (refreshToken) {
      extraConfigPatch.sub2apiAuth = tokenExpiresAt > 0
        ? { refreshToken, tokenExpiresAt }
        : { refreshToken };
    }

    const accountId = nextAccountId++;
    section.accounts.push({
      id: accountId,
      siteId,
      username,
      accessToken,
      apiToken,
      oauthProvider: null,
      oauthAccountKey: null,
      oauthProjectId: null,
      balance: importedBalance,
      balanceUsed: importedUsed,
      quota: importedQuota > 0 ? importedQuota : importedBalance,
      unitCost: null,
      valueScore: 0,
      status: asBoolean(row.disabled, false) ? 'disabled' : 'active',
      isPinned: false,
      sortOrder: section.accounts.length,
      checkinEnabled: credentialMode === 'session' ? asBoolean(checkin.autoCheckInEnabled, true) : false,
      lastCheckinAt: null,
      lastBalanceRefresh: null,
      extraConfig: mergeAccountExtraConfig(undefined, extraConfigPatch),
      createdAt,
      updatedAt,
    });
    pushDefaultImportedToken(section.accountTokens, nextToken, accountId, apiToken, createdAt, updatedAt);
    if (credentialMode === 'apikey') importedApiKeyConnections += 1;
    importedAccounts += 1;
  }

  const profilesContainer = isRecord(data.apiCredentialProfiles) ? data.apiCredentialProfiles : null;
  const profiles = Array.isArray(profilesContainer?.profiles) ? profilesContainer.profiles : [];
  for (const profile of profiles) {
    if (!isRecord(profile)) continue;

    const baseUrl = normalizeOriginUrl(asString(profile.baseUrl));
    const apiKey = asString(profile.apiKey);
    if (!baseUrl || !apiKey) {
      warnings.push(`跳过 ALL-API-Hub API 凭据 ${asString(profile.id) || asString(profile.name) || 'unknown'}：baseUrl 或 apiKey 缺失`);
      continue;
    }

    const createdAt = toIsoString(profile.createdAt);
    const updatedAt = toIsoString(profile.updatedAt);
    const platform = resolveImportedProfilePlatform(profile.apiType, asString(profile.baseUrl));
    const siteId = ensureSite({
      platform,
      url: baseUrl,
      name: baseUrl,
      createdAt,
      updatedAt,
    });
    if (!siteId) continue;

    const accountId = nextAccountId++;
    section.accounts.push({
      id: accountId,
      siteId,
      username: asString(profile.name) || asString(profile.id) || baseUrl,
      accessToken: '',
      apiToken: apiKey,
      oauthProvider: null,
      oauthAccountKey: null,
      oauthProjectId: null,
      balance: 0,
      balanceUsed: 0,
      quota: 0,
      unitCost: null,
      valueScore: 0,
      status: 'active',
      isPinned: false,
      sortOrder: section.accounts.length,
      checkinEnabled: false,
      lastCheckinAt: null,
      lastBalanceRefresh: null,
      extraConfig: mergeAccountExtraConfig(undefined, {
        credentialMode: 'apikey',
        source: 'all-api-hub-profile',
        importedProfileId: asString(profile.id) || undefined,
      }),
      createdAt,
      updatedAt,
    });
    pushDefaultImportedToken(section.accountTokens, nextToken, accountId, apiKey, createdAt, updatedAt);
    importedApiKeyConnections += 1;
    importedProfiles += 1;
  }

  return {
    section,
    summary: {
      importedSites: section.sites.length,
      importedAccounts,
      importedProfiles,
      importedApiKeyConnections,
      skippedAccounts,
      ignoredSections,
    },
    warnings,
  };
}

function buildAccountsSectionFromRefBackup(data: RawBackupData): AccountsBackupSection | null {
  const accountsContainer = isRecord(data.accounts) ? data.accounts : null;
  const rows = Array.isArray(accountsContainer?.accounts) ? accountsContainer.accounts : null;
  if (!rows) return null;

  const sites: SiteRow[] = [];
  const accounts: AccountRow[] = [];
  const accountTokens: AccountTokenRow[] = [];
  const tokenRoutes: TokenRouteRow[] = [];
  const routeChannels: RouteChannelRow[] = [];

  const siteIdByKey = new Map<string, number>();
  let nextSiteId = 1;
  let nextAccountId = 1;
  let nextTokenId = 1;

  for (const item of rows) {
    if (!isRecord(item)) continue;

    const siteUrl = asString(item.site_url);
    if (!siteUrl) continue;

    const platform = normalizeLegacyPlatform(asString(item.site_type));
    const siteName = asString(item.site_name) || siteUrl;
    const siteKey = `${platform}::${siteUrl}`;

    let siteId = siteIdByKey.get(siteKey) || 0;
    if (!siteId) {
      siteId = nextSiteId++;
      siteIdByKey.set(siteKey, siteId);
      sites.push({
        id: siteId,
        name: siteName,
        url: siteUrl,
        externalCheckinUrl: null,
        platform,
        proxyUrl: null,
        useSystemProxy: false,
        customHeaders: null,
        status: 'active',
        isPinned: false,
        sortOrder: sites.length,
        globalWeight: 1,
        apiKey: null,
        createdAt: toIsoString(item.created_at),
        updatedAt: toIsoString(item.updated_at),
      });
    }

    const accountInfo = isRecord(item.account_info) ? item.account_info : {};
    const cookieAuth = isRecord(item.cookieAuth) ? item.cookieAuth : {};
    const authType = asString(item.authType);

    const accountAccessToken =
      asString(accountInfo.access_token)
      || asString(cookieAuth.sessionCookie)
      || asString((item as Record<string, unknown>).access_token);
    if (!accountAccessToken) continue;

    const platformUserId = asNumber(accountInfo.id, 0);
    const username = asString(accountInfo.username)
      || asString(item.username)
      || (platformUserId > 0 ? `user-${platformUserId}` : `account-${nextAccountId}`);

    let apiToken: string | null = null;
    if (authType === 'api_key') {
      apiToken = accountAccessToken;
    }

    const createdAt = toIsoString(item.created_at);
    const updatedAt = toIsoString(item.updated_at);
    const checkin = isRecord(item.checkIn) ? item.checkIn : {};
    const extraConfigPayload = {
      platformUserId: platformUserId > 0 ? platformUserId : undefined,
      authType: authType || undefined,
      source: 'ref-all-api-hub',
    };

    const accountId = nextAccountId++;
    const importedBalance = normalizeLegacyQuota(accountInfo.quota);
    const importedUsed = normalizeLegacyQuota(accountInfo.today_quota_consumption);
    const importedQuota = importedBalance + importedUsed;

    accounts.push({
      id: accountId,
      siteId,
      username,
      accessToken: accountAccessToken,
      apiToken,
      oauthProvider: null,
      oauthAccountKey: null,
      oauthProjectId: null,
      balance: importedBalance,
      balanceUsed: importedUsed,
      quota: importedQuota > 0 ? importedQuota : importedBalance,
      unitCost: null,
      valueScore: 0,
      status: asBoolean(item.disabled, false) ? 'disabled' : 'active',
      isPinned: false,
      sortOrder: accounts.length,
      checkinEnabled: asBoolean(checkin.autoCheckInEnabled, true),
      lastCheckinAt: null,
      lastBalanceRefresh: null,
      extraConfig: JSON.stringify(extraConfigPayload),
      createdAt,
      updatedAt,
    });

    if (apiToken) {
      accountTokens.push({
        id: nextTokenId++,
        accountId,
        name: 'default',
        token: apiToken,
        tokenGroup: 'default',
        valueStatus: 'ready',
        source: 'legacy',
        enabled: true,
        isDefault: true,
        createdAt,
        updatedAt,
      });
    }
  }

  return {
    sites,
    accounts,
    accountTokens,
    tokenRoutes,
    routeChannels,
    routeGroupSources: [],
  };
}

function buildPreferencesSectionFromRefBackup(data: RawBackupData): PreferencesBackupSection | null {
  const settings: Array<{ key: string; value: unknown }> = [];

  if (isRecord(data.preferences)) {
    settings.push({ key: 'legacy_preferences_ref_v2', value: data.preferences });
  }
  if (isRecord(data.channelConfigs)) {
    settings.push({ key: 'legacy_channel_configs_ref_v2', value: data.channelConfigs });
  }
  if (isRecord(data.tagStore)) {
    settings.push({ key: 'legacy_tag_store_ref_v2', value: data.tagStore });
  }

  if (settings.length === 0) return null;
  return { settings };
}

function parseSettingValue(raw: string | null): unknown {
  if (raw === null || raw === undefined) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function stringifySettingValue(value: unknown): string {
  return JSON.stringify(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isSettingValueAcceptable(key: string, value: unknown): boolean {
  if (key === 'checkin_cron' || key === 'balance_refresh_cron' || key === 'log_cleanup_cron') {
    return typeof value === 'string' && cron.validate(value);
  }

  if (key === 'log_cleanup_usage_logs_enabled' || key === 'log_cleanup_program_logs_enabled') {
    return typeof value === 'boolean';
  }

  if (key === 'log_cleanup_retention_days') {
    return isFiniteNumber(value) && value >= 1;
  }

  if (key === 'proxy_token') {
    return typeof value === 'string'
      && value.trim().length >= 6
      && value.trim().startsWith('sk-');
  }

  if (key === 'smtp_port') {
    return isFiniteNumber(value) && value > 0;
  }

  if (key === 'routing_weights') {
    if (!isRecord(value)) return false;
    const keys = ['baseWeightFactor', 'valueScoreFactor', 'costWeight', 'balanceWeight', 'usageWeight'] as const;
    return keys.every((weightKey) => value[weightKey] === undefined || isFiniteNumber(value[weightKey]));
  }

  return true;
}

async function exportAccountsSection(): Promise<AccountsBackupSection> {
  const sites = await db.select().from(schema.sites).orderBy(asc(schema.sites.id)).all();
  const accounts = await db.select().from(schema.accounts).orderBy(asc(schema.accounts.id)).all();
  const accountTokens = await db.select().from(schema.accountTokens).orderBy(asc(schema.accountTokens.id)).all();
  const tokenRoutes = await db.select().from(schema.tokenRoutes).orderBy(asc(schema.tokenRoutes.id)).all();
  const routeChannels = await db.select().from(schema.routeChannels).orderBy(asc(schema.routeChannels.id)).all();
  const routeGroupSources = await db.select().from(schema.routeGroupSources).orderBy(asc(schema.routeGroupSources.id)).all();

  return {
    sites,
    accounts,
    accountTokens,
    tokenRoutes,
    routeChannels,
    routeGroupSources,
  };
}

async function exportPreferencesSection(): Promise<PreferencesBackupSection> {
  const settings = (await db.select().from(schema.settings).all())
    .filter((row) => !EXCLUDED_SETTING_KEYS.has(row.key))
    .map((row) => ({
      key: row.key,
      value: parseSettingValue(row.value),
    }));

  return { settings };
}

export async function exportBackup(type: BackupExportType): Promise<BackupV2> {
  const now = Date.now();
  if (type === 'accounts') {
    return {
      version: BACKUP_VERSION,
      timestamp: now,
      type: 'accounts',
      accounts: await exportAccountsSection(),
    };
  }

  if (type === 'preferences') {
    return {
      version: BACKUP_VERSION,
      timestamp: now,
      type: 'preferences',
      preferences: await exportPreferencesSection(),
    };
  }

  return {
    version: BACKUP_VERSION,
    timestamp: now,
    accounts: await exportAccountsSection(),
    preferences: await exportPreferencesSection(),
  };
}

function coerceAccountsSection(input: unknown): AccountsBackupSection | null {
  if (!isRecord(input)) return null;

  const sites = Array.isArray(input.sites) ? input.sites as SiteRow[] : null;
  const accounts = Array.isArray(input.accounts) ? input.accounts as AccountRow[] : null;
  const accountTokens = Array.isArray(input.accountTokens) ? input.accountTokens as AccountTokenRow[] : null;
  const tokenRoutes = Array.isArray(input.tokenRoutes) ? input.tokenRoutes as TokenRouteRow[] : null;
  const routeChannels = Array.isArray(input.routeChannels) ? input.routeChannels as RouteChannelRow[] : null;
  const routeGroupSources = Array.isArray(input.routeGroupSources)
    ? input.routeGroupSources as RouteGroupSourceRow[]
    : [];

  if (!sites || !accounts || !accountTokens || !tokenRoutes || !routeChannels) return null;

  return {
    sites,
    accounts,
    accountTokens,
    tokenRoutes,
    routeChannels,
    routeGroupSources,
  };
}

function coercePreferencesSection(input: unknown): PreferencesBackupSection | null {
  if (!isRecord(input)) return null;
  const settingsRaw = input.settings;
  if (!Array.isArray(settingsRaw)) return null;

  const settings = settingsRaw
    .map((row) => {
      if (!isRecord(row)) return null;
      const key = typeof row.key === 'string' ? row.key.trim() : '';
      if (!key || EXCLUDED_SETTING_KEYS.has(key)) return null;
      return { key, value: row.value };
    })
    .filter((row): row is { key: string; value: unknown } => !!row);

  return { settings };
}

function detectAccountsSection(data: RawBackupData): AccountsBackupSection | null {
  const rootMatch = coerceAccountsSection(data);
  if (rootMatch) return rootMatch;

  if ('accounts' in data) {
    const nested = coerceAccountsSection(data.accounts);
    if (nested) return nested;
  }

  if (isRecord(data.data) && 'accounts' in data.data) {
    const legacyNested = coerceAccountsSection((data.data as Record<string, unknown>).accounts);
    if (legacyNested) return legacyNested;
  }

  const allApiHubV2 = buildAllApiHubV2AccountsSection(data);
  if (allApiHubV2) return allApiHubV2.section;

  const refFormat = buildAccountsSectionFromRefBackup(data);
  if (refFormat) return refFormat;

  return null;
}

function detectPreferencesSection(data: RawBackupData): PreferencesBackupSection | null {
  const rootMatch = coercePreferencesSection(data);
  if (rootMatch) return rootMatch;

  if ('preferences' in data) {
    const nested = coercePreferencesSection(data.preferences);
    if (nested) return nested;
  }

  if (isRecord(data.data) && 'preferences' in data.data) {
    const legacyNested = coercePreferencesSection((data.data as Record<string, unknown>).preferences);
    if (legacyNested) return legacyNested;
  }

  const refFormat = buildPreferencesSectionFromRefBackup(data);
  if (refFormat) return refFormat;

  return null;
}

function detectImportMetadata(data: RawBackupData): {
  summary?: BackupImportResult['summary'];
  warnings?: string[];
} {
  const allApiHubV2 = buildAllApiHubV2AccountsSection(data);
  if (!allApiHubV2) return {};
  return {
    summary: allApiHubV2.summary,
    warnings: allApiHubV2.warnings.length > 0 ? allApiHubV2.warnings : undefined,
  };
}

async function importAccountsSection(section: AccountsBackupSection): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.delete(schema.routeChannels).run();
    await tx.delete(schema.routeGroupSources).run();
    await tx.delete(schema.tokenRoutes).run();
    await tx.delete(schema.tokenModelAvailability).run();
    await tx.delete(schema.modelAvailability).run();
    await tx.delete(schema.proxyLogs).run();
    await tx.delete(schema.checkinLogs).run();
    await tx.delete(schema.accountTokens).run();
    await tx.delete(schema.accounts).run();
    await tx.delete(schema.sites).run();

    for (const row of section.sites) {
      await tx.insert(schema.sites).values({
        id: row.id,
        name: row.name,
        url: row.url,
        externalCheckinUrl: row.externalCheckinUrl ?? null,
        platform: row.platform,
        proxyUrl: row.proxyUrl ?? null,
        useSystemProxy: row.useSystemProxy ?? false,
        customHeaders: row.customHeaders ?? null,
        status: row.status || 'active',
        isPinned: row.isPinned ?? false,
        sortOrder: row.sortOrder ?? 0,
        globalWeight: row.globalWeight ?? 1,
        apiKey: row.apiKey,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      }).run();
    }

    for (const row of section.accounts) {
      const oauthColumns = resolveImportedOauthColumns(row);
      await tx.insert(schema.accounts).values({
        id: row.id,
        siteId: row.siteId,
        username: row.username,
        accessToken: row.accessToken,
        apiToken: row.apiToken,
        oauthProvider: oauthColumns.oauthProvider,
        oauthAccountKey: oauthColumns.oauthAccountKey,
        oauthProjectId: oauthColumns.oauthProjectId,
        balance: row.balance,
        balanceUsed: row.balanceUsed,
        quota: row.quota,
        unitCost: row.unitCost,
        valueScore: row.valueScore,
        status: row.status,
        isPinned: row.isPinned ?? false,
        sortOrder: row.sortOrder ?? 0,
        checkinEnabled: row.checkinEnabled,
        lastCheckinAt: row.lastCheckinAt,
        lastBalanceRefresh: row.lastBalanceRefresh,
        extraConfig: row.extraConfig,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      }).run();
    }

    for (const row of section.accountTokens) {
      await tx.insert(schema.accountTokens).values({
        id: row.id,
        accountId: row.accountId,
        name: row.name,
        token: row.token,
        tokenGroup: row.tokenGroup ?? null,
        valueStatus: row.valueStatus ?? 'ready',
        source: row.source,
        enabled: row.enabled,
        isDefault: row.isDefault,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      }).run();
    }

    for (const row of section.tokenRoutes) {
      await tx.insert(schema.tokenRoutes).values({
        id: row.id,
        modelPattern: row.modelPattern,
        displayName: row.displayName ?? null,
        displayIcon: row.displayIcon ?? null,
        modelMapping: row.modelMapping,
        routeMode: row.routeMode ?? 'pattern',
        decisionSnapshot: row.decisionSnapshot ?? null,
        decisionRefreshedAt: row.decisionRefreshedAt ?? null,
        routingStrategy: row.routingStrategy ?? 'weighted',
        enabled: row.enabled,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      }).run();
    }

    for (const row of section.routeGroupSources || []) {
      await tx.insert(schema.routeGroupSources).values({
        id: row.id,
        groupRouteId: row.groupRouteId,
        sourceRouteId: row.sourceRouteId,
      }).run();
    }

    for (const row of section.routeChannels) {
      await tx.insert(schema.routeChannels).values({
        id: row.id,
        routeId: row.routeId,
        accountId: row.accountId,
        tokenId: row.tokenId,
        sourceModel: row.sourceModel ?? null,
        priority: row.priority,
        weight: row.weight,
        enabled: row.enabled,
        manualOverride: row.manualOverride,
        successCount: row.successCount,
        failCount: row.failCount,
        totalLatencyMs: row.totalLatencyMs,
        totalCost: row.totalCost,
        lastUsedAt: row.lastUsedAt,
        lastFailAt: row.lastFailAt,
        cooldownUntil: row.cooldownUntil,
      }).run();
    }
  });
}

async function importPreferencesSection(section: PreferencesBackupSection): Promise<Array<{ key: string; value: unknown }>> {
  const applied: Array<{ key: string; value: unknown }> = [];

  await db.transaction(async (tx) => {
    for (const row of section.settings) {
      if (!isSettingValueAcceptable(row.key, row.value)) continue;

      await upsertSetting(row.key, row.value, tx);
      applied.push({ key: row.key, value: row.value });
    }
  });

  return applied;
}

export async function importBackup(data: RawBackupData): Promise<BackupImportResult> {
  if (!isRecord(data)) {
    throw new Error('导入数据格式错误：必须为 JSON 对象');
  }

  if (!('timestamp' in data) || data.timestamp === null || data.timestamp === undefined) {
    throw new Error('导入数据格式错误：缺少 timestamp');
  }

  const accountsSection = detectAccountsSection(data);
  const preferencesSection = detectPreferencesSection(data);
  const importMetadata = detectImportMetadata(data);

  const type = typeof data.type === 'string' ? data.type : '';
  const accountsRequested = type === 'accounts' || !!accountsSection;
  const preferencesRequested = type === 'preferences' || !!preferencesSection;

  if (!accountsRequested && !preferencesRequested) {
    throw new Error('导入数据中没有可识别的账号或设置数据');
  }

  let accountsImported = false;
  let preferencesImported = false;
  let appliedSettings: Array<{ key: string; value: unknown }> = [];

  if (accountsRequested) {
    if (!accountsSection) {
      throw new Error('导入数据格式错误：账号数据结构不正确');
    }
    await importAccountsSection(accountsSection);
    accountsImported = true;
  }

  if (preferencesRequested) {
    if (!preferencesSection) {
      throw new Error('导入数据格式错误：设置数据结构不正确');
    }
    appliedSettings = await importPreferencesSection(preferencesSection);
    preferencesImported = true;
  }

  return {
    allImported: (!accountsRequested || accountsImported) && (!preferencesRequested || preferencesImported),
    sections: {
      accounts: accountsImported,
      preferences: preferencesImported,
    },
    appliedSettings,
    summary: importMetadata.summary,
    warnings: importMetadata.warnings,
  };
}
