import { and, eq } from 'drizzle-orm';
import { fetch } from 'undici';
import { db, schema } from '../db/index.js';
import { getAdapter } from './platforms/index.js';
import {
  ACCOUNT_TOKEN_VALUE_STATUS_READY,
  ensureDefaultTokenForAccount,
  getPreferredAccountToken,
  isMaskedTokenValue,
  isUsableAccountToken,
} from './accountTokenService.js';
import {
  getCredentialModeFromExtraConfig,
  mergeAccountExtraConfig,
  resolvePlatformUserId,
  supportsDirectAccountRoutingConnection,
} from './accountExtraConfig.js';
import { invalidateTokenRouterCache } from './tokenRouter.js';
import { setAccountRuntimeHealth } from './accountHealthService.js';
import { clearAllRouteDecisionSnapshots } from './routeDecisionSnapshotStore.js';
import { withSiteRecordProxyRequestInit } from './siteProxy.js';
import { buildCodexOauthInfo, getCodexOauthInfoFromExtraConfig, isCodexPlatform } from './oauth/codexAccount.js';

const API_TOKEN_DISCOVERY_TIMEOUT_MS = 8_000;
const MODEL_DISCOVERY_TIMEOUT_MS = 12_000;
const MODEL_REFRESH_BATCH_SIZE = 3;
const CODEX_MODELS_CLIENT_VERSION = '1.0.0';

type ModelRefreshErrorCode = 'timeout' | 'unauthorized' | 'empty_models' | 'unknown';
type ModelRefreshSkipCode = 'site_disabled' | 'adapter_or_status';

export type ModelRefreshAccountNotFoundResult = {
  accountId: number;
  refreshed: false;
  status: 'failed';
  errorCode: 'account_not_found';
  errorMessage: '账号不存在';
  modelCount: 0;
  modelsPreview: string[];
  reason: 'account_not_found';
};

export type ModelRefreshSkippedResult = {
  accountId: number;
  refreshed: false;
  status: 'skipped';
  errorCode: ModelRefreshSkipCode;
  errorMessage: string;
  modelCount: 0;
  modelsPreview: string[];
  reason: ModelRefreshSkipCode;
};

export type ModelRefreshFailureResult = {
  accountId: number;
  refreshed: true;
  status: 'failed';
  errorCode: ModelRefreshErrorCode;
  errorMessage: string;
  modelCount: 0;
  modelsPreview: string[];
  tokenScanned: number;
  discoveredByCredential: boolean;
  discoveredApiToken: boolean;
};

export type ModelRefreshSuccessResult = {
  accountId: number;
  refreshed: true;
  status: 'success';
  errorCode: null;
  errorMessage: '';
  modelCount: number;
  modelsPreview: string[];
  tokenScanned: number;
  discoveredByCredential: boolean;
  discoveredApiToken: boolean;
};

export type ModelRefreshResult =
  | ModelRefreshAccountNotFoundResult
  | ModelRefreshSkippedResult
  | ModelRefreshFailureResult
  | ModelRefreshSuccessResult;

function classifyModelDiscoveryError(message: string): ModelRefreshErrorCode {
  const lowered = message.toLowerCase();
  if (lowered.includes('timeout') || lowered.includes('timed out') || lowered.includes('请求超时')) return 'timeout';
  if (lowered.includes('http 401') || lowered.includes('http 403')
    || lowered.includes('unauthorized') || lowered.includes('invalid')
    || lowered.includes('无权') || lowered.includes('未提供令牌')) return 'unauthorized';
  return 'unknown';
}

function buildModelFailureMessage(code: ModelRefreshErrorCode, fallback?: string) {
  if (code === 'timeout') return '模型获取失败（请求超时）';
  if (code === 'unauthorized') return '模型获取失败，API Key 已无效';
  if (code === 'empty_models') return '模型获取失败：未获取到可用模型';
  return fallback || '模型获取失败';
}

function isSiteDisabled(status?: string | null): boolean {
  return (status || 'active') === 'disabled';
}

function isApiKeyConnection(account: typeof schema.accounts.$inferSelect): boolean {
  const explicit = getCredentialModeFromExtraConfig(account.extraConfig);
  if (explicit && explicit !== 'auto') return explicit === 'apikey';
  return !(account.accessToken || '').trim();
}

function normalizeModels(models: string[]): string[] {
  const normalizedModels: string[] = [];
  const seen = new Set<string>();

  for (const rawModel of models) {
    if (typeof rawModel !== 'string') continue;
    const modelName = rawModel.trim();
    if (!modelName) continue;

    // Keep app/database behavior stable across SQLite/MySQL by deduping with a
    // case-insensitive key after trimming whitespace.
    const dedupeKey = modelName.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    normalizedModels.push(modelName);
  }

  return normalizedModels;
}

function buildCodexModelsEndpoint(baseUrl: string): string {
  const normalized = (baseUrl || '').replace(/\/+$/, '');
  return `${normalized}/models?client_version=${encodeURIComponent(CODEX_MODELS_CLIENT_VERSION)}`;
}

function extractCodexModelIds(payload: unknown): string[] {
  const collection = (() => {
    if (Array.isArray(payload)) return payload;
    if (!payload || typeof payload !== 'object') return [];
    const record = payload as Record<string, unknown>;
    if (Array.isArray(record.models)) return record.models;
    if (Array.isArray(record.data)) return record.data;
    if (Array.isArray(record.items)) return record.items;
    return [];
  })();

  return collection.flatMap((item) => {
    if (typeof item === 'string') return [item];
    if (!item || typeof item !== 'object' || Array.isArray(item)) return [];
    const record = item as Record<string, unknown>;
    const id = typeof record.id === 'string'
      ? record.id
      : (typeof record.slug === 'string' ? record.slug : (typeof record.model === 'string' ? record.model : ''));
    return id ? [id] : [];
  });
}

async function updateCodexOauthModelDiscoveryState(input: {
  account: typeof schema.accounts.$inferSelect;
  checkedAt: string;
  status: 'healthy' | 'abnormal';
  lastModelSyncError?: string;
  lastDiscoveredModels?: string[];
}) {
  if (!isCodexPlatform(input.account)) return input.account.extraConfig || null;
  const extraConfig = mergeAccountExtraConfig(input.account.extraConfig, {
    oauth: buildCodexOauthInfo(input.account.extraConfig, {
      modelDiscoveryStatus: input.status,
      lastModelSyncAt: input.checkedAt,
      lastModelSyncError: input.lastModelSyncError,
      lastDiscoveredModels: input.lastDiscoveredModels ?? [],
    }),
  });
  await db.update(schema.accounts).set({
    extraConfig,
    updatedAt: input.checkedAt,
  }).where(eq(schema.accounts.id, input.account.id)).run();
  input.account.extraConfig = extraConfig;
  return extraConfig;
}

async function discoverCodexModelsFromCloud(input: {
  site: typeof schema.sites.$inferSelect;
  account: typeof schema.accounts.$inferSelect;
}): Promise<string[]> {
  const accessToken = (input.account.accessToken || '').trim();
  if (!accessToken) {
    throw new Error('codex oauth access token missing');
  }
  const oauth = getCodexOauthInfoFromExtraConfig(input.account.extraConfig);
  const headers: Record<string, string> = {
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/json',
    Originator: 'codex_cli_rs',
  };
  if (oauth?.accountId) {
    headers['Chatgpt-Account-Id'] = oauth.accountId;
  }

  const response = await fetch(
    buildCodexModelsEndpoint(input.site.url),
    withSiteRecordProxyRequestInit(input.site, { method: 'GET', headers }),
  );
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`HTTP ${response.status}: ${text || 'codex model discovery failed'}`);
  }
  return normalizeModels(extractCodexModelIds(await response.json()));
}

function isExactModelPattern(modelPattern: string): boolean {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (normalized.toLowerCase().startsWith('re:')) return false;
  return !/[\*\?\[]/.test(normalized);
}

async function withTimeout<T>(fn: () => Promise<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    return await Promise.race([
      fn(),
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function buildAccountNotFoundRefreshResult(accountId: number): ModelRefreshAccountNotFoundResult {
  return {
    accountId,
    refreshed: false,
    status: 'failed',
    errorCode: 'account_not_found',
    errorMessage: '账号不存在',
    modelCount: 0,
    modelsPreview: [],
    reason: 'account_not_found',
  };
}

function buildSkippedRefreshResult(
  accountId: number,
  code: ModelRefreshSkipCode,
  errorMessage: string,
): ModelRefreshSkippedResult {
  return {
    accountId,
    refreshed: false,
    status: 'skipped',
    errorCode: code,
    errorMessage,
    modelCount: 0,
    modelsPreview: [],
    reason: code,
  };
}

function buildFailedRefreshResult(input: {
  accountId: number;
  errorCode: ModelRefreshErrorCode;
  errorMessage: string;
  tokenScanned: number;
  discoveredByCredential: boolean;
  discoveredApiToken: boolean;
}): ModelRefreshFailureResult {
  return {
    accountId: input.accountId,
    refreshed: true,
    status: 'failed',
    errorCode: input.errorCode,
    errorMessage: input.errorMessage,
    modelCount: 0,
    modelsPreview: [],
    tokenScanned: input.tokenScanned,
    discoveredByCredential: input.discoveredByCredential,
    discoveredApiToken: input.discoveredApiToken,
  };
}

function buildSuccessfulRefreshResult(input: {
  accountId: number;
  modelCount: number;
  modelsPreview: string[];
  tokenScanned: number;
  discoveredByCredential: boolean;
  discoveredApiToken: boolean;
}): ModelRefreshSuccessResult {
  return {
    accountId: input.accountId,
    refreshed: true,
    status: 'success',
    errorCode: null,
    errorMessage: '',
    modelCount: input.modelCount,
    modelsPreview: input.modelsPreview,
    tokenScanned: input.tokenScanned,
    discoveredByCredential: input.discoveredByCredential,
    discoveredApiToken: input.discoveredApiToken,
  };
}

export async function refreshModelsForAccount(accountId: number): Promise<ModelRefreshResult> {
  const row = await db.select().from(schema.accounts)
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(eq(schema.accounts.id, accountId))
    .get();

  if (!row) {
    return buildAccountNotFoundRefreshResult(accountId);
  }

  const account = row.accounts;
  const site = row.sites;
  const adapter = getAdapter(site.platform);

  const accountTokens = await db.select()
    .from(schema.accountTokens)
    .where(eq(schema.accountTokens.accountId, accountId))
    .all();

  await db.delete(schema.modelAvailability)
    .where(eq(schema.modelAvailability.accountId, accountId))
    .run();

  for (const token of accountTokens) {
    await db.delete(schema.tokenModelAvailability)
      .where(eq(schema.tokenModelAvailability.tokenId, token.id))
      .run();
  }

  if (isSiteDisabled(site.status)) {
    return buildSkippedRefreshResult(accountId, 'site_disabled', '站点已禁用');
  }

  if (!adapter || account.status !== 'active') {
    return buildSkippedRefreshResult(accountId, 'adapter_or_status', '平台不可用或账号未激活');
  }

  if (isCodexPlatform(account)) {
    const checkedAt = new Date().toISOString();
    const startedAt = Date.now();
    try {
      const codexModels = await withTimeout(
        () => discoverCodexModelsFromCloud({ site, account }),
        MODEL_DISCOVERY_TIMEOUT_MS,
        `codex model discovery timeout (${Math.round(MODEL_DISCOVERY_TIMEOUT_MS / 1000)}s)`,
      );
      if (codexModels.length === 0) {
        throw new Error('未获取到可用模型');
      }

      await db.insert(schema.modelAvailability).values(
        codexModels.map((modelName) => ({
          accountId,
          modelName,
          available: true,
          latencyMs: Date.now() - startedAt,
          checkedAt,
        })),
      ).run();
      await updateCodexOauthModelDiscoveryState({
        account,
        checkedAt,
        status: 'healthy',
        lastDiscoveredModels: codexModels,
      });
      await setAccountRuntimeHealth(accountId, {
        state: 'healthy',
        reason: 'Codex 云端模型探测成功',
        source: 'model-discovery',
        checkedAt,
      });
      return buildSuccessfulRefreshResult({
        accountId,
        modelCount: codexModels.length,
        modelsPreview: codexModels.slice(0, 10),
        tokenScanned: 0,
        discoveredByCredential: true,
        discoveredApiToken: false,
      });
    } catch (err) {
      const rawMessage = (err as { message?: string })?.message || 'codex model discovery failed';
      const errorCode = classifyModelDiscoveryError(rawMessage);
      const errorMessage = `Codex 模型获取失败（${rawMessage}）`;
      await updateCodexOauthModelDiscoveryState({
        account,
        checkedAt,
        status: 'abnormal',
        lastModelSyncError: errorMessage,
        lastDiscoveredModels: [],
      });
      await setAccountRuntimeHealth(account.id, {
        state: 'unhealthy',
        reason: errorMessage,
        source: 'model-discovery',
        checkedAt,
      });
      return buildFailedRefreshResult({
        accountId,
        errorCode,
        errorMessage,
        tokenScanned: 0,
        discoveredByCredential: false,
        discoveredApiToken: false,
      });
    }
  }

  const platformUserId = resolvePlatformUserId(account.extraConfig, account.username);
  let discoveredApiToken: string | null = null;

  if (!account.apiToken && account.accessToken) {
    try {
      discoveredApiToken = await withTimeout(
        () => adapter.getApiToken(site.url, account.accessToken, platformUserId),
        API_TOKEN_DISCOVERY_TIMEOUT_MS,
        `api token discovery timeout (${Math.round(API_TOKEN_DISCOVERY_TIMEOUT_MS / 1000)}s)`,
      );
      if (discoveredApiToken && !isMaskedTokenValue(discoveredApiToken)) {
        ensureDefaultTokenForAccount(account.id, discoveredApiToken, { name: 'default', source: 'sync' });
        await db.update(schema.accounts).set({
          apiToken: discoveredApiToken,
          updatedAt: new Date().toISOString(),
        }).where(eq(schema.accounts.id, account.id)).run();
      } else {
        discoveredApiToken = null;
      }
    } catch { }
  }

  let enabledTokens = await db.select()
    .from(schema.accountTokens)
    .where(and(
      eq(schema.accountTokens.accountId, account.id),
      eq(schema.accountTokens.enabled, true),
      eq(schema.accountTokens.valueStatus, ACCOUNT_TOKEN_VALUE_STATUS_READY),
    ))
    .all();
  enabledTokens = enabledTokens.filter(isUsableAccountToken);

  // Last fallback: if still no managed token but account has a legacy apiToken, mirror it into token table.
  if (!isApiKeyConnection(account) && enabledTokens.length === 0) {
    const fallback = discoveredApiToken || account.apiToken || null;
    if (fallback) {
      ensureDefaultTokenForAccount(account.id, fallback, { name: 'default', source: 'legacy' });
      enabledTokens = await db.select()
        .from(schema.accountTokens)
        .where(and(
          eq(schema.accountTokens.accountId, account.id),
          eq(schema.accountTokens.enabled, true),
          eq(schema.accountTokens.valueStatus, ACCOUNT_TOKEN_VALUE_STATUS_READY),
        ))
        .all();
      enabledTokens = enabledTokens.filter(isUsableAccountToken);
    }
  }

  const accountModels = new Set<string>();
  const modelLatency = new Map<string, number | null>();
  let scannedTokenCount = 0;
  let discoveredByCredential = false;
  const attemptedCredentials = new Set<string>();
  const failureMessages: string[] = [];
  const recordFailure = (err: unknown) => {
    const message = (err as { message?: string })?.message || String(err || '');
    if (message) failureMessages.push(message);
  };

  const mergeDiscoveredModels = (models: string[], latencyMs: number | null) => {
    for (const modelName of models) {
      accountModels.add(modelName);
      const prev = modelLatency.get(modelName);
      if (prev === undefined || prev === null) {
        modelLatency.set(modelName, latencyMs);
        continue;
      }
      if (latencyMs === null) continue;
      if (latencyMs < prev) modelLatency.set(modelName, latencyMs);
    }
  };

  const discoverModelsWithCredential = async (credentialRaw: string | null | undefined) => {
    const credential = (credentialRaw || '').trim();
    if (!credential) return;
    if (isMaskedTokenValue(credential)) return;
    if (attemptedCredentials.has(credential)) return;
    attemptedCredentials.add(credential);

    const startedAt = Date.now();
    let models: string[] = [];
    try {
      models = normalizeModels(
        await withTimeout(
          () => adapter.getModels(site.url, credential, platformUserId),
          MODEL_DISCOVERY_TIMEOUT_MS,
          `model discovery timeout (${Math.round(MODEL_DISCOVERY_TIMEOUT_MS / 1000)}s)`,
        ),
      );
    } catch (err) {
      recordFailure(err);
      models = [];
    }
    if (models.length === 0) return;
    discoveredByCredential = true;
    const latencyMs = Date.now() - startedAt;
    mergeDiscoveredModels(models, latencyMs);
  };

  // Prefer account-level credential discovery so model availability does not rely on managed tokens.
  await discoverModelsWithCredential(account.apiToken);
  await discoverModelsWithCredential(discoveredApiToken);
  await discoverModelsWithCredential(account.accessToken);

  for (const token of enabledTokens) {
    const startedAt = Date.now();
    let models: string[] = [];

    try {
      models = normalizeModels(
        await withTimeout(
          () => adapter.getModels(site.url, token.token, platformUserId),
          MODEL_DISCOVERY_TIMEOUT_MS,
          `model discovery timeout (${Math.round(MODEL_DISCOVERY_TIMEOUT_MS / 1000)}s)`,
        ),
      );
    } catch (err) {
      recordFailure(err);
      models = [];
    }

    if (models.length === 0) continue;

    const latencyMs = Date.now() - startedAt;
    const checkedAt = new Date().toISOString();

    await db.insert(schema.tokenModelAvailability).values(
      models.map((modelName) => ({
        tokenId: token.id,
        modelName,
        available: true,
        latencyMs,
        checkedAt,
      })),
    ).run();

    scannedTokenCount++;
    mergeDiscoveredModels(models, latencyMs);
  }

  if (accountModels.size === 0) {
    const firstMessage = failureMessages[0] || '';
    const errorCode = firstMessage ? classifyModelDiscoveryError(firstMessage) : 'empty_models';
    const errorMessage = buildModelFailureMessage(errorCode, firstMessage);
    await setAccountRuntimeHealth(account.id, {
      state: 'unhealthy',
      reason: errorMessage,
      source: 'model-discovery',
      checkedAt: new Date().toISOString(),
    });
    return buildFailedRefreshResult({
      accountId,
      errorCode,
      errorMessage,
      tokenScanned: scannedTokenCount,
      discoveredByCredential,
      discoveredApiToken: !!discoveredApiToken,
    });
  }

  const checkedAt = new Date().toISOString();
  await db.insert(schema.modelAvailability).values(
    Array.from(accountModels).map((modelName) => ({
      accountId: account.id,
      modelName,
      available: true,
      latencyMs: modelLatency.get(modelName) ?? null,
      checkedAt,
    })),
  ).run();

  await setAccountRuntimeHealth(account.id, {
    state: 'healthy',
    reason: '模型探测成功',
    source: 'model-discovery',
    checkedAt,
  });

  const modelsPreview = Array.from(accountModels).slice(0, 10);
  return buildSuccessfulRefreshResult({
    accountId,
    modelCount: accountModels.size,
    modelsPreview,
    tokenScanned: scannedTokenCount,
    discoveredByCredential,
    discoveredApiToken: !!discoveredApiToken,
  });
}

async function refreshModelsForAllActiveAccounts(): Promise<ModelRefreshResult[]> {
  const accounts = await db.select({ id: schema.accounts.id }).from(schema.accounts)
    .where(eq(schema.accounts.status, 'active'))
    .all();

  const results: ModelRefreshResult[] = [];
  for (let offset = 0; offset < accounts.length; offset += MODEL_REFRESH_BATCH_SIZE) {
    const batch = accounts.slice(offset, offset + MODEL_REFRESH_BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(async (account) => refreshModelsForAccount(account.id)));
    results.push(...batchResults);
  }
  return results;
}

export async function rebuildTokenRoutesFromAvailability() {
  const tokenRows = await db.select().from(schema.tokenModelAvailability)
    .innerJoin(schema.accountTokens, eq(schema.tokenModelAvailability.tokenId, schema.accountTokens.id))
    .innerJoin(schema.accounts, eq(schema.accountTokens.accountId, schema.accounts.id))
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(
      and(
        eq(schema.tokenModelAvailability.available, true),
        eq(schema.accountTokens.enabled, true),
        eq(schema.accountTokens.valueStatus, ACCOUNT_TOKEN_VALUE_STATUS_READY),
        eq(schema.accounts.status, 'active'),
        eq(schema.sites.status, 'active'),
      ),
    )
    .all();
  const usableTokenRows = tokenRows.filter((row) => isUsableAccountToken(row.account_tokens));

  const accountRows = await db.select().from(schema.modelAvailability)
    .innerJoin(schema.accounts, eq(schema.modelAvailability.accountId, schema.accounts.id))
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(
      and(
        eq(schema.modelAvailability.available, true),
        eq(schema.accounts.status, 'active'),
        eq(schema.sites.status, 'active'),
      ),
    )
    .all();

  // Load site-level disabled models
  const disabledModelRows = await db.select().from(schema.siteDisabledModels).all();
  const disabledModelsBySite = new Map<number, Set<string>>();
  for (const row of disabledModelRows) {
    if (!disabledModelsBySite.has(row.siteId)) disabledModelsBySite.set(row.siteId, new Set());
    disabledModelsBySite.get(row.siteId)!.add(row.modelName);
  }

  function isModelDisabledForSite(siteId: number, modelName: string): boolean {
    const disabled = disabledModelsBySite.get(siteId);
    return !!disabled && disabled.has(modelName);
  }

  const modelCandidates = new Map<string, Map<string, { accountId: number; tokenId: number | null }>>();
  const addModelCandidate = (modelNameRaw: string | null | undefined, accountId: number, tokenId: number | null, siteId: number) => {
    const modelName = (modelNameRaw || '').trim();
    if (!modelName) return;
    if (isModelDisabledForSite(siteId, modelName)) return;
    if (!modelCandidates.has(modelName)) modelCandidates.set(modelName, new Map());
    const candidateKey = `${accountId}:${tokenId ?? 'account'}`;
    modelCandidates.get(modelName)!.set(candidateKey, { accountId, tokenId });
  };

  for (const row of usableTokenRows) {
    addModelCandidate(row.token_model_availability.modelName, row.accounts.id, row.account_tokens.id, row.accounts.siteId);
  }

  for (const row of accountRows) {
    if (!supportsDirectAccountRoutingConnection(row.accounts)) continue;
    addModelCandidate(row.model_availability.modelName, row.accounts.id, null, row.accounts.siteId);
  }

  const routes = await db.select().from(schema.tokenRoutes).all();
  const channels = await db.select().from(schema.routeChannels).all();

  let createdRoutes = 0;
  let createdChannels = 0;
  let removedChannels = 0;
  let removedRoutes = 0;

  for (const [modelName, candidateMap] of modelCandidates.entries()) {
    let route = routes.find((r) => r.modelPattern === modelName);
    if (!route) {
      const inserted = await db.insert(schema.tokenRoutes).values({
        modelPattern: modelName,
        enabled: true,
      }).run();
      const insertedId = Number(inserted.lastInsertRowid || 0);
      route = insertedId > 0
        ? await db.select().from(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, insertedId)).get()
        : undefined;
      if (!route) continue;
      routes.push(route);
      createdRoutes++;
    }

    const routeChannels = channels.filter((channel) => channel.routeId === route.id);
    const desiredKeys = new Set(Array.from(candidateMap.keys()));

    for (const [candidateKey, candidate] of candidateMap.entries()) {
      const exists = routeChannels.some((channel) => (
        channel.accountId === candidate.accountId
        && (channel.tokenId ?? null) === candidate.tokenId
      ));
      if (exists) continue;

      const inserted = await db.insert(schema.routeChannels).values({
        routeId: route.id,
        accountId: candidate.accountId,
        tokenId: candidate.tokenId,
        priority: 0,
        weight: 10,
        enabled: true,
        manualOverride: false,
      }).run();
      const insertedId = Number(inserted.lastInsertRowid || 0);
      if (insertedId <= 0) continue;
      const created = await db.select().from(schema.routeChannels).where(eq(schema.routeChannels.id, insertedId)).get();
      if (!created) continue;
      channels.push(created);
      createdChannels++;
      desiredKeys.add(candidateKey);
    }

    for (const channel of routeChannels) {
      const channelKey = `${channel.accountId}:${channel.tokenId ?? 'account'}`;
      if (desiredKeys.has(channelKey)) {
        continue;
      }

      if (!channel.tokenId) {
        const preferred = await getPreferredAccountToken(channel.accountId);
        if (preferred && desiredKeys.has(`${channel.accountId}:${preferred.id}`)) {
          await db.update(schema.routeChannels)
            .set({ tokenId: preferred.id })
            .where(eq(schema.routeChannels.id, channel.id))
            .run();
          continue;
        }
      }

      if (!channel.manualOverride) {
        await db.delete(schema.routeChannels).where(eq(schema.routeChannels.id, channel.id)).run();
        removedChannels++;
      }
    }
  }

  const latestModelNames = new Set<string>(Array.from(modelCandidates.keys()));
  for (const route of routes) {
    const modelPattern = (route.modelPattern || '').trim();
    if (!modelPattern || !isExactModelPattern(modelPattern) || latestModelNames.has(modelPattern)) {
      continue;
    }

    const routeChannelCount = channels.filter((channel) => channel.routeId === route.id).length;
    if (routeChannelCount > 0) {
      removedChannels += routeChannelCount;
    }

    const deleted = (await db.delete(schema.tokenRoutes).where(eq(schema.tokenRoutes.id, route.id)).run()).changes;
    if (deleted > 0) {
      removedRoutes += deleted;
    }
  }

  if (createdRoutes > 0 || createdChannels > 0 || removedChannels > 0 || removedRoutes > 0) {
    await clearAllRouteDecisionSnapshots();
  }

  invalidateTokenRouterCache();

  return {
    models: modelCandidates.size,
    createdRoutes,
    createdChannels,
    removedChannels,
    removedRoutes,
  };
}

export async function refreshModelsAndRebuildRoutes() {
  const refresh = await refreshModelsForAllActiveAccounts();
  const rebuild = await rebuildTokenRoutesFromAvailability();
  return { refresh, rebuild };
}
