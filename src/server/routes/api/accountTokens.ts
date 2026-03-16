import { FastifyInstance } from 'fastify';
import { and, eq } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import {
  ACCOUNT_TOKEN_VALUE_STATUS_MASKED_PENDING,
  ACCOUNT_TOKEN_VALUE_STATUS_READY,
  ensureDefaultTokenForAccount,
  isMaskedPendingAccountToken,
  isMaskedTokenValue,
  isUsableAccountToken,
  listTokensWithRelations,
  normalizeTokenForDisplay,
  maskToken,
  repairDefaultToken,
  resolveAccountTokenValueStatus,
  setDefaultToken,
  syncTokensFromUpstream,
} from '../../services/accountTokenService.js';
import { getAdapter } from '../../services/platforms/index.js';
import { getCredentialModeFromExtraConfig, resolvePlatformUserId } from '../../services/accountExtraConfig.js';
import { startBackgroundTask } from '../../services/backgroundTaskService.js';
import {
  rebuildTokenRoutesFromAvailability,
  refreshModelsForAccount,
  type ModelRefreshResult,
} from '../../services/modelService.js';

type AccountWithSiteRow = {
  accounts: typeof schema.accounts.$inferSelect;
  sites: typeof schema.sites.$inferSelect;
};

type SyncExecutionResult = {
  accountId: number;
  accountName: string;
  accountStatus: string | null;
  siteId: number;
  siteName: string;
  siteStatus: string | null;
  status: 'synced' | 'skipped' | 'failed';
  reason?: string;
  message?: string;
  synced: boolean;
  created: number;
  updated: number;
  maskedPending?: number;
  pendingTokenIds?: number[];
  total: number;
  defaultTokenId?: number | null;
};

type CoverageRefreshFailureItem = {
  accountId: number;
  refreshed: false;
  status: 'failed';
  errorCode: 'coverage_refresh_failed';
  errorMessage: string;
  modelCount: 0;
  modelsPreview: string[];
  reason: 'coverage_refresh_failed';
  tokenScanned: 0;
  discoveredByCredential: false;
  discoveredApiToken: false;
};

type CoverageRefreshItem = ModelRefreshResult | CoverageRefreshFailureItem;
type CoverageRefreshRebuildResult =
  | { success: true; result: Awaited<ReturnType<typeof rebuildTokenRoutesFromAvailability>> }
  | { success: false; error: string };

const TOKEN_SYNC_TIMEOUT_MS = 15_000;
const SYNC_ALL_BATCH_SIZE = 3;

function buildSyncAccountLabel(item: SyncExecutionResult): string {
  const account = (item.accountName || `#${item.accountId}`).trim();
  const site = (item.siteName || 'unknown-site').trim();
  return `${account} @ ${site}`;
}

function buildSyncReason(item: SyncExecutionResult): string {
  const message = String(item.message || item.reason || '').trim();
  if (!message) return '';
  if (message.length <= 32) return message;
  return `${message.slice(0, 32)}...`;
}

function buildTokenSyncTaskDetailMessage(results: SyncExecutionResult[]): string {
  if (!Array.isArray(results) || results.length === 0) return '';

  const synced = results.filter((item) => item.status === 'synced');
  const skipped = results.filter((item) => item.status === 'skipped');
  const failed = results.filter((item) => item.status === 'failed');

  const renderRows = (rows: SyncExecutionResult[], withReason = false) => {
    const sliced = rows.slice(0, 12).map((item) => {
      const base = buildSyncAccountLabel(item);
      if (!withReason) return base;
      const reason = buildSyncReason(item);
      return reason ? `${base}(${reason})` : base;
    });
    if (rows.length > 12) sliced.push(`...等${rows.length}个`);
    return sliced.join('、');
  };

  const segments: string[] = [
    `成功(${synced.length}): ${synced.length > 0 ? renderRows(synced) : '-'}`,
    `跳过(${skipped.length}): ${skipped.length > 0 ? renderRows(skipped, true) : '-'}`,
    `失败(${failed.length}): ${failed.length > 0 ? renderRows(failed, true) : '-'}`,
  ];
  return segments.join('\n');
}

function isSiteDisabled(status?: string | null): boolean {
  return (status || 'active') === 'disabled';
}

function isApiKeyConnection(account: typeof schema.accounts.$inferSelect): boolean {
  const explicit = getCredentialModeFromExtraConfig(account.extraConfig);
  if (explicit && explicit !== 'auto') return explicit === 'apikey';
  return !(account.accessToken || '').trim();
}

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function parseOptionalBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1') return true;
  if (normalized === 'false' || normalized === '0') return false;
  return undefined;
}

function parsePositiveInteger(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const normalized = Math.trunc(value);
    return normalized > 0 ? normalized : undefined;
  }
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const normalized = Number.parseInt(trimmed, 10);
  if (Number.isNaN(normalized) || normalized <= 0) return undefined;
  return normalized;
}

function parseExpiredTime(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const normalized = Math.trunc(value);
    return normalized > 0 ? normalized : undefined;
  }
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;

  if (/^\d+$/.test(trimmed)) {
    const numericValue = Number.parseInt(trimmed, 10);
    if (!Number.isNaN(numericValue) && numericValue > 0) return numericValue;
  }

  const parsedMs = Date.parse(trimmed);
  if (!Number.isFinite(parsedMs)) return undefined;
  const seconds = Math.trunc(parsedMs / 1000);
  return seconds > 0 ? seconds : undefined;
}

function normalizeBatchIds(input: unknown): number[] {
  if (!Array.isArray(input)) return [];
  return input
    .map((item) => Number.parseInt(String(item), 10))
    .filter((id) => Number.isFinite(id) && id > 0);
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

async function executeAccountTokenSync(row: AccountWithSiteRow): Promise<SyncExecutionResult> {
  const accountId = row.accounts.id;
  const base = {
    accountId,
    accountName: row.accounts.username || `account-${accountId}`,
    accountStatus: row.accounts.status,
    siteId: row.sites.id,
    siteName: row.sites.name,
    siteStatus: row.sites.status,
  };

  if (isSiteDisabled(row.sites.status)) {
    return {
      ...base,
      status: 'skipped',
      reason: 'site_disabled',
      message: 'site disabled',
      synced: false,
      created: 0,
      updated: 0,
      total: 0,
      defaultTokenId: null,
    };
  }

  if (isApiKeyConnection(row.accounts)) {
    return {
      ...base,
      status: 'skipped',
      reason: 'apikey_connection',
      message: 'apikey connection does not support account tokens',
      synced: false,
      created: 0,
      updated: 0,
      total: 0,
      defaultTokenId: null,
    };
  }

  if (!row.accounts.accessToken) {
    if (row.accounts.apiToken) {
      ensureDefaultTokenForAccount(accountId, row.accounts.apiToken, { name: 'default', source: 'legacy' });
    }
    return {
      ...base,
      status: 'skipped',
      reason: 'missing_access_token',
      synced: false,
      created: 0,
      updated: 0,
      total: 0,
      defaultTokenId: null,
    };
  }

  const adapter = getAdapter(row.sites.platform);
  if (!adapter) {
    return {
      ...base,
      status: 'failed',
      reason: 'unsupported_platform',
      message: `不支持的平台: ${row.sites.platform}`,
      synced: false,
      created: 0,
      updated: 0,
      total: 0,
      defaultTokenId: null,
    };
  }

  try {
    const platformUserId = resolvePlatformUserId(row.accounts.extraConfig, row.accounts.username);
    let tokens = await withTimeout(
      () => adapter.getApiTokens(row.sites.url, row.accounts.accessToken, platformUserId),
      TOKEN_SYNC_TIMEOUT_MS,
      `token sync timeout (${Math.round(TOKEN_SYNC_TIMEOUT_MS / 1000)}s)`,
    );

    if (tokens.length === 0) {
      const fallback = await withTimeout(
        () => adapter.getApiToken(row.sites.url, row.accounts.accessToken, platformUserId),
        TOKEN_SYNC_TIMEOUT_MS,
        `token sync timeout (${Math.round(TOKEN_SYNC_TIMEOUT_MS / 1000)}s)`,
      );
      if (fallback) {
        tokens = [{ name: 'default', key: fallback, enabled: true, tokenGroup: 'default' }];
      }
    }

    if (tokens.length === 0) {
      return {
        ...base,
        status: 'skipped',
        reason: 'no_upstream_tokens',
        message: 'upstream returned no api tokens',
        synced: false,
        created: 0,
        updated: 0,
        total: 0,
        defaultTokenId: null,
      };
    }

    const synced = await syncTokensFromUpstream(accountId, tokens);
    if ((synced.maskedPending || 0) > 0) {
      return {
        ...base,
        status: 'synced',
        reason: 'upstream_masked_tokens',
        message: `上游返回 ${synced.maskedPending} 条脱敏令牌，已保存为待补全记录，请手动补全明文 token。`,
        synced: true,
        ...synced,
      };
    }
    return {
      ...base,
      status: 'synced',
      synced: true,
      ...synced,
    };
  } catch (error: any) {
    return {
      ...base,
      status: 'failed',
      reason: 'sync_error',
      message: error?.message || 'sync failed',
      synced: false,
      created: 0,
      updated: 0,
      total: 0,
      defaultTokenId: null,
    };
  }
}

async function appendTokenSyncEvent(result: SyncExecutionResult) {
  const title = result.status === 'synced'
    ? '令牌同步成功'
    : (result.status === 'skipped' ? '令牌同步跳过' : '令牌同步失败');
  const level = result.status === 'synced'
    ? 'info'
    : (result.status === 'skipped' ? 'warning' : 'error');
  const detail = result.status === 'synced'
    ? `新增 ${result.created}，更新 ${result.updated}，待补全 ${result.maskedPending || 0}，总数 ${result.total}`
    : (result.message || result.reason || 'sync skipped');

  try {
    await db.insert(schema.events).values({
      type: 'token',
      title,
      message: `${result.accountName} @ ${result.siteName}: ${detail}`,
      level,
      relatedId: result.accountId,
      relatedType: 'account',
      createdAt: new Date().toISOString(),
    }).run();
  } catch {}
}

async function executeSyncAllAccountTokens() {
  const rows = await db.select().from(schema.accounts)
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(eq(schema.accounts.status, 'active'))
    .all();

  const results: SyncExecutionResult[] = [];
  for (let offset = 0; offset < rows.length; offset += SYNC_ALL_BATCH_SIZE) {
    const batch = rows.slice(offset, offset + SYNC_ALL_BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map(async (row) => {
        const result = await executeAccountTokenSync(row);
        appendTokenSyncEvent(result);
        return result;
      }),
    );
    results.push(...batchResults);
  }

  const coverageRefresh = await refreshCoverageForAccounts(
    results
      .filter((item) => item.status === 'synced')
      .map((item) => item.accountId),
  );

  const summary = {
    total: results.length,
    synced: results.filter((item) => item.status === 'synced').length,
    skipped: results.filter((item) => item.status === 'skipped').length,
    failed: results.filter((item) => item.status === 'failed').length,
    created: results.reduce((acc, item) => acc + item.created, 0),
    updated: results.reduce((acc, item) => acc + item.updated, 0),
  };

  return { summary, results, coverageRefresh };
}

async function refreshCoverageForAccounts(accountIds: number[]) {
  const uniqueAccountIds = Array.from(new Set(
    accountIds.filter((id) => Number.isFinite(id) && id > 0),
  ));

  if (uniqueAccountIds.length === 0) {
    return { refresh: [], rebuild: null };
  }

  const refresh: CoverageRefreshItem[] = [];
  for (let offset = 0; offset < uniqueAccountIds.length; offset += SYNC_ALL_BATCH_SIZE) {
    const batch = uniqueAccountIds.slice(offset, offset + SYNC_ALL_BATCH_SIZE);
    const settled = await Promise.allSettled(
      batch.map(async (accountId) => refreshModelsForAccount(accountId)),
    );
    settled.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        refresh.push(result.value);
        return;
      }

      const accountId = batch[index] || 0;
      const errorMessage = result.reason instanceof Error ? result.reason.message : String(result.reason || 'coverage refresh failed');
      refresh.push(buildCoverageRefreshFailureItem(accountId, errorMessage));
      console.warn(`[account-tokens] coverage refresh failed for account ${accountId}: ${errorMessage}`);
    });
  }

  let rebuild: CoverageRefreshRebuildResult | null = null;
  try {
    rebuild = {
      success: true,
      result: await rebuildTokenRoutesFromAvailability(),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error || 'route rebuild failed');
    rebuild = {
      success: false,
      error: errorMessage,
    };
    console.warn(`[account-tokens] token route rebuild failed after coverage refresh: ${errorMessage}`);
  }

  return { refresh, rebuild };
}

function buildCoverageRefreshFailureItem(
  accountId: number,
  errorMessage: string,
): CoverageRefreshFailureItem {
  return {
    accountId,
    refreshed: false,
    status: 'failed',
    errorCode: 'coverage_refresh_failed',
    errorMessage,
    modelCount: 0,
    modelsPreview: [],
    reason: 'coverage_refresh_failed',
    tokenScanned: 0,
    discoveredByCredential: false,
    discoveredApiToken: false,
  };
}

export async function accountTokensRoutes(app: FastifyInstance) {
  app.get<{ Querystring: { accountId?: string } }>('/api/account-tokens', async (request) => {
    const accountId = request.query.accountId ? Number.parseInt(request.query.accountId, 10) : undefined;
    return listTokensWithRelations(Number.isFinite(accountId as number) ? accountId : undefined);
  });

  app.post<{ Body: {
    accountId: number;
    name?: string;
    token?: string;
    enabled?: boolean;
    isDefault?: boolean;
    source?: string;
    group?: string;
    unlimitedQuota?: boolean | string;
    remainQuota?: number | string;
    expiredTime?: number | string;
    allowIps?: string;
    modelLimitsEnabled?: boolean | string;
    modelLimits?: string;
  } }>('/api/account-tokens', async (request, reply) => {
    const body = request.body;
    const row = await db.select()
      .from(schema.accounts)
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.accounts.id, body.accountId))
      .get();
    if (!row) {
      return reply.code(404).send({ success: false, message: '账号不存在' });
    }

    if (isApiKeyConnection(row.accounts)) {
      return reply.code(400).send({ success: false, message: 'API Key 连接不支持创建账号令牌' });
    }

    const tokenValue = (body.token || '').trim();
    if (tokenValue) {
      const now = new Date().toISOString();
      const existing = await db.select().from(schema.accountTokens)
        .where(eq(schema.accountTokens.accountId, body.accountId))
        .all();
      const valueStatus = isMaskedTokenValue(tokenValue)
        ? ACCOUNT_TOKEN_VALUE_STATUS_MASKED_PENDING
        : ACCOUNT_TOKEN_VALUE_STATUS_READY;
      const enabled = valueStatus === ACCOUNT_TOKEN_VALUE_STATUS_READY
        ? (body.enabled ?? true)
        : false;
      const isDefault = valueStatus === ACCOUNT_TOKEN_VALUE_STATUS_READY
        ? (body.isDefault ?? false)
        : false;

      const inserted = await db.insert(schema.accountTokens).values({
        accountId: body.accountId,
        name: (body.name || '').trim() || (existing.length === 0 ? 'default' : `token-${existing.length + 1}`),
        token: tokenValue,
        tokenGroup: (body.group || '').trim() || null,
        valueStatus,
        source: body.source || 'manual',
        enabled,
        isDefault,
        createdAt: now,
        updatedAt: now,
      }).run();
      const createdId = Number(inserted.lastInsertRowid || 0);
      if (createdId <= 0) {
        return reply.code(500).send({ success: false, message: '创建令牌失败' });
      }
      const created = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, createdId)).get();
      if (!created) {
        return reply.code(500).send({ success: false, message: '创建令牌失败' });
      }

      if (valueStatus === ACCOUNT_TOKEN_VALUE_STATUS_READY && (body.isDefault || (existing.length === 0 && enabled))) {
        await setDefaultToken(created.id);
      } else if (valueStatus === ACCOUNT_TOKEN_VALUE_STATUS_READY && existing.every((token) => !token.isDefault) && enabled) {
        await setDefaultToken(created.id);
      }
      const coverageRefresh = await refreshCoverageForAccounts([body.accountId]);
      return { success: true, token: created, coverageRefresh };
    }

    const account = row.accounts;
    const site = row.sites;

    if (isSiteDisabled(site.status)) {
      return reply.code(400).send({ success: false, message: '站点已禁用，无法创建令牌' });
    }

    if (!account.accessToken?.trim()) {
      return reply.code(400).send({ success: false, message: '账号缺少访问令牌，无法创建站点令牌' });
    }

    const adapter = getAdapter(site.platform);
    if (!adapter) {
      return reply.code(400).send({ success: false, message: `不支持的平台: ${site.platform}` });
    }

    const unlimitedQuota = body.unlimitedQuota === undefined
      ? undefined
      : parseOptionalBoolean(body.unlimitedQuota);
    if (body.unlimitedQuota !== undefined && unlimitedQuota === undefined) {
      return reply.code(400).send({ success: false, message: 'unlimitedQuota 参数无效' });
    }

    const remainQuota = body.remainQuota === undefined
      ? undefined
      : parsePositiveInteger(body.remainQuota);
    if (body.remainQuota !== undefined && remainQuota === undefined) {
      return reply.code(400).send({ success: false, message: 'remainQuota 必须是正整数' });
    }
    if (unlimitedQuota === false && remainQuota === undefined) {
      return reply.code(400).send({ success: false, message: '有限额度令牌必须填写 remainQuota' });
    }

    const expiredTime = body.expiredTime === undefined
      ? undefined
      : parseExpiredTime(body.expiredTime);
    if (body.expiredTime !== undefined && expiredTime === undefined) {
      return reply.code(400).send({ success: false, message: 'expiredTime 参数无效' });
    }

    const modelLimitsEnabled = body.modelLimitsEnabled === undefined
      ? undefined
      : parseOptionalBoolean(body.modelLimitsEnabled);
    if (body.modelLimitsEnabled !== undefined && modelLimitsEnabled === undefined) {
      return reply.code(400).send({ success: false, message: 'modelLimitsEnabled 参数无效' });
    }

    const platformUserId = resolvePlatformUserId(account.extraConfig, account.username);
    const createdViaUpstream = await adapter.createApiToken(
      site.url,
      account.accessToken,
      platformUserId,
      {
        name: asTrimmedString(body.name),
        group: asTrimmedString(body.group),
        unlimitedQuota,
        remainQuota,
        expiredTime,
        allowIps: asTrimmedString(body.allowIps),
        modelLimitsEnabled,
        modelLimits: asTrimmedString(body.modelLimits),
      },
    );
    if (!createdViaUpstream) {
      return reply.code(502).send({ success: false, message: '站点创建令牌失败' });
    }

    const syncResult = await executeAccountTokenSync(row);
    appendTokenSyncEvent(syncResult);

    if (syncResult.status === 'failed') {
      return reply.code(502).send({ success: false, message: syncResult.message || '同步站点令牌失败' });
    }
    if (syncResult.status === 'skipped') {
      return reply.code(502).send({ success: false, message: syncResult.message || '站点未返回可用令牌' });
    }
    const coverageRefresh = await refreshCoverageForAccounts([account.id]);

    const preferred = await db.select().from(schema.accountTokens)
      .where(and(eq(schema.accountTokens.accountId, account.id), eq(schema.accountTokens.isDefault, true)))
      .get();
    const token = preferred || (await db.select().from(schema.accountTokens)
      .where(eq(schema.accountTokens.accountId, account.id))
      .all())
      .slice(-1)[0] || null;

    return {
      success: true,
      createdViaUpstream: true,
      ...syncResult,
      coverageRefresh,
      token,
    };
  });

  const deleteAccountTokenById = async (tokenId: number): Promise<{ success: boolean; message?: string }> => {
    const row = await db.select()
      .from(schema.accountTokens)
      .innerJoin(schema.accounts, eq(schema.accountTokens.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.accountTokens.id, tokenId))
      .get();
    if (!row) {
      return { success: false, message: '令牌不存在' };
    }

    if (isApiKeyConnection(row.accounts)) {
      return { success: false, message: 'API Key 连接不支持管理账号令牌' };
    }

    const existing = row.account_tokens;
    const account = row.accounts;
    const site = row.sites;
    const adapter = getAdapter(site.platform);
    const shouldDeleteUpstream = !isMaskedPendingAccountToken(existing)
      && !isSiteDisabled(site.status)
      && !!account.accessToken?.trim()
      && !!adapter;

    if (shouldDeleteUpstream) {
      const platformUserId = resolvePlatformUserId(account.extraConfig, account.username);
      const upstreamDeleted = await adapter!.deleteApiToken(
        site.url,
        account.accessToken,
        existing.token,
        platformUserId,
      );
      if (!upstreamDeleted) {
        return { success: false, message: '站点删除令牌失败，本地未删除' };
      }
    }

    await db.delete(schema.accountTokens).where(eq(schema.accountTokens.id, tokenId)).run();
    if (existing.isDefault) {
      repairDefaultToken(existing.accountId);
    }

    return { success: true };
  };

  app.post<{ Body?: { ids?: number[]; action?: string } }>('/api/account-tokens/batch', async (request, reply) => {
    const ids = normalizeBatchIds(request.body?.ids);
    const action = String(request.body?.action || '').trim();
    if (ids.length === 0) {
      return reply.code(400).send({ message: 'ids is required' });
    }
    if (!['enable', 'disable', 'delete'].includes(action)) {
      return reply.code(400).send({ message: 'Invalid action' });
    }

    const successIds: number[] = [];
    const failedItems: Array<{ id: number; message: string }> = [];

    for (const id of ids) {
      try {
        const existing = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, id)).get();
        if (!existing) {
          failedItems.push({ id, message: 'Token not found' });
          continue;
        }

        const owner = await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.accountId)).get();
        if (!owner) {
          failedItems.push({ id, message: 'Account not found' });
          continue;
        }
        if (isApiKeyConnection(owner)) {
          failedItems.push({ id, message: 'API Key 连接不支持管理账号令牌' });
          continue;
        }

        if (action === 'delete') {
          const result = await deleteAccountTokenById(id);
          if (!result.success) {
            failedItems.push({ id, message: result.message || 'Batch operation failed' });
            continue;
          }
        } else {
          if (isMaskedPendingAccountToken(existing)) {
            failedItems.push({ id, message: '待补全令牌不能修改启用状态，请先补全明文 token' });
            continue;
          }
          await db.update(schema.accountTokens)
            .set({
              enabled: action === 'enable',
              updatedAt: new Date().toISOString(),
            })
            .where(eq(schema.accountTokens.id, id))
            .run();
          if (existing.isDefault && action === 'disable') {
            repairDefaultToken(existing.accountId);
          }
        }

        successIds.push(id);
      } catch (error: any) {
        failedItems.push({ id, message: error?.message || 'Batch operation failed' });
      }
    }

    return {
      success: true,
      successIds,
      failedItems,
    };
  });

  app.put<{ Params: { id: string }; Body: { name?: string; token?: string; group?: string; enabled?: boolean; isDefault?: boolean; source?: string } }>('/api/account-tokens/:id', async (request, reply) => {
    const tokenId = Number.parseInt(request.params.id, 10);
    if (Number.isNaN(tokenId)) {
      return reply.code(400).send({ success: false, message: '令牌 ID 无效' });
    }

    const existing = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, tokenId)).get();
    if (!existing) {
      return reply.code(404).send({ success: false, message: '令牌不存在' });
    }

    const owner = await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.accountId)).get();
    if (!owner) {
      return reply.code(404).send({ success: false, message: '账号不存在' });
    }
    if (isApiKeyConnection(owner)) {
      return reply.code(400).send({ success: false, message: 'API Key 连接不支持管理账号令牌' });
    }

    const body = request.body;
    const updates: Record<string, unknown> = { updatedAt: new Date().toISOString() };
    let nextValueStatus = resolveAccountTokenValueStatus(existing);

    if (body.name !== undefined) {
      updates.name = (body.name || '').trim() || existing.name;
    }

    if (body.token !== undefined) {
      const tokenValue = body.token.trim();
      if (!tokenValue) {
        return reply.code(400).send({ success: false, message: '令牌不能为空' });
      }
      updates.token = tokenValue;
      nextValueStatus = isMaskedTokenValue(tokenValue)
        ? ACCOUNT_TOKEN_VALUE_STATUS_MASKED_PENDING
        : ACCOUNT_TOKEN_VALUE_STATUS_READY;
      updates.valueStatus = nextValueStatus;
    }

    if (body.group !== undefined) {
      updates.tokenGroup = (body.group || '').trim() || null;
    }

    if (nextValueStatus === ACCOUNT_TOKEN_VALUE_STATUS_MASKED_PENDING) {
      updates.enabled = false;
      updates.isDefault = false;
    } else {
      if (body.enabled !== undefined) updates.enabled = body.enabled;
      if (body.isDefault !== undefined) updates.isDefault = body.isDefault;
    }
    if (body.source !== undefined) updates.source = body.source;

    await db.update(schema.accountTokens).set(updates).where(eq(schema.accountTokens.id, tokenId)).run();

    const latest = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, tokenId)).get();
    if (!latest) {
      return reply.code(500).send({ success: false, message: '更新失败' });
    }

    if (body.isDefault === true && isUsableAccountToken(latest)) {
      setDefaultToken(tokenId);
    } else if (latest.isDefault && isUsableAccountToken(latest)) {
      setDefaultToken(tokenId);
    } else if (existing.isDefault && !isUsableAccountToken(latest)) {
      repairDefaultToken(existing.accountId);
    } else if (body.isDefault === false && existing.isDefault) {
      repairDefaultToken(existing.accountId);
    }

    return { success: true, token: latest };
  });

  app.post<{ Params: { id: string } }>('/api/account-tokens/:id/default', async (request, reply) => {
    const tokenId = Number.parseInt(request.params.id, 10);
    if (Number.isNaN(tokenId)) {
      return reply.code(400).send({ success: false, message: '令牌 ID 无效' });
    }
    const tokenRow = await db.select().from(schema.accountTokens).where(eq(schema.accountTokens.id, tokenId)).get();
    if (!tokenRow) {
      return reply.code(404).send({ success: false, message: '令牌不存在' });
    }
    const owner = await db.select().from(schema.accounts).where(eq(schema.accounts.id, tokenRow.accountId)).get();
    if (!owner) {
      return reply.code(404).send({ success: false, message: '账号不存在' });
    }
    if (isApiKeyConnection(owner)) {
      return reply.code(400).send({ success: false, message: 'API Key 连接不支持管理账号令牌' });
    }
    if (isMaskedPendingAccountToken(tokenRow)) {
      return reply.code(400).send({ success: false, message: '待补全令牌不能设为默认，请先补全明文 token' });
    }
    const success = await setDefaultToken(tokenId);
    if (!success) {
      return reply.code(404).send({ success: false, message: '令牌不存在' });
    }
    return { success: true };
  });

  app.get<{ Params: { id: string } }>('/api/account-tokens/:id/value', async (request, reply) => {
    const tokenId = Number.parseInt(request.params.id, 10);
    if (Number.isNaN(tokenId)) {
      return reply.code(400).send({ success: false, message: '令牌 ID 无效' });
    }

    const row = await db.select()
      .from(schema.accountTokens)
      .innerJoin(schema.accounts, eq(schema.accountTokens.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.accountTokens.id, tokenId))
      .get();
    if (!row) {
      return reply.code(404).send({ success: false, message: '令牌不存在' });
    }

    if (isApiKeyConnection(row.accounts)) {
      return reply.code(400).send({ success: false, message: 'API Key 连接不支持管理账号令牌' });
    }

    if (isMaskedPendingAccountToken(row.account_tokens) || isMaskedTokenValue(row.account_tokens.token)) {
      return reply.code(409).send({
        success: false,
        message: '当前仅保存了脱敏令牌，无法展开/复制。请在站点重新生成并同步，或手动更新为完整令牌。',
      });
    }

    const tokenValue = normalizeTokenForDisplay(row.account_tokens.token, row.sites.platform);
    return {
      success: true,
      id: row.account_tokens.id,
      name: row.account_tokens.name,
      token: tokenValue,
      tokenMasked: maskToken(row.account_tokens.token, row.sites.platform),
    };
  });

  app.get<{ Params: { accountId: string } }>('/api/account-tokens/groups/:accountId', async (request, reply) => {
    const accountId = Number.parseInt(request.params.accountId, 10);
    if (Number.isNaN(accountId)) {
      return reply.code(400).send({ success: false, message: '账号 ID 无效' });
    }

    const row = await db.select()
      .from(schema.accounts)
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.accounts.id, accountId))
      .get();
    if (!row) {
      return reply.code(404).send({ success: false, message: '账号不存在' });
    }

    if (isApiKeyConnection(row.accounts)) {
      return reply.code(400).send({ success: false, message: 'API Key 连接不支持拉取账号令牌分组' });
    }

    const account = row.accounts;
    const site = row.sites;
    const adapter = getAdapter(site.platform);
    if (!adapter) {
      return reply.code(400).send({ success: false, message: `不支持的平台: ${site.platform}` });
    }
    if (!account.accessToken?.trim()) {
      return reply.code(400).send({ success: false, message: '账号缺少访问令牌，无法拉取分组' });
    }

    try {
      const platformUserId = resolvePlatformUserId(account.extraConfig, account.username);
      const groups = await adapter.getUserGroups(site.url, account.accessToken, platformUserId);
      const normalized = Array.from(new Set((groups || []).map((item) => String(item || '').trim()).filter(Boolean)));
      return { success: true, groups: normalized.length > 0 ? normalized : ['default'] };
    } catch (error: any) {
      return reply.code(502).send({
        success: false,
        message: error?.message || '拉取分组失败',
      });
    }
  });

  app.delete<{ Params: { id: string } }>('/api/account-tokens/:id', async (request, reply) => {
    const tokenId = Number.parseInt(request.params.id, 10);
    if (Number.isNaN(tokenId)) {
      return reply.code(400).send({ success: false, message: '令牌 ID 无效' });
    }
    const result = await deleteAccountTokenById(tokenId);
    if (!result.success) {
      const statusCode = result.message === '令牌不存在'
        ? 404
        : (result.message === 'API Key 连接不支持管理账号令牌' ? 400 : 502);
      return reply.code(statusCode).send({ success: false, message: result.message });
    }
    return { success: true };
  });

  app.post<{ Params: { accountId: string } }>('/api/account-tokens/sync/:accountId', async (request, reply) => {
    const accountId = Number.parseInt(request.params.accountId, 10);
    if (Number.isNaN(accountId)) {
      return reply.code(400).send({ success: false, message: '账号 ID 无效' });
    }

    const row = await db.select().from(schema.accounts)
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(eq(schema.accounts.id, accountId))
      .get();

    if (!row) {
      return reply.code(404).send({ success: false, message: '账号不存在' });
    }

    const result = await executeAccountTokenSync(row);
    appendTokenSyncEvent(result);
    if (result.status === 'skipped' && result.reason === 'apikey_connection') {
      return reply.code(400).send({ success: false, message: 'API Key 连接不支持同步账号令牌' });
    }
    if (result.status === 'failed' && result.reason === 'unsupported_platform') {
      return reply.code(400).send({ success: false, message: result.message });
    }
    if (result.status === 'failed') {
      return reply.code(502).send({ success: false, message: result.message || '同步失败' });
    }
    const coverageRefresh = await refreshCoverageForAccounts([accountId]);
    return { success: true, ...result, coverageRefresh };
  });

  app.post<{ Body?: { wait?: boolean } }>('/api/account-tokens/sync-all', async (request, reply) => {
    if (request.body?.wait) {
      const syncResult = await executeSyncAllAccountTokens();
      return { success: true, ...syncResult };
    }

    const { task, reused } = startBackgroundTask(
      {
        type: 'token',
        title: '同步全部账号令牌',
        dedupeKey: 'sync-all-account-tokens',
        notifyOnFailure: true,
        successTitle: (currentTask) => {
          const summary = (currentTask.result as any)?.summary;
          if (!summary) return '同步全部账号令牌已完成';
          return `同步全部账号令牌已完成（成功${summary.synced}/跳过${summary.skipped}/失败${summary.failed}）`;
        },
        failureTitle: () => '同步全部账号令牌失败',
        successMessage: (currentTask) => {
          const summary = (currentTask.result as any)?.summary;
          const results = (currentTask.result as any)?.results as SyncExecutionResult[] | undefined;
          if (!summary) return '全部账号令牌同步任务已完成';
          const detail = buildTokenSyncTaskDetailMessage(Array.isArray(results) ? results : []);
          return detail
            ? `全部账号令牌同步完成：成功 ${summary.synced}，跳过 ${summary.skipped}，失败 ${summary.failed}\n${detail}`
            : `全部账号令牌同步完成：成功 ${summary.synced}，跳过 ${summary.skipped}，失败 ${summary.failed}`;
        },
        failureMessage: (currentTask) => `全部账号令牌同步失败：${currentTask.error || 'unknown error'}`,
      },
      async () => executeSyncAllAccountTokens(),
    );

    return reply.code(202).send({
      success: true,
      queued: true,
      reused,
      jobId: task.id,
      status: task.status,
      message: reused
        ? '令牌同步任务执行中，请稍后查看程序日志'
        : '已开始全部账号令牌同步，请稍后查看程序日志',
    });
  });

  app.get<{ Params: { accountId: string } }>('/api/account-tokens/account/:accountId/default', async (request, reply) => {
    const accountId = Number.parseInt(request.params.accountId, 10);
    if (Number.isNaN(accountId)) {
      return reply.code(400).send({ success: false, message: '账号 ID 无效' });
    }

    const row = await db.select()
      .from(schema.accountTokens)
      .innerJoin(schema.accounts, eq(schema.accountTokens.accountId, schema.accounts.id))
      .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
      .where(and(eq(schema.accountTokens.accountId, accountId), eq(schema.accountTokens.isDefault, true)))
      .get();

    return {
      success: true,
      token: row
        ? (() => {
          if (isApiKeyConnection(row.accounts)) return null;
          const { token: rawToken, ...meta } = row.account_tokens;
          return { ...meta, tokenMasked: maskToken(rawToken, row.sites.platform) };
        })()
        : null,
    };
  });
}
