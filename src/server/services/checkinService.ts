import { db, schema } from '../db/index.js';
import { getAdapter } from './platforms/index.js';
import { eq, and } from 'drizzle-orm';
import { sendNotification } from './notifyService.js';
import { isCloudflareChallenge, isTokenExpiredError } from './alertRules.js';
import { reportTokenExpired } from './alertService.js';
import { refreshBalance } from './balanceService.js';
import { parseCheckinRewardAmount } from './checkinRewardParser.js';
import {
  getAutoReloginConfig,
  getPlatformUserIdFromExtraConfig,
  guessPlatformUserIdFromUsername,
  mergeAccountExtraConfig,
  resolveProxyUrlFromExtraConfig,
  resolvePlatformUserId,
} from './accountExtraConfig.js';
import { decryptAccountPassword } from './accountCredentialService.js';
import { setAccountRuntimeHealth } from './accountHealthService.js';
import { formatUtcSqlDateTime } from './localTimeService.js';
import { withAccountProxyOverride } from './siteProxy.js';

type CheckinExecutionStatus = 'success' | 'failed' | 'skipped';

function isSiteDisabled(status?: string | null): boolean {
  return (status || 'active') === 'disabled';
}

function isAlreadyCheckedInMessage(message?: string | null): boolean {
  if (!message) return false;
  const text = message.trim();
  if (!text) return false;
  const normalized = text.toLowerCase();
  return (
    normalized.includes('already checked in') ||
    normalized.includes('already signed') ||
    normalized.includes('already sign in') ||
    text.includes('\u4eca\u65e5\u5df2\u7b7e\u5230') ||
    text.includes('\u4eca\u5929\u5df2\u7b7e\u5230') ||
    text.includes('\u4eca\u5929\u5df2\u7ecf\u7b7e\u5230') ||
    text.includes('\u4eca\u65e5\u5df2\u7ecf\u7b7e\u5230') ||
    text.includes('\u5df2\u7ecf\u7b7e\u5230') ||
    text.includes('\u5df2\u7b7e\u5230') ||
    text.includes('\u91cd\u590d\u7b7e\u5230') ||
    text.includes('\u7b7e\u5230\u8fc7')
  );
}

function isUnsupportedCheckinMessage(message?: string | null): boolean {
  if (!message) return false;
  const text = message.toLowerCase();
  return (
    text.includes('invalid url (post /api/user/checkin)') ||
    (text.includes('http 404') && text.includes('/api/user/checkin')) ||
    text.includes('checkin endpoint not found') ||
    text.includes('check-in is not supported') ||
    text.includes('checkin is not supported') ||
    text.includes('does not support checkin') ||
    text.includes('not support checkin')
  );
}

function isManualVerificationRequiredMessage(message?: string | null): boolean {
  if (!message) return false;
  const text = message.toLowerCase();
  return (
    text.includes('turnstile token \u4e3a\u7a7a') ||
    (text.includes('turnstile') && (text.includes('token') || text.includes('\u6821\u9a8c') || text.includes('\u9a8c\u8bc1')))
  );
}

function shouldAttemptAutoRelogin(message?: string | null): boolean {
  if (!message) return false;
  if (isTokenExpiredError({ message })) return true;

  const text = message.toLowerCase();
  if (text.includes('new-api-user')) return true;
  if (text.includes('access token')) return true;
  return false;
}

function inferRewardFromBalanceDelta(previousBalance: unknown, latestBalance: unknown): number {
  const before = typeof previousBalance === 'number' && Number.isFinite(previousBalance)
    ? previousBalance
    : null;
  const after = typeof latestBalance === 'number' && Number.isFinite(latestBalance)
    ? latestBalance
    : null;
  if (before == null || after == null) return 0;

  const delta = after - before;
  if (!Number.isFinite(delta) || delta <= 0) return 0;
  return Math.round(delta * 1_000_000) / 1_000_000;
}

async function tryAutoRelogin(account: any, site: any): Promise<string | null> {
  const adapter = getAdapter(site.platform);
  if (!adapter) return null;

  const relogin = getAutoReloginConfig(account.extraConfig);
  if (!relogin) return null;

  const password = decryptAccountPassword(relogin.passwordCipher);
  if (!password) return null;

  const result = await withAccountProxyOverride(
    resolveProxyUrlFromExtraConfig(account.extraConfig),
    () => adapter.login(site.url, relogin.username, password),
  );
  if (!result.success || !result.accessToken) return null;

  await db.update(schema.accounts)
    .set({
      accessToken: result.accessToken,
      updatedAt: new Date().toISOString(),
      status: account.status === 'expired' ? 'active' : account.status,
    })
    .where(eq(schema.accounts.id, account.id))
    .run();

  return result.accessToken;
}

export async function checkinAccount(accountId: number, options?: { skipEvent?: boolean; scheduleMode?: 'cron' | 'interval' }) {
  const rows = await db
    .select()
    .from(schema.accounts)
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(eq(schema.accounts.id, accountId))
    .all();

  if (rows.length === 0) return { success: false, message: 'account not found' };

  const account = rows[0].accounts;
  const site = rows[0].sites;

  if (isSiteDisabled(site.status)) {
    const createdAt = formatUtcSqlDateTime(new Date());
    setAccountRuntimeHealth(account.id, {
      state: 'disabled',
      reason: '\u7ad9\u70b9\u5df2\u7981\u7528',
      source: 'checkin',
    });
    await db.insert(schema.checkinLogs).values({
      accountId: account.id,
      status: 'skipped',
      message: 'site disabled',
      createdAt,
    }).run();

    if (!options?.skipEvent) {
      await db.insert(schema.events).values({
        type: 'checkin',
        title: 'checkin skipped',
        message: `${account.username || 'ID:' + accountId} @ ${site.name}: site disabled`,
        level: 'info',
        relatedId: accountId,
        relatedType: 'account',
        createdAt,
      }).run();
    }

    return {
      success: true,
      status: 'skipped' as const,
      skipped: true,
      reason: 'site_disabled',
      message: 'site disabled',
    };
  }

  const adapter = getAdapter(site.platform);
  if (!adapter) return { success: false, status: 'failed' as const, message: `unsupported platform: ${site.platform}` };

  const storedPlatformUserId = getPlatformUserIdFromExtraConfig(account.extraConfig);
  const guessedPlatformUserId = storedPlatformUserId
    ? undefined
    : guessPlatformUserIdFromUsername(account.username);
  const platformUserId = resolvePlatformUserId(account.extraConfig, account.username);

  const accountProxyUrl = resolveProxyUrlFromExtraConfig(account.extraConfig);
  let activeAccessToken = account.accessToken;
  let result = await withAccountProxyOverride(accountProxyUrl,
    () => adapter.checkin(site.url, activeAccessToken, platformUserId));

  if (!result.success && shouldAttemptAutoRelogin(result.message)) {
    const refreshedAccessToken = await tryAutoRelogin(account, site);
    if (refreshedAccessToken) {
      activeAccessToken = refreshedAccessToken;
      result = await withAccountProxyOverride(accountProxyUrl,
        () => adapter.checkin(site.url, activeAccessToken, platformUserId));
    }
  }

  const isCloudflare = isCloudflareChallenge(result.message);
  const alreadyCheckedIn = isAlreadyCheckedInMessage(result.message);
  const unsupportedCheckin = isUnsupportedCheckinMessage(result.message);
  const manualVerificationRequired = isManualVerificationRequiredMessage(result.message);
  const manualVerificationMessage = '\u7ad9\u70b9\u5f00\u542f\u4e86 Turnstile \u6821\u9a8c\uff0c\u9700\u8981\u4eba\u5de5\u7b7e\u5230';
  const logMessage = manualVerificationRequired ? manualVerificationMessage : result.message;
  const effectiveSuccess = result.success || alreadyCheckedIn || unsupportedCheckin || manualVerificationRequired;
  const shouldRefreshBalance = result.success || alreadyCheckedIn;
  const directCheckinSuccess = result.success && !alreadyCheckedIn && !unsupportedCheckin;
  const shouldAdvanceLastCheckinAt = directCheckinSuccess || (alreadyCheckedIn && options?.scheduleMode !== 'interval');
  const normalizedStatus: CheckinExecutionStatus = effectiveSuccess
    ? ((unsupportedCheckin || manualVerificationRequired) ? 'skipped' : 'success')
    : 'failed';
  let logReward = result.reward;
  let refreshedBalanceInfo: Awaited<ReturnType<typeof refreshBalance>> | null = null;

  if (effectiveSuccess) {
    const healthState = (unsupportedCheckin || manualVerificationRequired) ? 'degraded' : 'healthy';
    const healthReason = unsupportedCheckin
      ? '\u7ad9\u70b9\u4e0d\u652f\u6301\u7b7e\u5230\u63a5\u53e3'
      : manualVerificationRequired
        ? manualVerificationMessage
      : (alreadyCheckedIn ? '\u4eca\u65e5\u5df2\u7b7e\u5230' : (result.message || '\u7b7e\u5230\u6210\u529f'));
    setAccountRuntimeHealth(account.id, {
      state: healthState,
      reason: healthReason,
      source: 'checkin',
    });

    const updates: Record<string, unknown> = {};
    if (shouldAdvanceLastCheckinAt) {
      updates.lastCheckinAt = new Date().toISOString();
    }
    if (!storedPlatformUserId && guessedPlatformUserId) {
      updates.extraConfig = mergeAccountExtraConfig(account.extraConfig, {
        platformUserId: guessedPlatformUserId,
      });
    }
    if (account.status === 'expired') {
      updates.status = 'active';
      updates.updatedAt = new Date().toISOString();
    }

    if (Object.keys(updates).length > 0) {
      await db.update(schema.accounts)
        .set(updates)
        .where(eq(schema.accounts.id, accountId))
        .run();
    }

    if (shouldRefreshBalance) {
      try {
        refreshedBalanceInfo = await refreshBalance(account.id);
      } catch {}
    }

    const parsedReward = parseCheckinRewardAmount(logReward) || parseCheckinRewardAmount(result.message);
    if (directCheckinSuccess && parsedReward <= 0) {
      const inferredReward = inferRewardFromBalanceDelta(account.balance, refreshedBalanceInfo?.balance);
      if (inferredReward > 0) {
        logReward = inferredReward.toString();
      }
    }
  }

  const createdAt = formatUtcSqlDateTime(new Date());
  await db.insert(schema.checkinLogs).values({
    accountId: account.id,
    status: normalizedStatus,
    message: logMessage,
    reward: logReward,
    createdAt,
  }).run();

  if (!options?.skipEvent) {
    await db.insert(schema.events).values({
      type: 'checkin',
      title: effectiveSuccess
        ? (normalizedStatus === 'skipped' ? 'checkin skipped' : 'checkin success')
        : (isCloudflare ? 'checkin failed (cloudflare challenge)' : 'checkin failed'),
      message: `${account.username || 'ID:' + accountId} @ ${site.name}: ${logMessage}`,
      level: effectiveSuccess ? 'info' : 'error',
      relatedId: accountId,
      relatedType: 'account',
      createdAt,
    }).run();
  }

  if (!effectiveSuccess) {
    setAccountRuntimeHealth(account.id, {
      state: 'unhealthy',
      reason: result.message || '\u7b7e\u5230\u5931\u8d25',
      source: 'checkin',
    });
    if (isTokenExpiredError({ message: result.message })) {
      await reportTokenExpired({
        accountId: account.id,
        username: account.username,
        siteName: site.name,
        detail: result.message,
      });
    }

    if (isCloudflare) {
      await sendNotification(
        'Cloudflare challenge',
        `${account.username || 'ID:' + accountId} @ ${site.name}: ${result.message}`,
        'warning',
      );
    }

    if (!unsupportedCheckin && !manualVerificationRequired) {
      await sendNotification(
        'checkin failed',
        `${account.username || 'ID:' + accountId} @ ${site.name}: ${result.message}`,
        'error',
      );
    }
  }


  return {
    ...result,
    success: effectiveSuccess,
    status: normalizedStatus,
    ...(normalizedStatus === 'skipped' ? { skipped: true } : {}),
  };
}

export async function checkinAll(options?: { accountIds?: number[]; scheduleMode?: 'cron' | 'interval' }) {
  const rows = await db
    .select()
    .from(schema.accounts)
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(
      and(
        eq(schema.accounts.checkinEnabled, true),
        eq(schema.accounts.status, 'active'),
      ),
    )
    .all();

  const scopedAccountIds = options?.accountIds ? new Set(options.accountIds) : null;
  const results: Array<{ accountId: number; username: string | null; site: string; result: any }> = [];

  const grouped = new Map<number, typeof rows>();
  for (const row of rows) {
    if (scopedAccountIds && !scopedAccountIds.has(row.accounts.id)) continue;
    const siteId = row.sites.id;
    if (!grouped.has(siteId)) grouped.set(siteId, []);
    grouped.get(siteId)!.push(row);
  }

  const promises = Array.from(grouped.entries()).map(async ([_, siteRows]) => {
    for (const row of siteRows) {
      const r = await checkinAccount(row.accounts.id, {
        skipEvent: true,
        scheduleMode: options?.scheduleMode,
      });
      results.push({
        accountId: row.accounts.id,
        username: row.accounts.username,
        site: row.sites.name,
        result: r,
      });
    }
  });

  await Promise.all(promises);
  return results;
}
