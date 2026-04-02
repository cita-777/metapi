import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import {
  getCredentialModeFromExtraConfig,
  hasOauthProvider,
  mergeAccountExtraConfig,
} from './accountExtraConfig.js';

export type RuntimeHealthState = 'healthy' | 'unhealthy' | 'degraded' | 'unknown' | 'disabled';

type RuntimeHealthInfo = {
  state: RuntimeHealthState;
  reason: string;
  source: string;
  checkedAt: string | null;
};

const VALID_RUNTIME_HEALTH_STATES = new Set<RuntimeHealthState>([
  'healthy',
  'unhealthy',
  'degraded',
  'unknown',
  'disabled',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function parseObject(value: string | Record<string, unknown> | null | undefined): Record<string, unknown> {
  if (!value) return {};
  if (isRecord(value)) return value;
  if (typeof value !== 'string') return {};
  try {
    const parsed = JSON.parse(value);
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function normalizeRuntimeHealthState(value: unknown): RuntimeHealthState | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  if (!VALID_RUNTIME_HEALTH_STATES.has(normalized as RuntimeHealthState)) return null;
  return normalized as RuntimeHealthState;
}

function normalizeRuntimeHealthRecord(raw: unknown): RuntimeHealthInfo | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const source = raw as Record<string, unknown>;
  const state = normalizeRuntimeHealthState(source.state);
  if (!state) return null;

  const reason = typeof source.reason === 'string'
    ? source.reason.trim().slice(0, 500)
    : '';
  const checkedAt = typeof source.checkedAt === 'string' && source.checkedAt.trim()
    ? source.checkedAt.trim()
    : null;
  const eventSource = typeof source.source === 'string' && source.source.trim()
    ? source.source.trim().slice(0, 64)
    : 'unknown';

  return {
    state,
    reason: reason || defaultHealthReason(state),
    source: eventSource,
    checkedAt,
  };
}

function defaultHealthReason(state: RuntimeHealthState): string {
  switch (state) {
    case 'healthy':
      return '运行状态正常';
    case 'unhealthy':
      return '最近一次检查失败';
    case 'degraded':
      return '运行状态波动';
    case 'disabled':
      return '账号或站点已禁用';
    case 'unknown':
    default:
      return '尚未检测';
  }
}

export function extractRuntimeHealth(extraConfig?: string | Record<string, unknown> | null): RuntimeHealthInfo | null {
  const parsed = parseObject(extraConfig);
  return normalizeRuntimeHealthRecord(parsed.runtimeHealth);
}

function isProxyOnlyAuthFailure(
  health: RuntimeHealthInfo | null,
  sessionCapable?: boolean,
): boolean {
  if (!health || sessionCapable !== false) return false;
  if (health.state !== 'unhealthy') return false;
  return (health.source || '').toLowerCase() === 'auth';
}

export function buildRuntimeHealthForAccount(input: {
  accountStatus?: string | null;
  siteStatus?: string | null;
  extraConfig?: string | Record<string, unknown> | null;
  sessionCapable?: boolean;
  hasDiscoveredModels?: boolean;
}): RuntimeHealthInfo {
  const accountStatus = (input.accountStatus || 'active').toLowerCase();
  const siteStatus = (input.siteStatus || 'active').toLowerCase();

  if (accountStatus === 'disabled' || siteStatus === 'disabled') {
    return {
      state: 'disabled',
      reason: defaultHealthReason('disabled'),
      source: 'system',
      checkedAt: null,
    };
  }

  if (accountStatus === 'expired') {
    const credentialMode = getCredentialModeFromExtraConfig(input.extraConfig);
    const usesOauthCredential = hasOauthProvider({ extraConfig: input.extraConfig });
    return {
      state: 'unhealthy',
      reason: usesOauthCredential
        ? '连接凭证已过期，请更新凭证'
        : credentialMode === 'apikey'
          ? '连接已过期，请更新 API Key'
          : (credentialMode === 'session'
            ? '访问令牌已过期'
            : '连接凭证已过期，请更新凭证'),
      source: 'auth',
      checkedAt: null,
    };
  }

  const stored = extractRuntimeHealth(input.extraConfig);
  const ignoreStoredProxyOnlyAuthFailure = isProxyOnlyAuthFailure(stored, input.sessionCapable);
  if (
    stored
    && !ignoreStoredProxyOnlyAuthFailure
    && !(input.sessionCapable === false && input.hasDiscoveredModels && stored.state === 'unknown')
  ) {
    return stored;
  }

  if (input.sessionCapable === false && input.hasDiscoveredModels) {
    return {
      state: 'healthy',
      reason: '模型探测成功',
      source: 'model-discovery',
      checkedAt: stored?.checkedAt || null,
    };
  }

  return {
    state: 'unknown',
    reason: defaultHealthReason('unknown'),
    source: 'none',
    checkedAt: null,
  };
}

function buildRuntimeHealthPatch(input: {
  state: RuntimeHealthState;
  reason?: string | null;
  source?: string | null;
  checkedAt?: string | null;
}): RuntimeHealthInfo {
  const state = normalizeRuntimeHealthState(input.state) || 'unknown';
  const reason = (input.reason || '').trim().slice(0, 500) || defaultHealthReason(state);
  const source = (input.source || '').trim().slice(0, 64) || 'manual';
  const checkedAt = (input.checkedAt || '').trim() || new Date().toISOString();

  return {
    state,
    reason,
    source,
    checkedAt,
  };
}

function applyRuntimeHealthToExtraConfig(extraConfig: string | null | undefined, health: RuntimeHealthInfo): string {
  return mergeAccountExtraConfig(extraConfig, {
    runtimeHealth: health,
  });
}

export async function setAccountRuntimeHealth(
  accountId: number,
  input: {
    state: RuntimeHealthState;
    reason?: string | null;
    source?: string | null;
    checkedAt?: string | null;
  },
): Promise<RuntimeHealthInfo | null> {
  try {
    const query = db.select().from(schema.accounts).where(eq(schema.accounts.id, accountId)) as any;
    const account = typeof query?.get === 'function' ? await query.get() : null;
    if (!account) return null;

    const health = buildRuntimeHealthPatch(input);
    const nextExtraConfig = applyRuntimeHealthToExtraConfig(account.extraConfig, health);

    await db.update(schema.accounts)
      .set({
        extraConfig: nextExtraConfig,
        updatedAt: new Date().toISOString(),
      })
      .where(eq(schema.accounts.id, accountId))
      .run();

    return health;
  } catch {
    return null;
  }
}
