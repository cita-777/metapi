import { eq } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { mergeAccountExtraConfig } from '../accountExtraConfig.js';
import { refreshModelsForAccount, rebuildTokenRoutesFromAvailability } from '../modelService.js';
import {
  buildCodexAuthorizationUrl,
  CODEX_LOOPBACK_REDIRECT_URI,
  CODEX_OAUTH_PROVIDER,
  CODEX_UPSTREAM_BASE_URL,
  exchangeCodexAuthorizationCode,
  refreshCodexTokens,
  type CodexTokenExchangeResult,
} from './codexProvider.js';
import {
  createOauthSession,
  getOauthSession,
  markOauthSessionError,
  markOauthSessionSuccess,
} from './sessionStore.js';
import { getCodexOauthInfoFromExtraConfig } from './codexAccount.js';
import { getCodexLoopbackCallbackServerState } from './localCallbackServer.js';

type OAuthProviderMetadata = {
  provider: string;
  label: string;
  platform: string;
  enabled: boolean;
  loginType: 'oauth';
};

const OAUTH_PROVIDER_LIST: OAuthProviderMetadata[] = [
  {
    provider: CODEX_OAUTH_PROVIDER,
    label: 'Codex',
    platform: 'codex',
    enabled: true,
    loginType: 'oauth',
  },
];

const CODEX_SITE_NAME = 'ChatGPT Codex OAuth';

function asNonEmptyString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function getHeaderValue(headers: Record<string, unknown> | undefined, key: string): string | undefined {
  if (!headers) return undefined;
  const loweredKey = key.toLowerCase();
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    if (rawKey.toLowerCase() !== loweredKey) continue;
    if (typeof rawValue === 'string') {
      const trimmed = rawValue.trim();
      if (trimmed) return trimmed;
    }
    if (Array.isArray(rawValue)) {
      for (const item of rawValue) {
        if (typeof item !== 'string') continue;
        const trimmed = item.trim();
        if (trimmed) return trimmed;
      }
    }
  }
  return undefined;
}

function buildUsername(exchange: CodexTokenExchangeResult): string {
  return exchange.email || exchange.accountId || 'codex-user';
}

async function getNextAccountSortOrder(): Promise<number> {
  const rows = await db.select({ sortOrder: schema.accounts.sortOrder }).from(schema.accounts).all();
  const max = rows.reduce((currentMax, row) => Math.max(currentMax, row.sortOrder || 0), -1);
  return max + 1;
}

async function getNextSiteSortOrder(): Promise<number> {
  const rows = await db.select({ sortOrder: schema.sites.sortOrder }).from(schema.sites).all();
  const max = rows.reduce((currentMax, row) => Math.max(currentMax, row.sortOrder || 0), -1);
  return max + 1;
}

async function ensureCodexSite() {
  const sites = await db.select().from(schema.sites).all();
  const existing = sites.find((site) => (
    String(site.platform || '').trim().toLowerCase() === 'codex'
    && String(site.url || '').trim() === CODEX_UPSTREAM_BASE_URL
  ));
  if (existing) return existing;

  return db.insert(schema.sites).values({
    name: CODEX_SITE_NAME,
    url: CODEX_UPSTREAM_BASE_URL,
    platform: 'codex',
    status: 'active',
    useSystemProxy: false,
    isPinned: false,
    globalWeight: 1,
    sortOrder: await getNextSiteSortOrder(),
  }).returning().get();
}

function matchesCodexIdentity(
  account: typeof schema.accounts.$inferSelect,
  exchange: CodexTokenExchangeResult,
): boolean {
  const oauth = getCodexOauthInfoFromExtraConfig(account.extraConfig);
  if (!oauth || oauth.provider !== CODEX_OAUTH_PROVIDER) return false;
  if (oauth.accountId && exchange.accountId) return oauth.accountId === exchange.accountId;
  if (oauth.email && exchange.email) return oauth.email === exchange.email;
  const username = asNonEmptyString(account.username);
  if (username && exchange.email) return username === exchange.email;
  return false;
}

async function findExistingCodexAccount(exchange: CodexTokenExchangeResult, rebindAccountId?: number) {
  if (typeof rebindAccountId === 'number' && rebindAccountId > 0) {
    return db.select().from(schema.accounts)
      .where(eq(schema.accounts.id, rebindAccountId))
      .get();
  }

  const accounts = await db.select().from(schema.accounts).all();
  return accounts.find((account) => matchesCodexIdentity(account, exchange)) || null;
}

async function upsertCodexAccount(exchange: CodexTokenExchangeResult, rebindAccountId?: number) {
  const site = await ensureCodexSite();
  const existing = await findExistingCodexAccount(exchange, rebindAccountId);
  const username = buildUsername(exchange);
  const extraConfig = mergeAccountExtraConfig(existing?.extraConfig, {
    credentialMode: 'session',
    oauth: {
      provider: CODEX_OAUTH_PROVIDER,
      accountId: exchange.accountId,
      email: exchange.email,
      planType: exchange.planType,
      refreshToken: exchange.refreshToken,
      idToken: exchange.idToken,
      tokenExpiresAt: exchange.tokenExpiresAt,
    },
  });

  if (existing) {
    await db.update(schema.accounts).set({
      siteId: site.id,
      username,
      accessToken: exchange.accessToken,
      apiToken: null,
      checkinEnabled: false,
      status: 'active',
      extraConfig,
      updatedAt: new Date().toISOString(),
    }).where(eq(schema.accounts.id, existing.id)).run();
    return {
      account: await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.id)).get(),
      site,
      created: false,
    };
  }

  const created = await db.insert(schema.accounts).values({
    siteId: site.id,
    username,
    accessToken: exchange.accessToken,
    apiToken: null,
    checkinEnabled: false,
    status: 'active',
    extraConfig,
    isPinned: false,
    sortOrder: await getNextAccountSortOrder(),
  }).returning().get();
  return { account: created, site, created: true };
}

export function listOauthProviders() {
  return OAUTH_PROVIDER_LIST;
}

export function startOauthProviderFlow(input: {
  provider: string;
  redirectOrigin: string;
  rebindAccountId?: number;
}) {
  if (input.provider !== CODEX_OAUTH_PROVIDER) {
    throw new Error(`unsupported oauth provider: ${input.provider}`);
  }
  const callbackServerState = getCodexLoopbackCallbackServerState();
  if (callbackServerState.attempted && !callbackServerState.ready) {
    throw new Error(`codex oauth callback listener is unavailable: ${callbackServerState.error || 'unknown error'}`);
  }
  const redirectUri = CODEX_LOOPBACK_REDIRECT_URI;
  const session = createOauthSession({
    provider: input.provider,
    redirectUri,
    rebindAccountId: input.rebindAccountId,
  });
  return {
    provider: input.provider,
    state: session.state,
    authorizationUrl: buildCodexAuthorizationUrl({
      state: session.state,
      redirectUri,
      codeVerifier: session.codeVerifier,
    }),
  };
}

export function getOauthSessionStatus(state: string) {
  const session = getOauthSession(state);
  if (!session) return null;
  return {
    provider: session.provider,
    state: session.state,
    status: session.status,
    accountId: session.accountId,
    siteId: session.siteId,
    error: session.error,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
  };
}

export async function handleOauthCallback(input: {
  provider: string;
  state: string;
  code?: string;
  error?: string;
}) {
  const session = getOauthSession(input.state);
  if (!session || session.provider !== input.provider) {
    throw new Error('oauth session not found or provider mismatch');
  }
  if (input.error) {
    markOauthSessionError(input.state, input.error);
    throw new Error(input.error);
  }
  const code = asNonEmptyString(input.code);
  if (!code) {
    markOauthSessionError(input.state, 'missing oauth code');
    throw new Error('missing oauth code');
  }

  const exchange = await exchangeCodexAuthorizationCode({
    code,
    codeVerifier: session.codeVerifier,
    redirectUri: session.redirectUri,
  });
  const { account, site, created } = await upsertCodexAccount(exchange, session.rebindAccountId) as Awaited<ReturnType<typeof upsertCodexAccount>> & { created: boolean };
  if (!account) {
    markOauthSessionError(input.state, 'failed to persist oauth account');
    throw new Error('failed to persist oauth account');
  }

  const refreshResult = await refreshModelsForAccount(account.id);
  if (refreshResult.status !== 'success') {
    if (created) {
      await db.delete(schema.accounts).where(eq(schema.accounts.id, account.id)).run();
    }
    await rebuildTokenRoutesFromAvailability();
    const errorMessage = refreshResult.errorMessage || 'codex model discovery failed';
    markOauthSessionError(input.state, errorMessage);
    throw new Error(errorMessage);
  }

  await rebuildTokenRoutesFromAvailability();
  markOauthSessionSuccess(input.state, {
    accountId: account.id,
    siteId: site.id,
  });
  return { accountId: account.id, siteId: site.id };
}

export async function listOauthConnections() {
  const rows = await db.select().from(schema.accounts)
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .all();
  const modelRows = await db.select({
    accountId: schema.modelAvailability.accountId,
    modelName: schema.modelAvailability.modelName,
  }).from(schema.modelAvailability)
    .where(eq(schema.modelAvailability.available, true))
    .all();
  const modelMap = new Map<number, string[]>();
  for (const row of modelRows) {
    if (typeof row.accountId !== 'number') continue;
    const list = modelMap.get(row.accountId) || [];
    list.push(row.modelName);
    modelMap.set(row.accountId, list);
  }
  const routeChannelRows = await db.select({
    accountId: schema.routeChannels.accountId,
  }).from(schema.routeChannels).all();
  const routeChannelCountByAccount = new Map<number, number>();
  for (const row of routeChannelRows) {
    const current = routeChannelCountByAccount.get(row.accountId) || 0;
    routeChannelCountByAccount.set(row.accountId, current + 1);
  }

  return rows
    .filter((row) => getCodexOauthInfoFromExtraConfig(row.accounts.extraConfig)?.provider === CODEX_OAUTH_PROVIDER)
    .map((row) => {
      const oauth = getCodexOauthInfoFromExtraConfig(row.accounts.extraConfig)!;
      const models = modelMap.get(row.accounts.id) || [];
      const status = (
        oauth.modelDiscoveryStatus === 'abnormal'
        || row.accounts.status !== 'active'
        || row.sites.status !== 'active'
      ) ? 'abnormal' : 'healthy';
      return {
        accountId: row.accounts.id,
        siteId: row.sites.id,
        provider: CODEX_OAUTH_PROVIDER,
        username: row.accounts.username,
        email: oauth.email,
        accountKey: oauth.accountId,
        planType: oauth.planType,
        modelCount: models.length,
        modelsPreview: models.slice(0, 10),
        status,
        routeChannelCount: routeChannelCountByAccount.get(row.accounts.id) || 0,
        lastModelSyncAt: oauth.lastModelSyncAt,
        lastModelSyncError: oauth.lastModelSyncError,
        site: {
          id: row.sites.id,
          name: row.sites.name,
          url: row.sites.url,
          platform: row.sites.platform,
        },
      };
    });
}

export async function deleteOauthConnection(accountId: number) {
  const account = await db.select().from(schema.accounts)
    .where(eq(schema.accounts.id, accountId))
    .get();
  if (!account) {
    throw new Error('oauth account not found');
  }
  const oauth = getCodexOauthInfoFromExtraConfig(account.extraConfig);
  if (!oauth) {
    throw new Error('account is not managed by oauth');
  }
  await db.delete(schema.accounts).where(eq(schema.accounts.id, accountId)).run();
  await rebuildTokenRoutesFromAvailability();
  return { success: true };
}

export async function startOauthRebindFlow(accountId: number, redirectOrigin: string) {
  const account = await db.select().from(schema.accounts)
    .where(eq(schema.accounts.id, accountId))
    .get();
  if (!account) {
    throw new Error('oauth account not found');
  }
  const oauth = getCodexOauthInfoFromExtraConfig(account.extraConfig);
  if (!oauth) {
    throw new Error('account is not managed by oauth');
  }
  return startOauthProviderFlow({
    provider: oauth.provider,
    redirectOrigin,
    rebindAccountId: accountId,
  });
}

export function buildCodexOauthProviderHeaders(input: {
  extraConfig?: string | null;
  downstreamHeaders?: Record<string, unknown>;
}) {
  const oauth = getCodexOauthInfoFromExtraConfig(input.extraConfig);
  if (!oauth) return {};

  const accountId = getHeaderValue(input.downstreamHeaders, 'chatgpt-account-id') || oauth.accountId;
  const originator = getHeaderValue(input.downstreamHeaders, 'originator') || 'codex_cli_rs';
  const headers: Record<string, string> = {
    Originator: originator,
  };
  if (accountId) {
    headers['Chatgpt-Account-Id'] = accountId;
  }
  return headers;
}

export async function refreshCodexOauthAccessToken(accountId: number) {
  const account = await db.select().from(schema.accounts)
    .where(eq(schema.accounts.id, accountId))
    .get();
  if (!account) {
    throw new Error('codex oauth account not found');
  }
  const oauth = getCodexOauthInfoFromExtraConfig(account.extraConfig);
  if (!oauth?.refreshToken) {
    throw new Error('codex oauth refresh token missing');
  }

  const refreshed = await refreshCodexTokens(oauth.refreshToken);
  const extraConfig = mergeAccountExtraConfig(account.extraConfig, {
    credentialMode: 'session',
    oauth: {
      provider: CODEX_OAUTH_PROVIDER,
      accountId: refreshed.accountId || oauth.accountId,
      email: refreshed.email || oauth.email,
      planType: refreshed.planType || oauth.planType,
      refreshToken: refreshed.refreshToken,
      idToken: refreshed.idToken,
      tokenExpiresAt: refreshed.tokenExpiresAt,
    },
  });

  await db.update(schema.accounts).set({
    accessToken: refreshed.accessToken,
    extraConfig,
    status: 'active',
    updatedAt: new Date().toISOString(),
  }).where(eq(schema.accounts.id, accountId)).run();

  return {
    accountId,
    accessToken: refreshed.accessToken,
    accountKey: refreshed.accountId || oauth.accountId,
    extraConfig,
  };
}
