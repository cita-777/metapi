import { and, desc, eq, inArray, isNull, or, sql } from 'drizzle-orm';
import { db, schema } from '../../db/index.js';
import { insertAndGetById } from '../../db/insertHelpers.js';
import { getProxyUrlFromExtraConfig, mergeAccountExtraConfig } from '../accountExtraConfig.js';
import { refreshModelsForAccount } from '../modelService.js';
import * as routeRefreshWorkflow from '../routeRefreshWorkflow.js';
import {
  createOauthSession,
  getOauthSession,
  markOauthSessionError,
  markOauthSessionSuccess,
} from './sessionStore.js';
import { getOAuthLoopbackCallbackServerState } from './localCallbackServer.js';
import {
  getOAuthProviderDefinition,
  listOAuthProviderDefinitions,
  type OAuthProviderDefinition,
} from './providers.js';
import { ensureOauthProviderSite } from './oauthSiteRegistry.js';
import {
  buildOauthInfo,
  buildOauthInfoFromAccount,
  buildStoredOauthState,
  buildStoredOauthStateFromAccount,
  getOauthInfoFromAccount,
  type OauthInfo,
} from './oauthAccount.js';
import {
  buildCodexOauthInfo,
  type OauthExtraConfigInput,
  type OauthIdentityCarrierLike,
} from './codexAccount.js';
import { resolveOauthAccountProxyUrl, resolveOauthProviderProxyUrl } from './requestProxy.js';
import { ensureOauthIdentityBackfill } from './oauthIdentityBackfill.js';
import { buildQuotaSnapshotFromOauthInfo, refreshOauthQuotaSnapshot } from './quota.js';

type OAuthProviderMetadata = ReturnType<typeof listOauthProviders>[number];
const MANUAL_CALLBACK_DELAY_MS = 15_000;
type OauthProviderHeaderAccountInput = OauthIdentityCarrierLike & {
  extraConfig?: OauthExtraConfigInput;
};

type OAuthStartInstructions = {
  redirectUri: string;
  callbackPort: number;
  callbackPath: string;
  manualCallbackDelayMs: number;
  sshTunnelCommand?: string;
  sshTunnelKeyCommand?: string;
};

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase();
  return normalized === 'localhost'
    || normalized === '127.0.0.1'
    || normalized === '::1'
    || normalized === '[::1]';
}

function resolveSshTunnelHost(requestOrigin?: string): string | undefined {
  if (!requestOrigin) return undefined;
  try {
    const parsed = new URL(requestOrigin);
    if (!parsed.hostname || isLoopbackHost(parsed.hostname)) {
      return undefined;
    }
    return parsed.hostname;
  } catch {
    return undefined;
  }
}

function buildLoopbackInstructions(
  definition: OAuthProviderDefinition,
  requestOrigin?: string,
): OAuthStartInstructions {
  const sshHost = resolveSshTunnelHost(requestOrigin);
  return {
    redirectUri: definition.loopback.redirectUri,
    callbackPort: definition.loopback.port,
    callbackPath: definition.loopback.path,
    manualCallbackDelayMs: MANUAL_CALLBACK_DELAY_MS,
    sshTunnelCommand: sshHost
      ? `ssh -L ${definition.loopback.port}:127.0.0.1:${definition.loopback.port} root@${sshHost} -p 22`
      : undefined,
    sshTunnelKeyCommand: sshHost
      ? `ssh -i <path_to_your_key> -L ${definition.loopback.port}:127.0.0.1:${definition.loopback.port} root@${sshHost} -p 22`
      : undefined,
  };
}

function parseManualCallbackUrl(input: {
  callbackUrl: string;
  provider: string;
}) {
  const raw = asNonEmptyString(input.callbackUrl);
  if (!raw) {
    throw new Error('invalid oauth callback url');
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('invalid oauth callback url');
  }

  const state = asNonEmptyString(parsed.searchParams.get('state'));
  const code = asNonEmptyString(parsed.searchParams.get('code'));
  const error = asNonEmptyString(parsed.searchParams.get('error'));
  const errorDescription = asNonEmptyString(parsed.searchParams.get('error_description'));
  if (!state || (!code && !error)) {
    throw new Error('invalid oauth callback url');
  }

  return {
    state,
    code,
    error: error
      ? (errorDescription ? `${error}: ${errorDescription}` : error)
      : undefined,
  };
}

function asNonEmptyString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function buildUsername(input: {
  email?: string;
  accountKey?: string;
  provider: string;
}) {
  return input.email || input.accountKey || `${input.provider}-user`;
}

async function getNextAccountSortOrder(): Promise<number> {
  const row = await db.select({
    maxSortOrder: sql<number>`COALESCE(MAX(${schema.accounts.sortOrder}), -1)`,
  }).from(schema.accounts).get();
  return (row?.maxSortOrder ?? -1) + 1;
}

async function ensureOauthSite(definition: OAuthProviderDefinition) {
  return ensureOauthProviderSite(definition);
}

async function findExistingOauthAccount(input: {
  provider: string;
  accountKey?: string;
  email?: string;
  projectId?: string;
  rebindAccountId?: number;
}) {
  if (typeof input.rebindAccountId === 'number' && input.rebindAccountId > 0) {
    return db.select().from(schema.accounts)
      .where(eq(schema.accounts.id, input.rebindAccountId))
      .get();
  }

  const accountKey = asNonEmptyString(input.accountKey);
  const email = asNonEmptyString(input.email);
  const projectId = asNonEmptyString(input.projectId);

  if (accountKey) {
    const byKey = await db.select().from(schema.accounts).where(and(
      eq(schema.accounts.oauthProvider, input.provider),
      eq(schema.accounts.oauthAccountKey, accountKey),
      projectId
        ? eq(schema.accounts.oauthProjectId, projectId)
        : or(isNull(schema.accounts.oauthProjectId), eq(schema.accounts.oauthProjectId, '')),
    )).get();
    if (byKey) return byKey;
  }

  if (!accountKey && email && input.provider !== 'codex') {
    const byEmail = await db.select().from(schema.accounts).where(and(
      eq(schema.accounts.oauthProvider, input.provider),
      eq(schema.accounts.username, email),
    )).get();
    if (byEmail) return byEmail;
  }

  return null;
}

async function upsertOauthAccount(input: {
  definition: OAuthProviderDefinition;
  exchange: {
    accessToken: string;
    refreshToken?: string;
    tokenExpiresAt?: number;
    email?: string;
    accountKey?: string;
    accountId?: string;
    planType?: string;
    projectId?: string;
    idToken?: string;
    providerData?: Record<string, unknown>;
  };
  rebindAccountId?: number;
  proxyUrl?: string | null;
}) {
  const site = await ensureOauthSite(input.definition);
  const existing = await findExistingOauthAccount({
    provider: input.definition.metadata.provider,
    accountKey: input.exchange.accountKey || input.exchange.accountId,
    email: input.exchange.email,
    projectId: input.exchange.projectId,
    rebindAccountId: input.rebindAccountId,
  });
  const username = buildUsername({
    email: input.exchange.email,
    accountKey: input.exchange.accountKey || input.exchange.accountId,
    provider: input.definition.metadata.provider,
  });
  const oauth = buildOauthInfo(existing?.extraConfig, {
    provider: input.definition.metadata.provider,
    accountId: input.exchange.accountId || input.exchange.accountKey,
    accountKey: input.exchange.accountKey || input.exchange.accountId,
    email: input.exchange.email,
    planType: input.exchange.planType,
    projectId: input.exchange.projectId,
    refreshToken: input.exchange.refreshToken,
    tokenExpiresAt: input.exchange.tokenExpiresAt,
    idToken: input.exchange.idToken,
    providerData: input.exchange.providerData,
  });
  const extraConfig = mergeAccountExtraConfig(existing?.extraConfig, {
    credentialMode: 'session',
    ...(input.proxyUrl !== undefined ? { proxyUrl: input.proxyUrl } : {}),
    oauth: buildStoredOauthState(oauth),
  });

  if (existing) {
    await db.update(schema.accounts).set({
      siteId: site.id,
      username,
      accessToken: input.exchange.accessToken,
      apiToken: null,
      checkinEnabled: false,
      status: 'disabled',
      oauthProvider: input.definition.metadata.provider,
      oauthAccountKey: oauth.accountKey || oauth.accountId || null,
      oauthProjectId: oauth.projectId || null,
      extraConfig,
      updatedAt: new Date().toISOString(),
    }).where(eq(schema.accounts.id, existing.id)).run();
    return {
      account: await db.select().from(schema.accounts).where(eq(schema.accounts.id, existing.id)).get(),
      site,
      created: false,
      previousAccount: existing,
    };
  }

  const created = await insertAndGetById<typeof schema.accounts.$inferSelect>({
    table: schema.accounts,
    idColumn: schema.accounts.id,
    values: {
      siteId: site.id,
      username,
      accessToken: input.exchange.accessToken,
      apiToken: null,
      checkinEnabled: false,
      status: 'active',
      oauthProvider: input.definition.metadata.provider,
      oauthAccountKey: oauth.accountKey || oauth.accountId || null,
      oauthProjectId: oauth.projectId || null,
      extraConfig,
      isPinned: false,
      sortOrder: await getNextAccountSortOrder(),
    },
    insertErrorMessage: `failed to create oauth account: ${input.definition.metadata.provider}`,
    loadErrorMessage: `failed to load created oauth account: ${input.definition.metadata.provider}`,
  });
  return { account: created, site, created: true, previousAccount: null };
}

export function listOauthProviders() {
  return listOAuthProviderDefinitions().map((definition) => {
    const state = getOAuthLoopbackCallbackServerState(definition.metadata.provider);
    return {
      ...definition.metadata,
      enabled: state.ready || !state.attempted,
    };
  });
}

export async function startOauthProviderFlow(input: {
  provider: string;
  rebindAccountId?: number;
  projectId?: string;
  proxyUrl?: string | null;
  requestOrigin?: string;
}) {
  const definition = getOAuthProviderDefinition(input.provider);
  if (!definition) {
    throw new Error(`unsupported oauth provider: ${input.provider}`);
  }
  const redirectUri = definition.loopback.redirectUri;
  const callbackServerState = getOAuthLoopbackCallbackServerState(input.provider);
  if (callbackServerState.attempted && !callbackServerState.ready) {
    throw new Error(`${input.provider} oauth callback listener is unavailable: ${callbackServerState.error || 'unknown error'}`);
  }
  const session = createOauthSession({
    provider: input.provider,
    redirectUri,
    rebindAccountId: input.rebindAccountId,
    projectId: input.projectId,
    proxyUrl: input.proxyUrl,
  });
  return {
    provider: input.provider,
    state: session.state,
    authorizationUrl: await definition.buildAuthorizationUrl({
      state: session.state,
      redirectUri: session.redirectUri,
      codeVerifier: session.codeVerifier,
      projectId: session.projectId,
    }),
    instructions: buildLoopbackInstructions(definition, input.requestOrigin),
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
  const definition = getOAuthProviderDefinition(input.provider);
  if (!definition) {
    markOauthSessionError(input.state, `unsupported oauth provider: ${input.provider}`);
    throw new Error(`unsupported oauth provider: ${input.provider}`);
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

  try {
    const resolvedProxyUrl = session.proxyUrl == null
      ? await resolveOauthProviderProxyUrl(input.provider)
      : session.proxyUrl;
    const exchange = await definition.exchangeAuthorizationCode({
      code,
      state: input.state,
      redirectUri: session.redirectUri,
      codeVerifier: session.codeVerifier,
      projectId: session.projectId,
      proxyUrl: resolvedProxyUrl,
    });
    const { account, site, created, previousAccount } = await upsertOauthAccount({
      definition,
      exchange,
      rebindAccountId: session.rebindAccountId,
      proxyUrl: session.proxyUrl,
    });
    if (!account) {
      markOauthSessionError(input.state, 'failed to persist oauth account');
      throw new Error('failed to persist oauth account');
    }

    const refreshResult = await refreshModelsForAccount(
      account.id,
      previousAccount ? { allowInactive: true } : undefined,
    );
    if (refreshResult.status !== 'success') {
      if (created) {
        await db.delete(schema.accounts).where(eq(schema.accounts.id, account.id)).run();
      } else if (previousAccount) {
        await db.update(schema.accounts).set({
          siteId: previousAccount.siteId,
          username: previousAccount.username,
          accessToken: previousAccount.accessToken,
          apiToken: previousAccount.apiToken,
          checkinEnabled: previousAccount.checkinEnabled,
          status: previousAccount.status,
          oauthProvider: previousAccount.oauthProvider,
          oauthAccountKey: previousAccount.oauthAccountKey,
          oauthProjectId: previousAccount.oauthProjectId,
          extraConfig: previousAccount.extraConfig,
          updatedAt: previousAccount.updatedAt,
        }).where(eq(schema.accounts.id, previousAccount.id)).run();
      }
      await routeRefreshWorkflow.rebuildRoutesOnly();
      const errorMessage = refreshResult.errorMessage || `${input.provider} model discovery failed`;
      markOauthSessionError(input.state, errorMessage);
      throw new Error(errorMessage);
    }

    if (previousAccount) {
      await db.update(schema.accounts).set({
        status: 'active',
        updatedAt: new Date().toISOString(),
      }).where(eq(schema.accounts.id, account.id)).run();
    }

    await routeRefreshWorkflow.rebuildRoutesOnly();
    markOauthSessionSuccess(input.state, {
      accountId: account.id,
      siteId: site.id,
    });
    return { accountId: account.id, siteId: site.id };
  } catch (error) {
    const message = (
      error instanceof Error
        ? (error.message || error.name)
        : String(error || 'OAuth failed')
    ).trim() || 'OAuth failed';
    markOauthSessionError(input.state, message);
    throw error;
  }
}

export async function submitOauthManualCallback(input: {
  state: string;
  callbackUrl: string;
}) {
  const session = getOauthSession(input.state);
  if (!session) {
    throw new Error('oauth session not found');
  }
  const parsed = parseManualCallbackUrl({
    callbackUrl: input.callbackUrl,
    provider: session.provider,
  });
  if (parsed.state !== input.state) {
    throw new Error('oauth callback state mismatch');
  }

  await handleOauthCallback({
    provider: session.provider,
    state: parsed.state,
    code: parsed.code,
    error: parsed.error,
  });

  return { success: true };
}

export async function listOauthConnections(options: {
  limit?: number;
  offset?: number;
} = {}) {
  await ensureOauthIdentityBackfill();
  const limit = Math.max(1, Math.min(200, Math.trunc(options.limit ?? 50)));
  const offset = Math.max(0, Math.trunc(options.offset ?? 0));

  const totalRow = await db.select({
    count: sql<number>`COUNT(*)`,
  }).from(schema.accounts)
    .where(sql`${schema.accounts.oauthProvider} IS NOT NULL`)
    .get();
  const total = totalRow?.count ?? 0;

  const rows = await db.select().from(schema.accounts)
    .innerJoin(schema.sites, eq(schema.accounts.siteId, schema.sites.id))
    .where(sql`${schema.accounts.oauthProvider} IS NOT NULL`)
    .orderBy(desc(schema.accounts.id))
    .limit(limit)
    .offset(offset)
    .all();

  const accountIds = rows.map((row) => row.accounts.id);
  if (accountIds.length <= 0) {
    return { items: [], total, limit, offset };
  }

  const modelRows = await db.select({
    accountId: schema.modelAvailability.accountId,
    modelName: schema.modelAvailability.modelName,
  }).from(schema.modelAvailability)
    .where(and(
      inArray(schema.modelAvailability.accountId, accountIds),
      eq(schema.modelAvailability.available, true),
    ))
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
    count: sql<number>`COUNT(*)`,
  }).from(schema.routeChannels)
    .where(inArray(schema.routeChannels.accountId, accountIds))
    .groupBy(schema.routeChannels.accountId)
    .all();
  const routeChannelCountByAccount = new Map<number, number>();
  for (const row of routeChannelRows) {
    routeChannelCountByAccount.set(row.accountId, row.count ?? 0);
  }

  const items = rows.flatMap((row) => {
    const oauth = getOauthInfoFromAccount(row.accounts);
    if (!oauth) return [];
    const models = modelMap.get(row.accounts.id) || [];
    const status = (
      oauth.modelDiscoveryStatus === 'abnormal'
      || row.accounts.status !== 'active'
      || row.sites.status !== 'active'
    ) ? 'abnormal' : 'healthy';
    return [{
      accountId: row.accounts.id,
      siteId: row.sites.id,
      provider: oauth.provider,
      username: row.accounts.username,
      email: oauth.email,
      accountKey: oauth.accountKey || oauth.accountId,
      planType: oauth.planType,
      projectId: oauth.projectId,
      modelCount: models.length,
      modelsPreview: models.slice(0, 10),
      quota: buildQuotaSnapshotFromOauthInfo(oauth),
      status,
      routeChannelCount: routeChannelCountByAccount.get(row.accounts.id) || 0,
      lastModelSyncAt: oauth.lastModelSyncAt,
      lastModelSyncError: oauth.lastModelSyncError,
      proxyUrl: getProxyUrlFromExtraConfig(row.accounts.extraConfig),
      site: {
        id: row.sites.id,
        name: row.sites.name,
        url: row.sites.url,
        platform: row.sites.platform,
      },
    }];
  });

  return { items, total, limit, offset };
}

export async function deleteOauthConnection(accountId: number) {
  const account = await db.select().from(schema.accounts)
    .where(eq(schema.accounts.id, accountId))
    .get();
  if (!account) {
    throw new Error('oauth account not found');
  }
  const normalizedOauth = getOauthInfoFromAccount(account);
  if (!normalizedOauth) {
    throw new Error('account is not managed by oauth');
  }
  await db.delete(schema.accounts).where(eq(schema.accounts.id, accountId)).run();
  await routeRefreshWorkflow.rebuildRoutesOnly();
  return { success: true };
}

export async function refreshOauthConnectionQuota(accountId: number) {
  const quota = await refreshOauthQuotaSnapshot(accountId);
  return { success: true, quota };
}

export async function startOauthRebindFlow(
  accountId: number,
  options?: { requestOrigin?: string; proxyUrl?: string | null },
) {
  const { requestOrigin, proxyUrl } = options ?? {};
  const account = await db.select().from(schema.accounts)
    .where(eq(schema.accounts.id, accountId))
    .get();
  if (!account) {
    throw new Error('oauth account not found');
  }
  const oauth = getOauthInfoFromAccount(account);
  if (!oauth) {
    throw new Error('account is not managed by oauth');
  }
  return startOauthProviderFlow({
    provider: oauth.provider,
    rebindAccountId: accountId,
    projectId: oauth.projectId,
    proxyUrl: proxyUrl !== undefined
      ? proxyUrl
      : (getProxyUrlFromExtraConfig(account.extraConfig) ?? undefined),
    requestOrigin,
  });
}

export function buildOauthProviderHeaders(input: {
  account?: OauthProviderHeaderAccountInput | null;
  extraConfig?: OauthExtraConfigInput;
  downstreamHeaders?: Record<string, unknown>;
}) {
  const oauth = getOauthInfoFromAccount(input.account || {
    extraConfig: input.extraConfig,
  });
  if (!oauth) return {};
  const definition = getOAuthProviderDefinition(oauth.provider);
  if (!definition?.buildProxyHeaders) return {};
  return definition.buildProxyHeaders({
    oauth,
    downstreamHeaders: input.downstreamHeaders,
  });
}

export function buildCodexOauthProviderHeaders(input: {
  extraConfig?: OauthExtraConfigInput;
  downstreamHeaders?: Record<string, unknown>;
}) {
  const oauth = buildCodexOauthInfo(input.extraConfig);
  const definition = getOAuthProviderDefinition('codex');
  return definition?.buildProxyHeaders?.({
    oauth,
    downstreamHeaders: input.downstreamHeaders,
  }) || {};
}

export async function refreshOauthAccessToken(accountId: number) {
  const account = await db.select().from(schema.accounts)
    .where(eq(schema.accounts.id, accountId))
    .get();
  if (!account) {
    throw new Error('oauth account not found');
  }
  const oauth = getOauthInfoFromAccount(account);
  if (!oauth?.refreshToken) {
    throw new Error('oauth refresh token missing');
  }
  const definition = getOAuthProviderDefinition(oauth.provider);
  if (!definition) {
    throw new Error(`unsupported oauth provider: ${oauth.provider}`);
  }

  const refreshed = await definition.refreshAccessToken({
    refreshToken: oauth.refreshToken,
    oauth: {
      projectId: oauth.projectId,
      providerData: oauth.providerData,
    },
    proxyUrl: await resolveOauthAccountProxyUrl({
      siteId: account.siteId,
      extraConfig: account.extraConfig,
    }),
  });
  const nextOauth = buildOauthInfoFromAccount(account, {
    provider: oauth.provider,
    accountId: refreshed.accountId || oauth.accountId,
    accountKey: refreshed.accountKey || oauth.accountKey || refreshed.accountId || oauth.accountId,
    email: refreshed.email || oauth.email,
    planType: refreshed.planType || oauth.planType,
    projectId: refreshed.projectId || oauth.projectId,
    refreshToken: refreshed.refreshToken || oauth.refreshToken,
    tokenExpiresAt: refreshed.tokenExpiresAt || oauth.tokenExpiresAt,
    idToken: refreshed.idToken || oauth.idToken,
    providerData: {
      ...(oauth.providerData || {}),
      ...(refreshed.providerData || {}),
    },
  });
  const extraConfig = mergeAccountExtraConfig(account.extraConfig, {
    credentialMode: 'session',
    oauth: buildStoredOauthStateFromAccount(account, nextOauth),
  });

  await db.update(schema.accounts).set({
    accessToken: refreshed.accessToken,
    oauthProvider: oauth.provider,
    oauthAccountKey: nextOauth.accountKey || nextOauth.accountId || null,
    oauthProjectId: nextOauth.projectId || null,
    extraConfig,
    status: 'active',
    updatedAt: new Date().toISOString(),
  }).where(eq(schema.accounts.id, accountId)).run();

  return {
    accountId,
    accessToken: refreshed.accessToken,
    accountKey: nextOauth.accountKey || nextOauth.accountId,
    extraConfig,
  };
}

export async function refreshCodexOauthAccessToken(accountId: number) {
  return refreshOauthAccessToken(accountId);
}

export type { OAuthProviderMetadata };
