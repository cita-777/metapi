import { clearAuthSession, getAuthToken } from './authSession.js';

type RequestOptions = RequestInit & {
  timeoutMs?: number;
};

async function request(url: string, options: RequestOptions = {}) {
  const { timeoutMs = 30_000, signal: externalSignal, ...fetchOptions } = options;
  const controller = new AbortController();
  let timeoutHandle: ReturnType<typeof setTimeout> | null = setTimeout(() => {
    controller.abort();
  }, timeoutMs);
  let cleanupExternalSignal = () => { };

  if (externalSignal) {
    if (externalSignal.aborted) {
      controller.abort();
    } else {
      const abortHandler = () => controller.abort();
      externalSignal.addEventListener('abort', abortHandler, { once: true });
      cleanupExternalSignal = () => externalSignal.removeEventListener('abort', abortHandler);
    }
  }

  const token = getAuthToken(localStorage);
  if (!token) {
    const hadToken = !!localStorage.getItem('auth_token');
    clearAuthSession(localStorage);
    if (hadToken && typeof window !== 'undefined' && typeof window.location?.reload === 'function') {
      window.location.reload();
    }
    throw new Error('Session expired');
  }
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${token}`,
  };
  if (fetchOptions.body) headers['Content-Type'] = 'application/json';

  try {
    const res = await fetch(url, {
      ...fetchOptions,
      signal: controller.signal,
      headers: {
        ...headers,
        ...fetchOptions.headers as Record<string, string>,
      },
    });
    if (res.status === 401 || res.status === 403) {
      const hadToken = !!getAuthToken(localStorage);
      clearAuthSession(localStorage);
      if (hadToken) window.location.reload();
      throw new Error('Session expired');
    }
    if (!res.ok) {
      let message = `HTTP ${res.status}`;
      try {
        const text = await res.text();
        if (text) {
          try {
            const json = JSON.parse(text);
            if (json?.message && typeof json.message === 'string') {
              message = json.message;
            } else if (json?.error && typeof json.error === 'string') {
              message = json.error;
            } else {
              message = `${message}: ${text.slice(0, 120)}`;
            }
          } catch {
            message = `${message}: ${text.slice(0, 120)}`;
          }
        }
      } catch { }
      throw new Error(message);
    }
    return res.json();
  } catch (error: any) {
    if (error?.name === 'AbortError') {
      if (externalSignal?.aborted) throw error;
      throw new Error(`请求超时（${Math.max(1, Math.round(timeoutMs / 1000))}s）`);
    }
    throw error;
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
      timeoutHandle = null;
    }
    cleanupExternalSignal();
  }
}

function buildQueryString(params?: Record<string, string | number | boolean | null | undefined>) {
  if (!params) return '';
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    searchParams.set(key, String(value));
  }
  const serialized = searchParams.toString();
  return serialized ? `?${serialized}` : '';
}

type TestChatRequestPayload = {
  model: string;
  messages: Array<{ role: string; content: string }>;
  targetFormat?: 'openai' | 'claude' | 'responses' | 'gemini';
  stream?: boolean;
  temperature?: number;
  top_p?: number;
  max_tokens?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  seed?: number;
};

export type ProxyTestMethod = 'POST' | 'GET' | 'DELETE';
export type ProxyTestRequestKind = 'json' | 'multipart' | 'empty';

export type ProxyTestMultipartFile = {
  field: string;
  name: string;
  mimeType: string;
  dataUrl: string;
};

export type ProxyTestRequestEnvelope = {
  method: ProxyTestMethod;
  path: string;
  requestKind: ProxyTestRequestKind;
  stream?: boolean;
  jobMode?: boolean;
  rawMode?: boolean;
  jsonBody?: unknown;
  rawJsonText?: string;
  multipartFields?: Record<string, string>;
  multipartFiles?: ProxyTestMultipartFile[];
};

const DEFAULT_PROXY_TEST_TIMEOUT_MS = 30_000;
const LONG_RUNNING_PROXY_TEST_TIMEOUT_MS = 150_000;

function resolveProxyTestTimeoutMs(data: ProxyTestRequestEnvelope) {
  if (data.jobMode) return LONG_RUNNING_PROXY_TEST_TIMEOUT_MS;
  if (data.path === '/v1/images/generations') return LONG_RUNNING_PROXY_TEST_TIMEOUT_MS;
  if (data.path === '/v1/images/edits') return LONG_RUNNING_PROXY_TEST_TIMEOUT_MS;
  if (data.path === '/v1/videos' && data.method === 'POST') return LONG_RUNNING_PROXY_TEST_TIMEOUT_MS;
  return DEFAULT_PROXY_TEST_TIMEOUT_MS;
}

export type ProxyTestJobResponse = {
  jobId: string;
  status: 'pending' | 'succeeded' | 'failed' | 'cancelled';
  result?: unknown;
  error?: unknown;
  createdAt?: string;
  updatedAt?: string;
  expiresAt?: string;
};

export type ProxyLogStatusFilter = 'all' | 'success' | 'failed';

export type ProxyLogBillingDetails = {
  quotaType: number;
  usage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
    cacheReadTokens: number;
    cacheCreationTokens: number;
    billablePromptTokens: number;
    promptTokensIncludeCache: boolean | null;
  };
  pricing: {
    modelRatio: number;
    completionRatio: number;
    cacheRatio: number;
    cacheCreationRatio: number;
    groupRatio: number;
  };
  breakdown: {
    inputPerMillion: number;
    outputPerMillion: number;
    cacheReadPerMillion: number;
    cacheCreationPerMillion: number;
    inputCost: number;
    outputCost: number;
    cacheReadCost: number;
    cacheCreationCost: number;
    totalCost: number;
  };
} | null;

export type ProxyLogListItem = {
  id: number;
  createdAt: string;
  modelRequested: string;
  modelActual: string;
  status: string;
  latencyMs: number;
  totalTokens: number | null;
  retryCount: number;
  accountId?: number | null;
  siteId?: number | null;
  username?: string | null;
  siteName?: string | null;
  siteUrl?: string | null;
  errorMessage?: string | null;
  downstreamKeyId?: number | null;
  downstreamKeyName?: string | null;
  downstreamKeyGroupName?: string | null;
  downstreamKeyTags?: string[];
  promptTokens?: number | null;
  completionTokens?: number | null;
  estimatedCost?: number | null;
};

export type ProxyLogDetail = ProxyLogListItem & {
  routeId?: number | null;
  channelId?: number | null;
  httpStatus?: number | null;
  billingDetails?: ProxyLogBillingDetails;
};

export type ProxyLogsSummary = {
  totalCount: number;
  successCount: number;
  failedCount: number;
  totalCost: number;
  totalTokensAll: number;
};

export type ProxyLogsQuery = {
  limit?: number;
  offset?: number;
  status?: ProxyLogStatusFilter;
  search?: string;
  siteId?: number;
  from?: string;
  to?: string;
};

export type ProxyLogsResponse = {
  items: ProxyLogListItem[];
  total: number;
  page: number;
  pageSize: number;
  summary: ProxyLogsSummary;
};

export type OAuthProviderInfo = {
  provider: string;
  label: string;
  platform: string;
  enabled: boolean;
  loginType: 'oauth';
};

export type OAuthSessionInfo = {
  provider: string;
  state: string;
  status: 'pending' | 'success' | 'error';
  accountId?: number;
  siteId?: number;
  error?: string;
};

export type OAuthConnectionInfo = {
  accountId: number;
  siteId: number;
  provider: string;
  username?: string | null;
  email?: string | null;
  accountKey?: string | null;
  planType?: string | null;
  modelCount: number;
  modelsPreview: string[];
  status: 'healthy' | 'abnormal';
  routeChannelCount?: number;
  lastModelSyncAt?: string | null;
  lastModelSyncError?: string | null;
  site?: { id: number; name: string; url: string; platform: string } | null;
};

export const api = {
  // Sites
  getSites: () => request('/api/sites'),
  addSite: (data: any) => request('/api/sites', { method: 'POST', body: JSON.stringify(data) }),
  updateSite: (id: number, data: any) => request(`/api/sites/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteSite: (id: number) => request(`/api/sites/${id}`, { method: 'DELETE' }),
  batchUpdateSites: (data: any) => request('/api/sites/batch', { method: 'POST', body: JSON.stringify(data) }),
  detectSite: (url: string) => request('/api/sites/detect', { method: 'POST', body: JSON.stringify({ url }) }),
  getSiteDisabledModels: (siteId: number) => request(`/api/sites/${siteId}/disabled-models`),
  updateSiteDisabledModels: (siteId: number, models: string[]) => request(`/api/sites/${siteId}/disabled-models`, { method: 'PUT', body: JSON.stringify({ models }) }),

  // Accounts
  getAccounts: () => request('/api/accounts'),
  addAccount: (data: any) => request('/api/accounts', { method: 'POST', body: JSON.stringify(data) }),
  loginAccount: (data: { siteId: number; username: string; password: string }) => request('/api/accounts/login', { method: 'POST', body: JSON.stringify(data) }),
  verifyToken: (data: { siteId: number; accessToken: string; platformUserId?: number; credentialMode?: 'auto' | 'session' | 'apikey' }) => request('/api/accounts/verify-token', { method: 'POST', body: JSON.stringify(data) }),
  rebindAccountSession: (id: number, data: { accessToken: string; platformUserId?: number; refreshToken?: string; tokenExpiresAt?: number }) =>
    request(`/api/accounts/${id}/rebind-session`, { method: 'POST', body: JSON.stringify(data) }),
  updateAccount: (id: number, data: any) => request(`/api/accounts/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteAccount: (id: number) => request(`/api/accounts/${id}`, { method: 'DELETE' }),
  batchUpdateAccounts: (data: any) => request('/api/accounts/batch', { method: 'POST', body: JSON.stringify(data) }),
  refreshBalance: (id: number) => request(`/api/accounts/${id}/balance`, { method: 'POST' }),
  getAccountModels: (id: number) => request(`/api/accounts/${id}/models`),
  addAccountAvailableModels: (accountId: number, models: string[]) => request(`/api/accounts/${accountId}/models/manual`, { method: 'POST', body: JSON.stringify({ models }) }),
  refreshAccountHealth: (data?: { accountId?: number; wait?: boolean }) => request('/api/accounts/health/refresh', {
    method: 'POST',
    body: JSON.stringify(data || {}),
    timeoutMs: data?.wait ? 150_000 : 30_000,
  }),

  // Account tokens
  getAccountTokens: (accountId?: number) => request(`/api/account-tokens${accountId ? `?accountId=${accountId}` : ''}`),
  addAccountToken: (data: any) => request('/api/account-tokens', { method: 'POST', body: JSON.stringify(data) }),
  updateAccountToken: (id: number, data: any) => request(`/api/account-tokens/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteAccountToken: (id: number) => request(`/api/account-tokens/${id}`, { method: 'DELETE' }),
  batchUpdateAccountTokens: (data: any) => request('/api/account-tokens/batch', { method: 'POST', body: JSON.stringify(data) }),
  getAccountTokenGroups: (accountId: number) => request(`/api/account-tokens/groups/${accountId}`),
  setDefaultAccountToken: (id: number) => request(`/api/account-tokens/${id}/default`, { method: 'POST' }),
  getAccountTokenValue: (id: number) => request(`/api/account-tokens/${id}/value`),
  syncAccountTokens: (accountId: number) => request(`/api/account-tokens/sync/${accountId}`, { method: 'POST', timeoutMs: 45_000 }),
  syncAllAccountTokens: (wait = false) => request('/api/account-tokens/sync-all', {
    method: 'POST',
    body: JSON.stringify(wait ? { wait: true } : {}),
    timeoutMs: wait ? 150_000 : 30_000,
  }),

  // Check-in
  triggerCheckinAll: () => request('/api/checkin/trigger', { method: 'POST' }),
  triggerCheckin: (id: number) => request(`/api/checkin/trigger/${id}`, { method: 'POST' }),
  getCheckinLogs: (params?: string) => request(`/api/checkin/logs${params ? '?' + params : ''}`),
  updateCheckinSchedule: (cron: string) => request('/api/checkin/schedule', { method: 'PUT', body: JSON.stringify({ cron }) }),

  // Routes
  getRoutes: () => request('/api/routes'),
  getRoutesLite: () => request('/api/routes/lite'),
  getRoutesSummary: () => request('/api/routes/summary'),
  getRouteChannels: (routeId: number) => request(`/api/routes/${routeId}/channels`),
  batchAddChannels: (routeId: number, channels: Array<{ accountId: number; tokenId?: number; sourceModel?: string }>) =>
    request(`/api/routes/${routeId}/channels/batch`, { method: 'POST', body: JSON.stringify({ channels }) }),
  addRoute: (data: any) => request('/api/routes', { method: 'POST', body: JSON.stringify(data) }),
  updateRoute: (id: number, data: any) => request(`/api/routes/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteRoute: (id: number) => request(`/api/routes/${id}`, { method: 'DELETE' }),
  addChannel: (routeId: number, data: any) => request(`/api/routes/${routeId}/channels`, { method: 'POST', body: JSON.stringify(data) }),
  updateChannel: (id: number, data: any) => request(`/api/channels/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  batchUpdateChannels: (updates: Array<{ id: number; priority: number }>) =>
    request('/api/channels/batch', { method: 'PUT', body: JSON.stringify({ updates }) }),
  deleteChannel: (id: number) => request(`/api/channels/${id}`, { method: 'DELETE' }),
  rebuildRoutes: (refreshModels = true, wait = false) => request('/api/routes/rebuild', {
    method: 'POST',
    body: JSON.stringify({ refreshModels, ...(wait ? { wait: true } : {}) }),
    timeoutMs: wait ? 150_000 : 30_000,
  }),
  getRouteDecision: (model: string) => request(`/api/routes/decision?model=${encodeURIComponent(model)}`),
  getRouteDecisionsBatch: (models: string[], options?: { refreshPricingCatalog?: boolean; persistSnapshots?: boolean }) => request('/api/routes/decision/batch', {
    method: 'POST',
    body: JSON.stringify({
      models,
      ...(options?.refreshPricingCatalog ? { refreshPricingCatalog: true } : {}),
      ...(options?.persistSnapshots ? { persistSnapshots: true } : {}),
    }),
  }),
  getRouteDecisionsByRouteBatch: (items: Array<{ routeId: number; model: string }>, options?: { refreshPricingCatalog?: boolean; persistSnapshots?: boolean }) => request('/api/routes/decision/by-route/batch', {
    method: 'POST',
    body: JSON.stringify({
      items,
      ...(options?.refreshPricingCatalog ? { refreshPricingCatalog: true } : {}),
      ...(options?.persistSnapshots ? { persistSnapshots: true } : {}),
    }),
  }),
  getRouteWideDecisionsBatch: (routeIds: number[], options?: { refreshPricingCatalog?: boolean; persistSnapshots?: boolean }) => request('/api/routes/decision/route-wide/batch', {
    method: 'POST',
    body: JSON.stringify({
      routeIds,
      ...(options?.refreshPricingCatalog ? { refreshPricingCatalog: true } : {}),
      ...(options?.persistSnapshots ? { persistSnapshots: true } : {}),
    }),
  }),

  // Stats
  getDashboard: () => request('/api/stats/dashboard'),
  getProxyLogs: (params?: ProxyLogsQuery) => request(`/api/stats/proxy-logs${buildQueryString(params)}`) as Promise<ProxyLogsResponse>,
  getProxyLogDetail: (id: number) => request(`/api/stats/proxy-logs/${id}`) as Promise<ProxyLogDetail>,
  checkModels: (accountId: number) => request(`/api/models/check/${accountId}`, { method: 'POST' }),
  getSiteDistribution: () => request('/api/stats/site-distribution'),
  getSiteTrend: (days = 7) => request(`/api/stats/site-trend?days=${days}`),
  getModelBySite: (siteId?: number, days = 7) =>
    request(`/api/stats/model-by-site?${siteId ? `siteId=${siteId}&` : ''}days=${days}`),

  // Search
  search: (query: string) => request('/api/search', { method: 'POST', body: JSON.stringify({ query, limit: 20 }) }),

  // OAuth
  getOAuthProviders: () => request('/api/oauth/providers') as Promise<{ providers: OAuthProviderInfo[] }>,
  startOAuthProvider: (provider: string, data?: { accountId?: number }) => request(`/api/oauth/providers/${encodeURIComponent(provider)}/start`, {
    method: 'POST',
    body: JSON.stringify(data || {}),
  }) as Promise<{ provider: string; state: string; authorizationUrl: string }>,
  getOAuthSession: (state: string) => request(`/api/oauth/sessions/${encodeURIComponent(state)}`) as Promise<OAuthSessionInfo>,
  getOAuthConnections: () => request('/api/oauth/connections') as Promise<{ items: OAuthConnectionInfo[] }>,
  rebindOAuthConnection: (accountId: number) => request(`/api/oauth/connections/${accountId}/rebind`, {
    method: 'POST',
    body: JSON.stringify({}),
  }) as Promise<{ provider: string; state: string; authorizationUrl: string }>,
  deleteOAuthConnection: (accountId: number) => request(`/api/oauth/connections/${accountId}`, {
    method: 'DELETE',
  }) as Promise<{ success: true }>,

  // Events
  getEvents: (params?: string) => request(`/api/events${params ? '?' + params : ''}`),
  getEventCount: () => request('/api/events/count'),
  markEventRead: (id: number) => request(`/api/events/${id}/read`, { method: 'POST' }),
  markAllEventsRead: () => request('/api/events/read-all', { method: 'POST' }),
  clearEvents: () => request('/api/events', { method: 'DELETE' }),
  getTasks: (limit = 50) => request(`/api/tasks?limit=${Math.max(1, Math.min(200, Math.trunc(limit)))}`),
  getTask: (id: string) => request(`/api/tasks/${encodeURIComponent(id)}`),

  // Auth management
  getAuthInfo: () => request('/api/settings/auth/info'),
  changeAuthToken: (oldToken: string, newToken: string) => request('/api/settings/auth/change', {
    method: 'POST', body: JSON.stringify({ oldToken, newToken }),
  }),
  getRuntimeSettings: () => request('/api/settings/runtime'),
  updateRuntimeSettings: (data: any) => request('/api/settings/runtime', {
    method: 'PUT',
    body: JSON.stringify(data),
  }),
  getRuntimeDatabaseConfig: () => request('/api/settings/database/runtime'),
  updateRuntimeDatabaseConfig: (data: { dialect: 'sqlite' | 'mysql' | 'postgres'; connectionString: string; ssl?: boolean }) =>
    request('/api/settings/database/runtime', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  testExternalDatabaseConnection: (data: { dialect: 'sqlite' | 'mysql' | 'postgres'; connectionString: string; ssl?: boolean }) =>
    request('/api/settings/database/test-connection', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  migrateExternalDatabase: (data: { dialect: 'sqlite' | 'mysql' | 'postgres'; connectionString: string; overwrite?: boolean; ssl?: boolean }) =>
    request('/api/settings/database/migrate', {
      method: 'POST',
      body: JSON.stringify(data),
      timeoutMs: 120_000,
    }),
  getDownstreamApiKeys: () => request('/api/downstream-keys'),
  createDownstreamApiKey: (data: any) => request('/api/downstream-keys', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  updateDownstreamApiKey: (id: number, data: any) => request(`/api/downstream-keys/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  }),
  deleteDownstreamApiKey: (id: number) => request(`/api/downstream-keys/${id}`, {
    method: 'DELETE',
  }),
  batchDownstreamApiKeys: (data: {
    ids: number[];
    action: 'enable' | 'disable' | 'delete' | 'resetUsage' | 'updateMetadata';
    groupOperation?: 'keep' | 'set' | 'clear';
    groupName?: string;
    tagOperation?: 'keep' | 'append';
    tags?: string[];
  }) =>
    request('/api/downstream-keys/batch', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  resetDownstreamApiKeyUsage: (id: number) => request(`/api/downstream-keys/${id}/reset-usage`, {
    method: 'POST',
  }),
  getDownstreamApiKeysSummary: (params?: { range?: '24h' | '7d' | 'all'; status?: 'all' | 'enabled' | 'disabled'; search?: string }) =>
    request(`/api/downstream-keys/summary${buildQueryString(params)}`),
  getDownstreamApiKeyOverview: (id: number) => request(`/api/downstream-keys/${id}/overview`),
  getDownstreamApiKeyTrend: (id: number, params?: { range?: '24h' | '7d' | 'all' }) =>
    request(`/api/downstream-keys/${id}/trend${buildQueryString(params)}`),
  exportBackup: (type: 'all' | 'accounts' | 'preferences' = 'all') =>
    request(`/api/settings/backup/export?type=${encodeURIComponent(type)}`),
  importBackup: (data: any) =>
    request('/api/settings/backup/import', {
      method: 'POST',
      body: JSON.stringify({ data }),
    }),
  clearRuntimeCache: () => request('/api/settings/maintenance/clear-cache', { method: 'POST' }),
  clearUsageData: () => request('/api/settings/maintenance/clear-usage', { method: 'POST' }),
  factoryReset: () => request('/api/settings/maintenance/factory-reset', { method: 'POST' }),
  testNotification: () => request('/api/settings/notify/test', { method: 'POST' }),

  // Monitor embed
  getMonitorConfig: () => request('/api/monitor/config'),
  updateMonitorConfig: (data: { ldohCookie?: string | null }) => request('/api/monitor/config', {
    method: 'PUT',
    body: JSON.stringify(data),
  }),
  initMonitorSession: () => request('/api/monitor/session', { method: 'POST' }),

  // Models marketplace
  getModelsMarketplace: (options?: { refresh?: boolean; includePricing?: boolean }) => {
    const params = new URLSearchParams();
    if (options?.refresh) params.set('refresh', '1');
    if (options?.includePricing) params.set('includePricing', '1');
    const query = params.toString();
    return request(`/api/models/marketplace${query ? `?${query}` : ''}`, { timeoutMs: options?.refresh ? 45_000 : 15_000 });
  },
  getModelTokenCandidates: () => request('/api/models/token-candidates'),

  // Simple chat test from admin panel
  startTestChatJob: (data: TestChatRequestPayload) =>
    request('/api/test/chat/jobs', { method: 'POST', body: JSON.stringify(data) }),
  getTestChatJob: (jobId: string) => request(`/api/test/chat/jobs/${encodeURIComponent(jobId)}`),
  deleteTestChatJob: (jobId: string) => request(`/api/test/chat/jobs/${encodeURIComponent(jobId)}`, { method: 'DELETE' }),
  startProxyTestJob: (data: ProxyTestRequestEnvelope) =>
    request('/api/test/proxy/jobs', {
      method: 'POST',
      body: JSON.stringify(data),
      timeoutMs: resolveProxyTestTimeoutMs(data),
    }),
  getProxyTestJob: (jobId: string) => request(`/api/test/proxy/jobs/${encodeURIComponent(jobId)}`),
  deleteProxyTestJob: (jobId: string) => request(`/api/test/proxy/jobs/${encodeURIComponent(jobId)}`, { method: 'DELETE' }),
  testProxy: (data: ProxyTestRequestEnvelope) =>
    request('/api/test/proxy', {
      method: 'POST',
      body: JSON.stringify(data),
      timeoutMs: resolveProxyTestTimeoutMs(data),
    }),
  proxyTest: (data: ProxyTestRequestEnvelope) =>
    request('/api/test/proxy', {
      method: 'POST',
      body: JSON.stringify(data),
      timeoutMs: resolveProxyTestTimeoutMs(data),
    }),
  testChat: (data: TestChatRequestPayload) =>
    request('/api/test/chat', { method: 'POST', body: JSON.stringify(data) }),
  testProxyStream: async (data: ProxyTestRequestEnvelope, signal?: AbortSignal) => {
    const token = getAuthToken(localStorage);
    if (!token) {
      clearAuthSession(localStorage);
      throw new Error('Session expired');
    }
    return fetch('/api/test/proxy/stream', {
      method: 'POST',
      signal,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
  },
  proxyTestStream: async (data: ProxyTestRequestEnvelope, signal?: AbortSignal) => {
    const token = getAuthToken(localStorage);
    if (!token) {
      clearAuthSession(localStorage);
      throw new Error('Session expired');
    }
    return fetch('/api/test/proxy/stream', {
      method: 'POST',
      signal,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
  },
  testChatStream: async (data: TestChatRequestPayload, signal?: AbortSignal) => {
    const token = getAuthToken(localStorage);
    if (!token) {
      clearAuthSession(localStorage);
      throw new Error('Session expired');
    }
    return fetch('/api/test/chat/stream', {
      method: 'POST',
      signal,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
  },
};
