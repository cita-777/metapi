import { clearAuthSession, getAuthToken } from './authSession.js';

type BufferLike = {
  from(data: ArrayBuffer): { toString(encoding: 'base64'): string };
};

const nodeBuffer = (globalThis as typeof globalThis & { Buffer?: BufferLike }).Buffer;

type RequestOptions = RequestInit & {
  timeoutMs?: number;
};

function requireAuthToken(): string {
  const token = getAuthToken(localStorage);
  if (!token) {
    const hadToken = !!localStorage.getItem('auth_token');
    clearAuthSession(localStorage);
    if (hadToken && typeof window !== 'undefined' && typeof window.location?.reload === 'function') {
      window.location.reload();
    }
    throw new Error('Session expired');
  }
  return token;
}

async function extractResponseErrorMessage(res: Response): Promise<string> {
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
        } else if (json?.error?.message && typeof json.error.message === 'string') {
          message = json.error.message;
        } else {
          message = `${message}: ${text.slice(0, 120)}`;
        }
      } catch {
        message = `${message}: ${text.slice(0, 120)}`;
      }
    }
  } catch { }
  return message;
}

function parseContentDispositionFilename(headerValue: string | null): string | null {
  if (!headerValue) return null;
  const utf8Match = /filename\*=UTF-8''([^;]+)/i.exec(headerValue);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }
  const quotedMatch = /filename="([^"]+)"/i.exec(headerValue);
  if (quotedMatch?.[1]) return quotedMatch[1];
  const bareMatch = /filename=([^;]+)/i.exec(headerValue);
  return bareMatch?.[1]?.trim() || null;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  if (nodeBuffer) {
    return nodeBuffer.from(buffer).toString('base64');
  }

  let binary = '';
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

async function fetchAuthenticatedResponse(url: string, options: RequestOptions = {}): Promise<Response> {
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

  const token = requireAuthToken();
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
      if (hadToken && typeof window !== 'undefined' && typeof window.location?.reload === 'function') {
        window.location.reload();
      }
      throw new Error('Session expired');
    }
    return res;
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

async function request(url: string, options: RequestOptions = {}) {
  const res = await fetchAuthenticatedResponse(url, options);
  if (!res.ok) {
    throw new Error(await extractResponseErrorMessage(res));
  }
  return res.json();
}

async function streamSse(
  url: string,
  handlers: {
    onLog?: (entry: any) => void;
    onDone?: (payload: any) => void;
    signal?: AbortSignal;
  },
) {
  const response = await fetchAuthenticatedResponse(url, {
    method: 'GET',
    signal: handlers.signal,
    headers: {
      Accept: 'text/event-stream',
    },
    timeoutMs: 120_000,
  });

  if (!response.ok) {
    throw new Error(await extractResponseErrorMessage(response));
  }
  if (!response.body) {
    throw new Error('响应未返回流式内容');
  }

  const decoder = new TextDecoder();
  const reader = response.body.getReader();
  let buffer = '';

  const flushBuffer = (final = false) => {
    const chunks = final ? [...buffer.split('\n\n'), ''] : buffer.split('\n\n');
    if (!final) buffer = chunks.pop() || '';
    else buffer = '';

    for (const chunk of chunks) {
      const lines = chunk.split('\n');
      let eventName = 'message';
      const dataLines: string[] = [];

      for (const line of lines) {
        if (line.startsWith('event:')) {
          eventName = line.slice('event:'.length).trim() || 'message';
        } else if (line.startsWith('data:')) {
          dataLines.push(line.slice('data:'.length).trim());
        }
      }

      if (dataLines.length <= 0) continue;
      let payload: any = dataLines.join('\n');
      try {
        payload = JSON.parse(payload);
      } catch {
        // keep string payload
      }

      if (eventName === 'log') {
        handlers.onLog?.(payload);
      } else if (eventName === 'done') {
        handlers.onDone?.(payload);
      }
    }
  };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    flushBuffer(false);
  }

  if (buffer.trim()) {
    flushBuffer(true);
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
  forcedChannelId?: number | null;
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
  forcedChannelId?: number | null;
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

function proxyTestRequest(data: ProxyTestRequestEnvelope) {
  return request('/api/test/proxy', {
    method: 'POST',
    body: JSON.stringify(data),
    timeoutMs: resolveProxyTestTimeoutMs(data),
  });
}

async function proxyTestStreamRequest(data: ProxyTestRequestEnvelope, signal?: AbortSignal) {
  const token = getAuthToken(localStorage);
  if (!token) {
    clearAuthSession(localStorage);
    throw new Error('Session expired');
  }
  const response = await fetch('/api/test/proxy/stream', {
    method: 'POST',
    signal,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });
  if (response.status === 401 || response.status === 403) {
    clearAuthSession(localStorage);
    throw new Error('Session expired');
  }
  return response;
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

export type SystemProxyTestRequest = {
  proxyUrl?: string;
};

export type SystemProxyTestResponse = {
  success: true;
  proxyUrl: string;
  probeUrl: string;
  finalUrl: string;
  reachable: true;
  ok: boolean;
  statusCode: number;
  latencyMs: number;
};

export type RuntimeRoutingWeightsPayload = {
  baseWeightFactor?: number;
  valueScoreFactor?: number;
  costWeight?: number;
  balanceWeight?: number;
  usageWeight?: number;
};

export type RuntimeSettingsPayload = {
  proxyToken?: string;
  systemProxyUrl?: string;
  codexUpstreamWebsocketEnabled?: boolean;
  disableCrossProtocolFallback?: boolean;
  proxySessionChannelConcurrencyLimit?: number;
  proxySessionChannelQueueWaitMs?: number;
  proxyDebugTraceEnabled?: boolean;
  proxyDebugCaptureHeaders?: boolean;
  proxyDebugCaptureBodies?: boolean;
  proxyDebugCaptureStreamChunks?: boolean;
  proxyDebugTargetSessionId?: string;
  proxyDebugTargetClientKind?: string;
  proxyDebugTargetModel?: string;
  proxyDebugRetentionHours?: number;
  proxyDebugMaxBodyBytes?: number;
  checkinCron?: string;
  checkinScheduleMode?: 'cron' | 'interval';
  checkinIntervalHours?: number;
  balanceRefreshCron?: string;
  logCleanupCron?: string;
  logCleanupUsageLogsEnabled?: boolean;
  logCleanupProgramLogsEnabled?: boolean;
  logCleanupRetentionDays?: number;
  webhookUrl?: string;
  barkUrl?: string;
  webhookEnabled?: boolean;
  barkEnabled?: boolean;
  serverChanEnabled?: boolean;
  serverChanKey?: string;
  telegramEnabled?: boolean;
  telegramApiBaseUrl?: string;
  telegramBotToken?: string;
  telegramChatId?: string;
  telegramUseSystemProxy?: boolean;
  telegramMessageThreadId?: string;
  smtpEnabled?: boolean;
  smtpHost?: string;
  smtpPort?: number;
  smtpSecure?: boolean;
  smtpUser?: string;
  smtpPass?: string;
  smtpFrom?: string;
  smtpTo?: string;
  notifyCooldownSec?: number;
  adminIpAllowlist?: string[] | string;
  routingFallbackUnitCost?: number;
  tokenRouterFailureCooldownMaxSec?: number;
  routingWeights?: RuntimeRoutingWeightsPayload;
  proxyErrorKeywords?: string[] | string;
  proxyEmptyContentFailEnabled?: boolean;
  globalBlockedBrands?: string[];
  globalAllowedModels?: string[];
};

export type ProxyLogStatusFilter = 'all' | 'success' | 'failed';
export type ProxyLogClientConfidence = 'exact' | 'heuristic' | 'unknown' | null;
export type ProxyLogUsageSource = 'upstream' | 'self-log' | 'unknown' | null;

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
  clientFamily?: string | null;
  clientAppId?: string | null;
  clientAppName?: string | null;
  clientConfidence?: ProxyLogClientConfidence;
  usageSource?: ProxyLogUsageSource;
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
  client?: string;
  siteId?: number;
  from?: string;
  to?: string;
};

export type ProxyLogClientOption = {
  value: string;
  label: string;
};

export type ProxyLogsResponse = {
  items: ProxyLogListItem[];
  total: number;
  page: number;
  pageSize: number;
  clientOptions: ProxyLogClientOption[];
  summary: ProxyLogsSummary;
};

export type ProxyDebugTraceListItem = {
  id: number;
  createdAt: string;
  downstreamPath: string;
  clientKind?: string | null;
  sessionId?: string | null;
  requestedModel?: string | null;
  selectedChannelId?: number | null;
  finalStatus?: string | null;
  finalHttpStatus?: number | null;
  finalUpstreamPath?: string | null;
};

export type ProxyDebugTraceDetail = {
  trace: {
    id: number;
    createdAt?: string | null;
    updatedAt?: string | null;
    downstreamPath?: string | null;
    clientKind?: string | null;
    sessionId?: string | null;
    traceHint?: string | null;
    requestedModel?: string | null;
    stickySessionKey?: string | null;
    stickyHitChannelId?: number | null;
    selectedChannelId?: number | null;
    selectedRouteId?: number | null;
    selectedAccountId?: number | null;
    selectedSiteId?: number | null;
    selectedSitePlatform?: string | null;
    endpointCandidatesJson?: string | null;
    endpointRuntimeStateJson?: string | null;
    decisionSummaryJson?: string | null;
    requestHeadersJson?: string | null;
    requestBodyJson?: string | null;
    finalStatus?: string | null;
    finalHttpStatus?: number | null;
    finalUpstreamPath?: string | null;
    finalResponseHeadersJson?: string | null;
    finalResponseBodyJson?: string | null;
  };
  attempts: Array<{
    id: number;
    attemptIndex: number;
    endpoint: string;
    requestPath: string;
    targetUrl: string;
    runtimeExecutor?: string | null;
    requestHeadersJson?: string | null;
    requestBodyJson?: string | null;
    responseStatus?: number | null;
    responseHeadersJson?: string | null;
    responseBodyJson?: string | null;
    rawErrorText?: string | null;
    recoverApplied?: boolean | null;
    downgradeDecision?: boolean | null;
    downgradeReason?: string | null;
    memoryWriteJson?: string | null;
    createdAt?: string | null;
  }>;
};

export type ProxyDebugTracesResponse = {
  items: ProxyDebugTraceListItem[];
};

export type OAuthProviderInfo = {
  provider: string;
  label: string;
  platform: string;
  enabled: boolean;
  loginType: 'oauth';
  requiresProjectId: boolean;
  supportsDirectAccountRouting: boolean;
  supportsCloudValidation: boolean;
  supportsNativeProxy: boolean;
};

export type OAuthStartInstructions = {
  redirectUri: string;
  callbackPort: number;
  callbackPath: string;
  manualCallbackDelayMs: number;
  sshTunnelCommand?: string;
  sshTunnelKeyCommand?: string;
};

export type OAuthStartResponse = {
  provider: string;
  state: string;
  authorizationUrl: string;
  instructions: OAuthStartInstructions;
};

export type OAuthSessionInfo = {
  provider: string;
  state: string;
  status: 'pending' | 'success' | 'error';
  accountId?: number;
  siteId?: number;
  error?: string;
};

export type OAuthQuotaWindowInfo = {
  supported: boolean;
  limit?: number | null;
  used?: number | null;
  remaining?: number | null;
  resetAt?: string | null;
  message?: string | null;
};

export type OAuthQuotaInfo = {
  status: 'supported' | 'unsupported' | 'error';
  source: 'official' | 'reverse_engineered';
  lastSyncAt?: string | null;
  lastError?: string | null;
  providerMessage?: string | null;
  subscription?: {
    planType?: string | null;
    activeStart?: string | null;
    activeUntil?: string | null;
  } | null;
  windows: {
    fiveHour: OAuthQuotaWindowInfo;
    sevenDay: OAuthQuotaWindowInfo;
  };
  lastLimitResetAt?: string | null;
};

export type OAuthConnectionInfo = {
  accountId: number;
  siteId: number;
  provider: string;
  username?: string | null;
  email?: string | null;
  accountKey?: string | null;
  planType?: string | null;
  projectId?: string | null;
  modelCount: number;
  modelsPreview: string[];
  status: 'healthy' | 'abnormal';
  quota?: OAuthQuotaInfo | null;
  routeChannelCount?: number;
  lastModelSyncAt?: string | null;
  lastModelSyncError?: string | null;
  proxyUrl?: string | null;
  site?: { id: number; name: string; url: string; platform: string } | null;
};

export type OAuthConnectionsResponse = {
  items: OAuthConnectionInfo[];
  total: number;
  limit: number;
  offset: number;
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
  getSiteAvailableModels: (siteId: number) => request(`/api/sites/${siteId}/available-models`),

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
  clearRouteCooldown: (id: number) => request(`/api/routes/${id}/cooldown/clear`, { method: 'POST' }),
  batchUpdateRoutes: (data: { ids: number[]; action: 'enable' | 'disable' }) =>
    request('/api/routes/batch', { method: 'POST', body: JSON.stringify(data) }),
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
  getProxyDebugTraces: (params?: { limit?: number }) => request(`/api/stats/proxy-debug/traces${buildQueryString(params)}`) as Promise<ProxyDebugTracesResponse>,
  getProxyDebugTraceDetail: (id: number) => request(`/api/stats/proxy-debug/traces/${id}`) as Promise<ProxyDebugTraceDetail>,
  checkModels: (accountId: number) => request(`/api/models/check/${accountId}`, { method: 'POST' }),
  getSiteDistribution: () => request('/api/stats/site-distribution'),
  getSiteTrend: (days = 7) => request(`/api/stats/site-trend?days=${days}`),
  getModelBySite: (siteId?: number, days = 7) =>
    request(`/api/stats/model-by-site?${siteId ? `siteId=${siteId}&` : ''}days=${days}`),

  // Search
  search: (query: string) => request('/api/search', { method: 'POST', body: JSON.stringify({ query, limit: 20 }) }),

  // OAuth
  getOAuthProviders: () => request('/api/oauth/providers') as Promise<{ providers: OAuthProviderInfo[] }>,
  startOAuthProvider: (provider: string, data?: { accountId?: number; projectId?: string; proxyUrl?: string | null }) => request(`/api/oauth/providers/${encodeURIComponent(provider)}/start`, {
    method: 'POST',
    body: JSON.stringify(data || {}),
  }) as Promise<OAuthStartResponse>,
  getOAuthSession: (state: string) => request(`/api/oauth/sessions/${encodeURIComponent(state)}`) as Promise<OAuthSessionInfo>,
  submitOAuthManualCallback: (state: string, callbackUrl: string) => request(`/api/oauth/sessions/${encodeURIComponent(state)}/manual-callback`, {
    method: 'POST',
    body: JSON.stringify({ callbackUrl }),
  }) as Promise<{ success: true }>,
  getOAuthConnections: (params?: { limit?: number; offset?: number }) =>
    request(`/api/oauth/connections${buildQueryString(params)}`) as Promise<OAuthConnectionsResponse>,
  refreshOAuthConnectionQuota: (accountId: number) => request(`/api/oauth/connections/${accountId}/quota/refresh`, {
    method: 'POST',
    body: JSON.stringify({}),
  }) as Promise<{ success: true; quota: OAuthQuotaInfo }>,
  rebindOAuthConnection: (accountId: number, data?: { proxyUrl?: string | null }) => request(`/api/oauth/connections/${accountId}/rebind`, {
    method: 'POST',
    body: JSON.stringify(data || {}),
  }) as Promise<OAuthStartResponse>,
  deleteOAuthConnection: (accountId: number) => request(`/api/oauth/connections/${accountId}`, {
    method: 'DELETE',
  }) as Promise<{ success: true }>,

  // Events
  getEvents: (params?: string) => request(`/api/events${params ? '?' + params : ''}`),
  getEventCount: () => request('/api/events/count'),
  markEventRead: (id: number) => request(`/api/events/${id}/read`, { method: 'POST' }),
  markAllEventsRead: () => request('/api/events/read-all', { method: 'POST' }),
  clearEvents: () => request('/api/events', { method: 'DELETE' }),
  getSiteAnnouncements: (params?: string) => request(`/api/site-announcements${params ? '?' + params : ''}`),
  markSiteAnnouncementRead: (id: number) => request(`/api/site-announcements/${id}/read`, { method: 'POST' }),
  markAllSiteAnnouncementsRead: () => request('/api/site-announcements/read-all', { method: 'POST' }),
  clearSiteAnnouncements: () => request('/api/site-announcements', { method: 'DELETE' }),
  syncSiteAnnouncements: (payload?: { siteId?: number }) => request('/api/site-announcements/sync', {
    method: 'POST',
    body: JSON.stringify(payload || {}),
  }),
  getTasks: (limit = 50) => request(`/api/tasks?limit=${Math.max(1, Math.min(200, Math.trunc(limit)))}`),
  getTask: (id: string) => request(`/api/tasks/${encodeURIComponent(id)}`),

  // Auth management
  getAuthInfo: () => request('/api/settings/auth/info'),
  changeAuthToken: (oldToken: string, newToken: string) => request('/api/settings/auth/change', {
    method: 'POST', body: JSON.stringify({ oldToken, newToken }),
  }),
  getRuntimeSettings: () => request('/api/settings/runtime'),
  getBrandList: () => request('/api/settings/brand-list'),
  updateRuntimeSettings: (data: RuntimeSettingsPayload) => request('/api/settings/runtime', {
    method: 'PUT',
    body: JSON.stringify(data),
  }),
  getUpdateCenterStatus: () => request('/api/update-center/status'),
  saveUpdateCenterConfig: (data: any) => request('/api/update-center/config', {
    method: 'PUT',
    body: JSON.stringify(data),
  }),
  checkUpdateCenter: () => request('/api/update-center/check', {
    method: 'POST',
    body: JSON.stringify({}),
  }),
  deployUpdateCenter: (data: {
    source: 'github-release' | 'docker-hub-tag';
    targetTag: string;
    targetDigest?: string | null;
  }) => request('/api/update-center/deploy', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  rollbackUpdateCenter: (data: { targetRevision: string }) => request('/api/update-center/rollback', {
    method: 'POST',
    body: JSON.stringify(data),
  }),
  streamUpdateCenterTaskLogs: (
    taskId: string,
    handlers: {
      onLog?: (entry: any) => void;
      onDone?: (payload: any) => void;
      signal?: AbortSignal;
    },
  ) => streamSse(`/api/update-center/tasks/${encodeURIComponent(taskId)}/stream`, handlers),
  testSystemProxy: (data: SystemProxyTestRequest) => request('/api/settings/system-proxy/test', {
    method: 'POST',
    body: JSON.stringify(data),
    timeoutMs: 20_000,
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
  getBackupWebdavConfig: () => request('/api/settings/backup/webdav'),
  saveBackupWebdavConfig: (data: {
    enabled: boolean;
    fileUrl: string;
    username: string;
    password?: string;
    clearPassword?: boolean;
    exportType: 'all' | 'accounts' | 'preferences';
    autoSyncEnabled: boolean;
    autoSyncCron: string;
  }) =>
    request('/api/settings/backup/webdav', {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  exportBackupToWebdav: (type?: 'all' | 'accounts' | 'preferences') =>
    request('/api/settings/backup/webdav/export', {
      method: 'POST',
      body: JSON.stringify(type ? { type } : {}),
      timeoutMs: 60_000,
    }),
  importBackupFromWebdav: () =>
    request('/api/settings/backup/webdav/import', {
      method: 'POST',
      body: JSON.stringify({}),
      timeoutMs: 60_000,
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
  getProxyFileContentDataUrl: async (
    fileId: string,
    options: Pick<RequestOptions, 'signal' | 'timeoutMs'> = {},
  ) => {
    const response = await fetchAuthenticatedResponse(`/v1/files/${encodeURIComponent(fileId)}/content`, {
      method: 'GET',
      ...options,
    });
    if (!response.ok) {
      throw new Error(await extractResponseErrorMessage(response));
    }

    const mimeType = (response.headers.get('content-type') || 'application/octet-stream')
      .split(';')[0]
      .trim() || 'application/octet-stream';
    const filename = parseContentDispositionFilename(response.headers.get('content-disposition'));
    const base64 = arrayBufferToBase64(await response.arrayBuffer());
    return {
      filename,
      mimeType,
      data: `data:${mimeType};base64,${base64}`,
    };
  },
  testProxy: proxyTestRequest,
  proxyTest: proxyTestRequest,
  testChat: (data: TestChatRequestPayload) =>
    request('/api/test/chat', { method: 'POST', body: JSON.stringify(data) }),
  testProxyStream: proxyTestStreamRequest,
  proxyTestStream: proxyTestStreamRequest,
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
