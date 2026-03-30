import { fetch } from 'undici';
import { schema } from '../db/index.js';
import { withSiteRecordProxyRequestInit } from './siteProxy.js';
import { getOauthInfoFromAccount } from './oauth/oauthAccount.js';
import { CLAUDE_DEFAULT_ANTHROPIC_VERSION } from './oauth/claudeProvider.js';
import {
  ANTIGRAVITY_DAILY_UPSTREAM_BASE_URL,
  ANTIGRAVITY_MODELS_USER_AGENT,
  ANTIGRAVITY_SANDBOX_DAILY_UPSTREAM_BASE_URL,
  ANTIGRAVITY_UPSTREAM_BASE_URL,
} from './oauth/antigravityProvider.js';
import {
  GEMINI_CLI_GOOGLE_API_CLIENT,
  GEMINI_CLI_REQUIRED_SERVICE,
  GEMINI_CLI_USER_AGENT,
} from './oauth/geminiCliProvider.js';

type PlatformDiscoverySite = typeof schema.sites.$inferSelect;
type PlatformDiscoveryAccount = typeof schema.accounts.$inferSelect;

function normalizeDiscoveredModels(models: string[]): string[] {
  const normalizedModels: string[] = [];
  const seen = new Set<string>();

  for (const rawModel of models) {
    if (typeof rawModel !== 'string') continue;
    const modelName = rawModel.trim();
    if (!modelName) continue;

    const dedupeKey = modelName.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    normalizedModels.push(modelName);
  }

  return normalizedModels;
}

function normalizeBaseUrl(baseUrl: string): string {
  return (baseUrl || '').replace(/\/+$/, '');
}

function buildCodexModelsEndpoint(baseUrl: string): string {
  const normalized = normalizeBaseUrl(baseUrl);
  return `${normalized}/models?client_version=${encodeURIComponent('1.0.0')}`;
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

function extractClaudeModelIds(payload: unknown): string[] {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return [];
  const record = payload as { data?: unknown };
  if (!Array.isArray(record.data)) return [];

  return record.data.flatMap((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return [];
    const value = item as { id?: unknown; name?: unknown };
    const id = typeof value.id === 'string'
      ? value.id.trim()
      : (typeof value.name === 'string' ? value.name.trim() : '');
    return id ? [id] : [];
  });
}

function extractAntigravityModelIds(payload: unknown): string[] {
  if (!payload || typeof payload !== 'object') return [];
  const record = payload as { models?: unknown };
  if (record.models && typeof record.models === 'object' && !Array.isArray(record.models)) {
    return Object.keys(record.models).map((name) => name.trim()).filter(Boolean);
  }
  if (!Array.isArray(record.models)) return [];
  return record.models.flatMap((item) => {
    if (typeof item === 'string') {
      const trimmed = item.trim();
      return trimmed ? [trimmed] : [];
    }
    if (!item || typeof item !== 'object' || Array.isArray(item)) return [];
    const value = item as { id?: unknown; name?: unknown };
    const id = typeof value.id === 'string'
      ? value.id.trim()
      : (typeof value.name === 'string' ? value.name.trim() : '');
    return id ? [id] : [];
  });
}

function buildAntigravityDiscoveryBaseUrls(siteUrl: string): string[] {
  const seen = new Set<string>();
  return [
    siteUrl,
    ANTIGRAVITY_UPSTREAM_BASE_URL,
    ANTIGRAVITY_DAILY_UPSTREAM_BASE_URL,
    ANTIGRAVITY_SANDBOX_DAILY_UPSTREAM_BASE_URL,
  ].flatMap((candidate) => {
    const normalized = normalizeBaseUrl(candidate);
    if (!normalized || seen.has(normalized)) return [];
    seen.add(normalized);
    return [normalized];
  });
}

export async function discoverCodexModelsFromCloud(input: {
  site: PlatformDiscoverySite;
  account: PlatformDiscoveryAccount;
}): Promise<string[]> {
  const accessToken = (input.account.accessToken || '').trim();
  if (!accessToken) {
    throw new Error('codex oauth access token missing');
  }
  const oauth = getOauthInfoFromAccount(input.account);
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
  return normalizeDiscoveredModels(extractCodexModelIds(await response.json()));
}

export async function discoverClaudeModelsFromCloud(input: {
  site: PlatformDiscoverySite;
  account: PlatformDiscoveryAccount;
}): Promise<string[]> {
  const accessToken = (input.account.accessToken || '').trim();
  if (!accessToken) {
    throw new Error('claude oauth access token missing');
  }
  const response = await fetch(
    `${input.site.url.replace(/\/+$/, '')}/v1/models`,
    withSiteRecordProxyRequestInit(input.site, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'anthropic-version': CLAUDE_DEFAULT_ANTHROPIC_VERSION,
      },
    }),
  );
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`HTTP ${response.status}: ${text || 'claude oauth model discovery failed'}`);
  }
  return normalizeDiscoveredModels(extractClaudeModelIds(await response.json()));
}

export async function validateGeminiCliOauthConnection(input: {
  site: PlatformDiscoverySite;
  account: PlatformDiscoveryAccount;
}): Promise<void> {
  const accessToken = (input.account.accessToken || '').trim();
  if (!accessToken) {
    throw new Error('gemini cli oauth access token missing');
  }
  const oauth = getOauthInfoFromAccount(input.account);
  const projectId = (oauth?.projectId || '').trim();
  if (!projectId) {
    throw new Error('gemini cli oauth project id missing');
  }
  const response = await fetch(
    `https://serviceusage.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/services/${encodeURIComponent(GEMINI_CLI_REQUIRED_SERVICE)}`,
    withSiteRecordProxyRequestInit(input.site, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'User-Agent': GEMINI_CLI_USER_AGENT,
        'X-Goog-Api-Client': GEMINI_CLI_GOOGLE_API_CLIENT,
      },
    }),
  );
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`HTTP ${response.status}: ${text || 'gemini cli oauth validation failed'}`);
  }
  const payload = await response.json() as { state?: unknown };
  if (String(payload.state || '').trim().toUpperCase() !== 'ENABLED') {
    throw new Error(`Cloud AI API not enabled for project ${projectId}`);
  }
}

export async function discoverAntigravityModelsFromCloud(input: {
  site: PlatformDiscoverySite;
  account: PlatformDiscoveryAccount;
}): Promise<string[]> {
  const accessToken = (input.account.accessToken || '').trim();
  if (!accessToken) {
    throw new Error('antigravity oauth access token missing');
  }

  const oauth = getOauthInfoFromAccount(input.account);
  const projectId = (oauth?.projectId || '').trim();
  const requestBody = projectId ? { project: projectId } : {};
  let lastError = '';

  for (const baseUrl of buildAntigravityDiscoveryBaseUrls(input.site.url || ANTIGRAVITY_UPSTREAM_BASE_URL)) {
    try {
      const response = await fetch(
        `${baseUrl}/v1internal:fetchAvailableModels`,
        withSiteRecordProxyRequestInit(input.site, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': ANTIGRAVITY_MODELS_USER_AGENT,
          },
          body: JSON.stringify(requestBody),
        }),
      );
      if (!response.ok) {
        lastError = await response.text().catch(() => '') || `HTTP ${response.status}`;
        continue;
      }

      const payload = await response.json();
      const models = normalizeDiscoveredModels(extractAntigravityModelIds(payload));
      if (models.length > 0) {
        return models;
      }
      lastError = '未获取到可用模型';
    } catch (error) {
      lastError = error instanceof Error ? `${baseUrl}: ${error.message}` : String(error);
    }
  }

  throw new Error(lastError || '未获取到可用模型');
}
