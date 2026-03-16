import type { PlatformAdapter } from './base.js';
import { AnyRouterAdapter } from './anyrouter.js';
import { NewApiAdapter } from './newApi.js';
import { OneApiAdapter } from './oneApi.js';
import { VeloeraAdapter } from './veloera.js';
import { OneHubAdapter } from './oneHub.js';
import { DoneHubAdapter } from './doneHub.js';
import { Sub2ApiAdapter } from './sub2api.js';
import { OpenAiAdapter } from './openai.js';
import { CodexAdapter } from './codex.js';
import { ClaudeAdapter } from './claude.js';
import { GeminiAdapter } from './gemini.js';
import { CliProxyApiAdapter } from './cliproxyapi.js';
import { detectPlatformByTitle } from './titleHint.js';

const adapters: PlatformAdapter[] = [
  // Specific forks before generic adapters for better auto-detection.
  new OpenAiAdapter(),
  new CodexAdapter(),
  new ClaudeAdapter(),
  new GeminiAdapter(),
  new CliProxyApiAdapter(),
  new AnyRouterAdapter(),
  new DoneHubAdapter(),
  new OneHubAdapter(),
  new VeloeraAdapter(),
  new NewApiAdapter(),
  new Sub2ApiAdapter(),
  new OneApiAdapter(),
];

const platformAliases: Record<string, string> = {
  // NewAPI family aliases
  anyrouter: 'anyrouter',
  'wong-gongyi': 'new-api',
  'vo-api': 'new-api',
  'super-api': 'new-api',
  'rix-api': 'new-api',
  'neo-api': 'new-api',
  newapi: 'new-api',
  'new api': 'new-api',
  // OneAPI family aliases
  oneapi: 'one-api',
  'one api': 'one-api',
  // Keep canonical forms explicit for clarity
  'new-api': 'new-api',
  'one-api': 'one-api',
  veloera: 'veloera',
  'one-hub': 'one-hub',
  'done-hub': 'done-hub',
  sub2api: 'sub2api',
  // Official upstream APIs
  openai: 'openai',
  codex: 'codex',
  'chatgpt-codex': 'codex',
  'chatgpt codex': 'codex',
  anthropic: 'claude',
  claude: 'claude',
  gemini: 'gemini',
  google: 'gemini',
  // CLIProxyAPI aliases
  cliproxyapi: 'cliproxyapi',
  cpa: 'cliproxyapi',
  'cli-proxy-api': 'cliproxyapi',
};

function normalizePlatform(platform: string): string {
  const raw = (platform || '').trim().toLowerCase();
  return platformAliases[raw] ?? raw;
}

export function getAdapter(platform: string): PlatformAdapter | undefined {
  const normalized = normalizePlatform(platform);
  return adapters.find((a) => a.platformName === normalized);
}

const titleFirstPlatforms = new Set<string>([
  'anyrouter',
  'done-hub',
  'one-hub',
  'veloera',
  'sub2api',
]);

function detectPlatformByUrlHint(url: string): string | undefined {
  const normalized = (url || '').trim().toLowerCase();
  if (!normalized) return undefined;

  // Official upstream endpoints.
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

  // NewAPI-family forks and common aliases.
  if (normalized.includes('anyrouter')) return 'anyrouter';
  if (normalized.includes('donehub') || normalized.includes('done-hub')) return 'done-hub';
  if (normalized.includes('onehub') || normalized.includes('one-hub')) return 'one-hub';
  if (normalized.includes('veloera')) return 'veloera';
  if (normalized.includes('sub2api')) return 'sub2api';

  // CLIProxyAPI default local endpoints.
  if (normalized.includes('127.0.0.1:8317') || normalized.includes('localhost:8317')) return 'cliproxyapi';

  return undefined;
}

export async function detectPlatform(url: string): Promise<PlatformAdapter | undefined> {
  const urlHint = detectPlatformByUrlHint(url);
  if (urlHint) {
    return getAdapter(urlHint);
  }

  const titleHint = await detectPlatformByTitle(url);
  if (titleHint && titleFirstPlatforms.has(titleHint)) {
    return getAdapter(titleHint);
  }

  for (const adapter of adapters) {
    if (await adapter.detect(url)) return adapter;
  }

  if (titleHint) {
    return getAdapter(titleHint);
  }

  return undefined;
}
