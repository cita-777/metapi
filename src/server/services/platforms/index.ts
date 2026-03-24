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
import { GeminiCliAdapter } from './geminiCli.js';
import { AntigravityAdapter } from './antigravity.js';
import { CliProxyApiAdapter } from './cliproxyapi.js';
import { detectPlatformByTitle } from './titleHint.js';
import { detectPlatformByUrlHint, normalizePlatformAlias } from '../../../shared/platformIdentity.js';

const adapters: PlatformAdapter[] = [
  // Specific forks before generic adapters for better auto-detection.
  new OpenAiAdapter(),
  new CodexAdapter(),
  new ClaudeAdapter(),
  new GeminiAdapter(),
  new GeminiCliAdapter(),
  new AntigravityAdapter(),
  new CliProxyApiAdapter(),
  new AnyRouterAdapter(),
  new DoneHubAdapter(),
  new OneHubAdapter(),
  new VeloeraAdapter(),
  new NewApiAdapter(),
  new Sub2ApiAdapter(),
  new OneApiAdapter(),
];

function normalizePlatform(platform: string): string {
  return normalizePlatformAlias(platform);
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
