import type { CSSProperties } from 'react';
import { getBrand, normalizeBrandIconKey, type BrandInfo } from '../../components/BrandIcon.js';
import type { RouteRow, RouteChannel, RouteDecisionCandidate, ChannelDecisionState, RouteSummaryRow } from './types.js';

export const AUTO_ROUTE_DECISION_LIMIT = 80;
export const ROUTE_RENDER_CHUNK = 40;
export const ROUTE_BRAND_ICON_PREFIX = 'brand:';

export const ENDPOINT_TYPE_ICON_MODEL_MAP: Record<string, string> = {
  openai: 'chatgpt',
  gemini: 'gemini',
  anthropic: 'claude',
  anthroic: 'claude',
  claude: 'claude',
};

export const PLATFORM_ENDPOINT_FALLBACK_MAP: Record<string, string[]> = {
  openai: ['openai'],
  'new-api': ['openai'],
  'one-api': ['openai'],
  'one-hub': ['openai'],
  'done-hub': ['openai'],
  sub2api: ['openai'],
  veloera: ['openai'],
  cliproxyapi: ['openai'],
  claude: ['anthropic'],
  gemini: ['gemini'],
  anyrouter: ['openai', 'anthropic'],
};

export const PLATFORM_ALIASES: Record<string, string> = {
  anthropic: 'claude',
  google: 'gemini',
  'new api': 'new-api',
  newapi: 'new-api',
  'one api': 'one-api',
  oneapi: 'one-api',
};

export function isRegexModelPattern(modelPattern: string): boolean {
  return modelPattern.trim().toLowerCase().startsWith('re:');
}

export function isExactModelPattern(modelPattern: string): boolean {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (isRegexModelPattern(normalized)) return false;
  return !/[\*\?]/.test(normalized);
}

export function parseRegexModelPattern(modelPattern: string): { regex: RegExp | null; error: string | null } {
  if (!isRegexModelPattern(modelPattern)) return { regex: null, error: null };
  const body = modelPattern.trim().slice(3).trim();
  if (!body) return { regex: null, error: 're: 后缺少正则表达式' };
  try {
    return { regex: new RegExp(body), error: null };
  } catch (error) {
    return { regex: null, error: (error as Error)?.message || '无效正则' };
  }
}

function globToRegexSource(glob: string): string {
  let source = '';
  for (let i = 0; i < glob.length; i += 1) {
    const ch = glob[i];
    if (ch === '*') {
      source += '.*';
      continue;
    }
    if (ch === '?') {
      source += '.';
      continue;
    }
    if (ch === '[') {
      const closeIndex = glob.indexOf(']', i + 1);
      if (closeIndex > i + 1) {
        source += glob.slice(i, closeIndex + 1);
        i = closeIndex;
        continue;
      }
      source += '\\[';
      continue;
    }
    source += ch.replace(/[\\^$+?.()|{}]/g, '\\$&');
  }
  return source;
}

const compiledGlobCache = new Map<string, RegExp | null>();

function matchesGlobPattern(model: string, pattern: string): boolean {
  let re = compiledGlobCache.get(pattern);
  if (re === undefined) {
    try {
      re = new RegExp(`^${globToRegexSource(pattern)}$`);
    } catch {
      re = null;
    }
    compiledGlobCache.set(pattern, re);
  }
  return re ? re.test(model) : false;
}

const matchCache = new Map<string, boolean>();
const MATCH_CACHE_LIMIT = 4000;

export function matchesModelPattern(model: string, pattern: string): boolean {
  const normalized = (pattern || '').trim();
  if (!normalized) return false;
  if (normalized === model) return true;

  const cacheKey = `${model}\0${normalized}`;
  const cached = matchCache.get(cacheKey);
  if (cached !== undefined) return cached;

  let result: boolean;
  if (isRegexModelPattern(normalized)) {
    const parsed = parseRegexModelPattern(normalized);
    result = !!parsed.regex && parsed.regex.test(model);
  } else {
    result = matchesGlobPattern(model, normalized);
  }

  if (matchCache.size >= MATCH_CACHE_LIMIT) matchCache.clear();
  matchCache.set(cacheKey, result);
  return result;
}

export function getModelPatternError(modelPattern: string): string | null {
  const normalized = modelPattern.trim();
  if (!normalized) return null;
  if (!isRegexModelPattern(normalized)) return null;
  const parsed = parseRegexModelPattern(normalized);
  if (!parsed.error) return null;
  return `模型匹配正则错误：${parsed.error}`;
}

export function resolveRouteTitle(route: Pick<RouteRow | RouteSummaryRow, 'displayName' | 'modelPattern'>): string {
  const title = (route.displayName || '').trim();
  return title || route.modelPattern;
}

export function resolveRouteBrand(route: Pick<RouteRow | RouteSummaryRow, 'displayName' | 'modelPattern'>): BrandInfo | null {
  const displayName = (route.displayName || '').trim();
  if (displayName) {
    const byDisplayName = getBrand(displayName);
    if (byDisplayName) return byDisplayName;
  }
  return getBrand(route.modelPattern);
}

export function toBrandIconValue(icon: string): string {
  return `${ROUTE_BRAND_ICON_PREFIX}${icon}`;
}

export function parseBrandIconValue(raw: string): string | null {
  const normalized = (raw || '').trim();
  if (!normalized.startsWith(ROUTE_BRAND_ICON_PREFIX)) return null;
  const icon = normalized.slice(ROUTE_BRAND_ICON_PREFIX.length).trim();
  return normalizeBrandIconKey(icon);
}

export function normalizeRouteDisplayIconValue(raw: string | null | undefined): string {
  const normalized = (raw || '').trim();
  const brandIcon = parseBrandIconValue(normalized);
  if (brandIcon) return toBrandIconValue(brandIcon);
  return normalized;
}

export function resolveEndpointTypeIconModel(endpointType: string): string | null {
  const key = String(endpointType || '').trim().toLowerCase();
  if (!key) return null;
  return ENDPOINT_TYPE_ICON_MODEL_MAP[key] || null;
}

export function normalizePlatformKey(platform: string | null | undefined): string {
  const raw = String(platform || '').trim().toLowerCase();
  if (!raw) return '';
  return PLATFORM_ALIASES[raw] || raw;
}

export function inferEndpointTypesFromPlatform(platform: string | null | undefined): string[] {
  const key = normalizePlatformKey(platform);
  if (!key) return [];
  const mapped = PLATFORM_ENDPOINT_FALLBACK_MAP[key];
  if (Array.isArray(mapped) && mapped.length > 0) return mapped;

  if (key.includes('claude') || key.includes('anthropic')) return ['anthropic'];
  if (key.includes('gemini')) return ['gemini'];
  if (key.includes('openai') || key.includes('new-api') || key.includes('one-api')) return ['openai'];
  return [];
}

export function siteAvatarLetters(siteName: string): string {
  const normalized = String(siteName || '').trim();
  if (!normalized) return 'S';
  const parts = normalized.replace(/[-_/.]/g, ' ').split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
  const compact = normalized.replace(/\s+/g, '');
  return compact.slice(0, 2).toUpperCase();
}

export function resolveRouteIcon(route: Pick<RouteRow | RouteSummaryRow, 'displayIcon'>): { kind: 'none' } | { kind: 'text'; value: string } | { kind: 'brand'; value: string } {
  const icon = (route.displayIcon || '').trim();
  if (!icon) return { kind: 'none' };
  const brandIcon = parseBrandIconValue(icon);
  if (brandIcon) return { kind: 'brand', value: brandIcon };
  return { kind: 'text', value: icon };
}

export function normalizeChannels(channels: RouteChannel[]): RouteChannel[] {
  return [...(channels || [])].sort((a, b) => {
    const pa = a.priority ?? 0;
    const pb = b.priority ?? 0;
    if (pa === pb) return (a.id ?? 0) - (b.id ?? 0);
    return pa - pb;
  });
}

export function normalizeRoutes(routeRows: any[]): RouteRow[] {
  return (routeRows || []).map((route) => ({
    ...(route as RouteRow),
    channels: normalizeChannels(route.channels || []),
  }));
}

export function buildSourceGroupKey(routeId: number, sourceModel: string): string {
  const normalizedSourceModel = sourceModel.trim() || '__ungrouped__';
  return `${routeId}::${normalizedSourceModel}`;
}

export function getPriorityTagStyle(priority: number): CSSProperties {
  if (priority <= 0) {
    return {
      background: 'color-mix(in srgb, var(--color-success) 16%, transparent)',
      color: 'var(--color-success)',
    };
  }

  if (priority === 1) {
    return {
      background: 'color-mix(in srgb, var(--color-info) 16%, transparent)',
      color: 'var(--color-info)',
    };
  }

  return {
    background: 'rgba(100,116,139,0.18)',
    color: 'var(--color-text-secondary)',
  };
}

export function getProbabilityColor(probability: number): string {
  if (probability >= 80) return 'var(--color-success)';
  if (probability >= 60) return 'color-mix(in srgb, var(--color-success) 50%, var(--color-warning))';
  if (probability >= 40) return 'var(--color-warning)';
  if (probability >= 20) return 'color-mix(in srgb, var(--color-warning) 45%, var(--color-danger))';
  if (probability > 0) return 'var(--color-danger)';
  return 'var(--color-border)';
}

export function getChannelDecisionState(
  candidate: RouteDecisionCandidate | undefined,
  channel: RouteChannel,
  isExactRoute: boolean,
  loadingDecision: boolean,
): ChannelDecisionState {
  if (!isExactRoute && !candidate) {
    return {
      probability: 0,
      showBar: true,
      reasonText: loadingDecision ? '计算中...' : '实时决策',
      reasonColor: 'var(--color-text-muted)',
    };
  }

  if (!candidate) {
    return {
      probability: 0,
      showBar: true,
      reasonText: loadingDecision ? '计算中...' : '无可用通道',
      reasonColor: 'var(--color-text-muted)',
    };
  }

  if (candidate.avoidedByRecentFailure) {
    return {
      probability: 0,
      showBar: true,
      reasonText: '失败避让',
      reasonColor: 'var(--color-warning)',
    };
  }

  if (!candidate.eligible) {
    const nowIso = new Date().toISOString();
    const cooldownActive = !!channel.cooldownUntil && channel.cooldownUntil > nowIso;
    if (cooldownActive || candidate.reason.includes('冷却中')) {
      return {
        probability: 0,
        showBar: true,
        reasonText: '冷却中',
        reasonColor: 'var(--color-danger)',
      };
    }

    return {
      probability: 0,
      showBar: true,
      reasonText: candidate.reason || '不可用',
      reasonColor: 'var(--color-text-muted)',
    };
  }

  const probability = Number(candidate.probability || 0);
  if (probability <= 0) {
    if (candidate.recentlyFailed) {
      return {
        probability: 0,
        showBar: false,
        reasonText: '近期失败',
        reasonColor: 'var(--color-warning)',
      };
    }

    return {
      probability: 0,
      showBar: false,
      reasonText: candidate.reason || '概率为 0%',
      reasonColor: 'var(--color-text-muted)',
    };
  }

  return {
    probability,
    showBar: true,
    reasonText: '',
    reasonColor: 'var(--color-text-muted)',
  };
}
