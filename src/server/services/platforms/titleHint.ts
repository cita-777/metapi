import { stripTrailingSlashes } from '../urlNormalization.js';

export type TitleHintPlatform =
  | 'anyrouter'
  | 'done-hub'
  | 'one-hub'
  | 'veloera'
  | 'sub2api'
  | 'new-api'
  | 'one-api';

type TitleRule = {
  platform: TitleHintPlatform;
  regex: RegExp;
};

const TITLE_RULES: TitleRule[] = [
  { platform: 'anyrouter', regex: /\bany\s*router\b/i },
  { platform: 'done-hub', regex: /\bdone[-_ ]?hub\b/i },
  { platform: 'one-hub', regex: /\bone[-_ ]?hub\b/i },
  { platform: 'veloera', regex: /\bveloera\b/i },
  { platform: 'sub2api', regex: /\bsub2api\b/i },
  { platform: 'new-api', regex: /\bnew[-_ ]?api\b/i },
  { platform: 'new-api', regex: /\bvo[-_ ]?api\b/i },
  { platform: 'new-api', regex: /\bsuper[-_ ]?api\b/i },
  { platform: 'new-api', regex: /\brix[-_ ]?api\b/i },
  { platform: 'new-api', regex: /\bneo[-_ ]?api\b/i },
  { platform: 'new-api', regex: /wong\s*(?:\u516c\u76ca\u7ad9)/i },
  { platform: 'one-api', regex: /\bone[-_ ]?api\b/i },
];

function normalizeBaseUrl(url: string): string {
  const trimmed = (url || '').trim();
  if (!trimmed) return '';
  try {
    const parsed = new URL(trimmed);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return stripTrailingSlashes(trimmed);
  }
}

function extractHtmlTitle(html: string): string {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match?.[1]) return '';
  return match[1].replace(/\s+/g, ' ').trim();
}

async function detectPlatformByTitleOnce(base: string): Promise<TitleHintPlatform | undefined> {
  try {
    const { fetch } = await import('undici');
    const res = await fetch(`${base}/`, {
      method: 'GET',
      headers: { Accept: 'text/html,application/xhtml+xml,*/*;q=0.8' },
      signal: AbortSignal.timeout(5000),
    });
    const contentType = (res.headers.get('content-type') || '').toLowerCase();
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml+xml')) {
      return undefined;
    }

    const title = extractHtmlTitle(await res.text());
    if (!title) return undefined;

    for (const rule of TITLE_RULES) {
      if (rule.regex.test(title)) return rule.platform;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export async function detectPlatformByTitle(url: string): Promise<TitleHintPlatform | undefined> {
  const base = normalizeBaseUrl(url);
  if (!base) return undefined;

  const first = await detectPlatformByTitleOnce(base);
  if (first) return first;

  // Under heavy parallel test load, local title probes can occasionally race
  // with just-started ephemeral HTTP servers. Retry once before giving up.
  await new Promise((resolve) => setTimeout(resolve, 50));
  return detectPlatformByTitleOnce(base);
}
