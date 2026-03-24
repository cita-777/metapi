import type { CliProfileDefinition, DetectCliProfileInput } from './types.js';

type CodexOfficialClientApp = {
  clientAppId: string;
  clientAppName: string;
};

const CODEX_OFFICIAL_CLIENT_USER_AGENT_PREFIXES = [
  'codex_cli_rs/',
  'codex_vscode/',
  'codex_app/',
  'codex_chatgpt_desktop/',
  'codex_atlas/',
  'codex_exec/',
  'codex_sdk_ts/',
  'codex ',
];

const CODEX_OFFICIAL_CLIENT_ORIGINATOR_PREFIXES = [
  'codex_',
  'codex ',
];

const CODEX_OFFICIAL_CLIENT_APP_RULES = [
  {
    id: 'codex_cli_rs',
    name: 'Codex CLI',
    userAgentPrefixes: ['codex_cli_rs/'],
    originatorPrefixes: ['codex_cli_rs'],
  },
  {
    id: 'codex_vscode',
    name: 'Codex VSCode',
    userAgentPrefixes: ['codex_vscode/'],
    originatorPrefixes: ['codex_vscode'],
  },
  {
    id: 'codex_app',
    name: 'Codex App',
    userAgentPrefixes: ['codex_app/'],
    originatorPrefixes: ['codex_app'],
  },
  {
    id: 'codex_chatgpt_desktop',
    name: 'Codex Desktop',
    userAgentPrefixes: ['codex_chatgpt_desktop/', 'codex desktop/'],
    originatorPrefixes: ['codex_chatgpt_desktop', 'codex desktop'],
  },
  {
    id: 'codex_atlas',
    name: 'Codex Atlas',
    userAgentPrefixes: ['codex_atlas/'],
    originatorPrefixes: ['codex_atlas'],
  },
  {
    id: 'codex_exec',
    name: 'Codex Exec',
    userAgentPrefixes: ['codex_exec/'],
    originatorPrefixes: ['codex_exec'],
  },
  {
    id: 'codex_sdk_ts',
    name: 'Codex SDK TS',
    userAgentPrefixes: ['codex_sdk_ts/'],
    originatorPrefixes: ['codex_sdk_ts'],
  },
] as const;

function headerValueToStrings(value: unknown): string[] {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }

  if (Array.isArray(value)) {
    const values: string[] = [];
    for (const item of value) {
      if (typeof item !== 'string') continue;
      const trimmed = item.trim();
      if (trimmed) values.push(trimmed);
    }
    return values;
  }

  return [];
}

function headerValueToString(value: unknown): string | null {
  return headerValueToStrings(value)[0] || null;
}

function getHeaderValue(headers: Record<string, unknown> | undefined, targetKey: string): string | null {
  return getHeaderValues(headers, targetKey)[0] || null;
}

function getHeaderValues(headers: Record<string, unknown> | undefined, targetKey: string): string[] {
  if (!headers) return [];
  const normalizedTarget = targetKey.trim().toLowerCase();
  const values: string[] = [];

  for (const [rawKey, rawValue] of Object.entries(headers)) {
    if (rawKey.trim().toLowerCase() !== normalizedTarget) continue;
    values.push(...headerValueToStrings(rawValue));
  }
  return values;
}

function hasHeaderPrefix(headers: Record<string, unknown> | undefined, prefix: string): boolean {
  if (!headers) return false;
  const normalizedPrefix = prefix.trim().toLowerCase();
  return Object.entries(headers).some(([rawKey, rawValue]) => {
    const key = rawKey.trim().toLowerCase();
    return key.startsWith(normalizedPrefix) && !!headerValueToString(rawValue);
  });
}

function matchesHeaderPrefixes(value: string | string[] | null, prefixes: readonly string[]): boolean {
  const values = Array.isArray(value)
    ? value.map((item) => item.trim().toLowerCase()).filter(Boolean)
    : [value?.trim().toLowerCase() || ''].filter(Boolean);
  if (values.length === 0) return false;

  return values.some((normalizedValue) => prefixes.some((prefix) => {
    const normalizedPrefix = prefix.trim().toLowerCase();
    if (!normalizedPrefix) return false;
    return normalizedValue.startsWith(normalizedPrefix)
      || normalizedValue.includes(normalizedPrefix);
  }));
}

function isCodexPath(path: string): boolean {
  const normalizedPath = path.trim().toLowerCase();
  return normalizedPath.startsWith('/v1/responses')
    || normalizedPath === '/v1/chat/completions'
    || normalizedPath.startsWith('/v1/messages');
}

export function detectCodexOfficialClientApp(
  headers?: Record<string, unknown>,
): CodexOfficialClientApp | null {
  for (const rule of CODEX_OFFICIAL_CLIENT_APP_RULES) {
    const matchesOriginator = matchesHeaderPrefixes(getHeaderValues(headers, 'originator'), rule.originatorPrefixes);
    const matchesUserAgent = matchesHeaderPrefixes(getHeaderValues(headers, 'user-agent'), rule.userAgentPrefixes);
    if (!matchesOriginator && !matchesUserAgent) continue;
    return {
      clientAppId: rule.id,
      clientAppName: rule.name,
    };
  }
  return null;
}

export function isCodexResponsesSurface(headers?: Record<string, unknown>): boolean {
  return isCodexRequest({
    downstreamPath: '/v1/responses',
    headers,
  });
}

export function getCodexSessionId(headers?: Record<string, unknown>): string | null {
  return getHeaderValue(headers, 'session_id') || getHeaderValue(headers, 'session-id');
}

export function isCodexRequest(input: DetectCliProfileInput): boolean {
  if (!isCodexPath(input.downstreamPath)) return false;
  const headers = input.headers;
  if (!headers) return false;

  const originator = getHeaderValues(headers, 'originator');
  if (matchesHeaderPrefixes(originator, CODEX_OFFICIAL_CLIENT_ORIGINATOR_PREFIXES)) return true;
  if (matchesHeaderPrefixes(getHeaderValues(headers, 'user-agent'), CODEX_OFFICIAL_CLIENT_USER_AGENT_PREFIXES)) return true;
  if (getHeaderValue(headers, 'openai-beta')) return true;
  if (hasHeaderPrefix(headers, 'x-stainless-')) return true;
  if (getCodexSessionId(headers)) return true;
  if (getHeaderValue(headers, 'x-codex-turn-state')) return true;
  return false;
}

export const codexCliProfile: CliProfileDefinition = {
  id: 'codex',
  capabilities: {
    supportsResponsesCompact: true,
    supportsResponsesWebsocketIncremental: true,
    preservesContinuation: true,
    supportsCountTokens: false,
    echoesTurnState: true,
  },
  detect(input) {
    if (!isCodexRequest(input)) return null;

    const sessionId = getCodexSessionId(input.headers) || undefined;
    const clientApp = detectCodexOfficialClientApp(input.headers);
    return {
      id: 'codex',
      ...(sessionId ? { sessionId, traceHint: sessionId } : {}),
      ...(clientApp
        ? {
          clientAppId: clientApp.clientAppId,
          clientAppName: clientApp.clientAppName,
          clientConfidence: 'exact' as const,
        }
        : {
          clientAppId: 'codex',
          clientAppName: 'Codex',
          clientConfidence: 'heuristic' as const,
        }),
    };
  },
};
