import type { CliProfileDefinition } from './types.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isGeminiCliPath(path: string): boolean {
  const normalizedPath = path.trim().toLowerCase();
  return normalizedPath === '/v1internal:generatecontent'
    || normalizedPath === '/v1internal:streamgeneratecontent'
    || normalizedPath === '/v1internal:counttokens';
}

function hasGeminiCliBodyShape(body: unknown): boolean {
  if (!isRecord(body)) return false;
  return typeof body.model === 'string'
    || Array.isArray(body.contents)
    || (isRecord(body.request) && (Array.isArray(body.request.contents) || typeof body.request.model === 'string'));
}

export const geminiCliProfile: CliProfileDefinition = {
  id: 'gemini_cli',
  capabilities: {
    supportsResponsesCompact: false,
    supportsResponsesWebsocketIncremental: false,
    preservesContinuation: false,
    supportsCountTokens: true,
    echoesTurnState: false,
  },
  detect(input) {
    if (!isGeminiCliPath(input.downstreamPath)) return null;
    if (input.body !== undefined && !hasGeminiCliBodyShape(input.body)) return null;
    return {
      id: 'gemini_cli',
      clientAppId: 'gemini_cli',
      clientAppName: 'Gemini CLI',
      clientConfidence: 'exact',
    };
  },
};
