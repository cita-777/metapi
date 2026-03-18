import { extractClaudeCodeSessionId as extractClaudeCodeSessionIdViaProfile } from '../../proxy-core/cliProfiles/claudeCodeProfile.js';
import {
  detectCliProfile,
} from '../../proxy-core/cliProfiles/registry.js';
import { isCodexResponsesSurface as isCodexResponsesSurfaceViaProfile } from '../../proxy-core/cliProfiles/codexProfile.js';
import type { CliProfileId } from '../../proxy-core/cliProfiles/types.js';

export type DownstreamClientKind = CliProfileId;

export type DownstreamClientContext = {
  clientKind: DownstreamClientKind;
  sessionId?: string;
  traceHint?: string;
};

export function isCodexResponsesSurface(headers?: Record<string, unknown>): boolean {
  return isCodexResponsesSurfaceViaProfile(headers);
}

export function extractClaudeCodeSessionId(userId: string): string | null {
  return extractClaudeCodeSessionIdViaProfile(userId);
}

export function detectDownstreamClientContext(input: {
  downstreamPath: string;
  headers?: Record<string, unknown>;
  body?: unknown;
}): DownstreamClientContext {
  const detected = detectCliProfile(input);
  return {
    clientKind: detected.id,
    ...(detected.sessionId ? { sessionId: detected.sessionId } : {}),
    ...(detected.traceHint ? { traceHint: detected.traceHint } : {}),
  };
}
