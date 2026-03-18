import { schema } from '../../db/index.js';
import {
  buildOauthInfo,
  getOauthInfoFromExtraConfig,
  isOauthProvider,
  type OauthInfo,
} from './oauthAccount.js';

export type CodexOauthInfo = OauthInfo & {
  provider: 'codex';
};

export function getCodexOauthInfoFromExtraConfig(extraConfig?: string | null): CodexOauthInfo | null {
  const oauth = getOauthInfoFromExtraConfig(extraConfig);
  if (!oauth || oauth.provider !== 'codex') return null;
  return oauth as CodexOauthInfo;
}

export function isCodexPlatform(
  account: Pick<typeof schema.accounts.$inferSelect, 'extraConfig'> | string | null | undefined,
): boolean {
  return isOauthProvider(account, 'codex');
}

export function buildCodexOauthInfo(
  extraConfig?: string | null,
  patch: Partial<CodexOauthInfo> = {},
): CodexOauthInfo {
  return buildOauthInfo(extraConfig, { provider: 'codex', ...patch }) as CodexOauthInfo;
}
