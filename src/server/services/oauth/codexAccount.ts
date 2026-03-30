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

type OauthExtraConfigInput = Parameters<typeof getOauthInfoFromExtraConfig>[0];
type BuildOauthInfoInput = Parameters<typeof buildOauthInfo>[0];
type OauthIdentityCarrierLike = Pick<
  typeof schema.accounts.$inferSelect,
  'extraConfig' | 'oauthProvider' | 'oauthAccountKey' | 'oauthProjectId'
>;

function isOauthIdentityCarrierLike(value: unknown): value is OauthIdentityCarrierLike {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return 'extraConfig' in value
    || 'oauthProvider' in value
    || 'oauthAccountKey' in value
    || 'oauthProjectId' in value;
}

export function getCodexOauthInfoFromExtraConfig(extraConfig?: OauthExtraConfigInput): CodexOauthInfo | null {
  const oauth = getOauthInfoFromExtraConfig(extraConfig);
  if (!oauth || oauth.provider !== 'codex') return null;
  return oauth as CodexOauthInfo;
}

export function isCodexPlatform(
  account: OauthIdentityCarrierLike | OauthExtraConfigInput,
): boolean {
  if (!account || typeof account === 'string') {
    return isOauthProvider(account, 'codex');
  }
  if (isOauthIdentityCarrierLike(account)) {
    return isOauthProvider(account, 'codex');
  }
  return getCodexOauthInfoFromExtraConfig(account) !== null;
}

export function buildCodexOauthInfo(
  extraConfig?: BuildOauthInfoInput,
  patch: Partial<CodexOauthInfo> = {},
): CodexOauthInfo {
  return buildOauthInfo(extraConfig, { provider: 'codex', ...patch }) as CodexOauthInfo;
}

export type {
  OauthExtraConfigInput,
  OauthIdentityCarrierLike,
};
