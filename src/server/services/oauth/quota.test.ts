import { describe, expect, it } from 'vitest';
import {
  buildQuotaSnapshotFromOauthInfo,
  parseCodexQuotaResetHint,
} from './quota.js';

function buildJwt(payload: Record<string, unknown>) {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value))
    .toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.signature`;
}

describe('oauth quota snapshot helpers', () => {
  it('builds a codex quota snapshot from stored id_token claims and reset hint', () => {
    const snapshot = buildQuotaSnapshotFromOauthInfo({
      provider: 'codex',
      planType: 'plus',
      idToken: buildJwt({
        email: 'codex-user@example.com',
        'https://api.openai.com/auth': {
          chatgpt_account_id: 'chatgpt-account-123',
          chatgpt_plan_type: 'plus',
          chatgpt_subscription_active_start: '2026-03-01T00:00:00.000Z',
          chatgpt_subscription_active_until: '2026-04-01T00:00:00.000Z',
        },
      }),
      quota: {
        status: 'supported',
        source: 'reverse_engineered',
        lastSyncAt: '2026-03-18T01:00:00.000Z',
        lastLimitResetAt: '2026-03-18T05:00:00.000Z',
        providerMessage: 'current codex oauth signals do not expose stable 5h/7d remaining values',
        windows: {
          fiveHour: {
            supported: false,
            message: 'official 5h quota window is not exposed by current codex oauth artifacts',
          },
          sevenDay: {
            supported: false,
            message: 'official 7d quota window is not exposed by current codex oauth artifacts',
          },
        },
      },
    });

    expect(snapshot).toEqual({
      status: 'supported',
      source: 'reverse_engineered',
      lastSyncAt: '2026-03-18T01:00:00.000Z',
      lastLimitResetAt: '2026-03-18T05:00:00.000Z',
      providerMessage: 'current codex oauth signals do not expose stable 5h/7d remaining values',
      subscription: {
        planType: 'plus',
        activeStart: '2026-03-01T00:00:00.000Z',
        activeUntil: '2026-04-01T00:00:00.000Z',
      },
      windows: {
        fiveHour: {
          supported: false,
          message: 'official 5h quota window is not exposed by current codex oauth artifacts',
        },
        sevenDay: {
          supported: false,
          message: 'official 7d quota window is not exposed by current codex oauth artifacts',
        },
      },
    });
  });

  it('returns unsupported snapshots for non-codex providers', () => {
    const snapshot = buildQuotaSnapshotFromOauthInfo({
      provider: 'antigravity',
      planType: 'pro',
    });

    expect(snapshot).toEqual({
      status: 'unsupported',
      source: 'official',
      providerMessage: 'official quota windows are not exposed for antigravity oauth',
      windows: {
        fiveHour: {
          supported: false,
          message: 'official 5h quota window is unavailable for this provider',
        },
        sevenDay: {
          supported: false,
          message: 'official 7d quota window is unavailable for this provider',
        },
      },
    });
  });

  it('parses codex usage_limit_reached reset hints', () => {
    const reset = parseCodexQuotaResetHint(429, JSON.stringify({
      error: {
        type: 'usage_limit_reached',
        resets_at: 1773800400,
      },
    }));

    expect(reset).toEqual({
      resetAt: '2026-03-18T02:20:00.000Z',
      message: 'codex usage_limit_reached reset hint observed from upstream',
    });
  });
});
