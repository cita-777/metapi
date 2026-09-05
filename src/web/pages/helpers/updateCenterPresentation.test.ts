import { describe, expect, it } from 'vitest';

import { buildUpdateReminder, describeUpdateState } from './updateCenterPresentation.js';

describe('updateCenterPresentation', () => {
  it('waits for a release when no check has completed', () => {
    expect(buildUpdateReminder({ currentVersion: '1.2.3', latestRelease: null })).toMatchObject({
      label: '等待检查',
      highlight: false,
    });
  });

  it('enables one-click update for a newer stable release', () => {
    const state = describeUpdateState({
      enabled: true,
      supported: true,
      currentVersion: '1.2.3',
      candidate: {
        normalizedVersion: '1.3.0',
        displayVersion: '1.3.0',
        tagName: 'v1.3.0',
      },
    });
    expect(state.kind).toBe('new-version');
    expect(state.canDeploy).toBe(true);
  });

  it('disables actions when the runtime is not supported', () => {
    const state = describeUpdateState({
      enabled: true,
      supported: false,
      reason: 'runtime volume is not persistent',
      currentVersion: '1.2.3',
      candidate: { normalizedVersion: '1.3.0' },
    });
    expect(state.kind).toBe('unsupported');
    expect(state.canDeploy).toBe(false);
    expect(state.reason).toContain('persistent');
  });

  it('reports current version when the release matches', () => {
    expect(describeUpdateState({
      enabled: true,
      supported: true,
      currentVersion: '1.3.0',
      candidate: { normalizedVersion: '1.3.0' },
    }).kind).toBe('same-version');
  });
});
