import { describe, expect, it } from 'vitest';

import {
  buildUpdateReminder,
  describeDockerDeployState,
} from './updateCenterPresentation.js';

describe('updateCenterPresentation', () => {
  it('returns an unknown reminder when no candidate source data is available', () => {
    expect(buildUpdateReminder({
      currentVersion: '1.2.3',
      helper: null,
      githubRelease: null,
      dockerHubTag: null,
    })).toEqual({
      label: '无法检查更新',
      badgeClassName: 'badge badge-muted',
      detail: '暂未获取到可比较的版本信息。',
      highlight: false,
    });
  });

  it('treats a same-version Docker target with a different digest as a real new-digest deploy', () => {
    const state = describeDockerDeployState({
      enabled: true,
      helperHealthy: true,
      currentVersion: '1.2.3',
      helper: {
        imageTag: '1.2.3',
        imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      candidate: {
        normalizedVersion: '1.2.3',
        tagName: '1.2.3',
        digest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
    });

    expect(state.kind).toBe('new-digest');
    expect(state.canDeploy).toBe(true);
    expect(state.badgeLabel).toBe('发现新 digest');
  });
});
