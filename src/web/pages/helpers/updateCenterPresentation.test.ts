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

  it('treats semver tags with and without a v prefix as the same Docker digest target', () => {
    const state = describeDockerDeployState({
      enabled: true,
      helperHealthy: true,
      currentVersion: '1.2.3',
      helper: {
        imageTag: 'v1.2.3',
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
  });

  it('treats alias tags like latest as a new digest deploy target when the digest changes', () => {
    const state = describeDockerDeployState({
      enabled: true,
      helperHealthy: true,
      currentVersion: '1.2.3',
      helper: {
        imageTag: 'latest',
        imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      candidate: {
        normalizedVersion: 'latest',
        tagName: 'latest',
        digest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
    });

    expect(state.kind).toBe('new-digest');
    expect(state.canDeploy).toBe(true);
    expect(state.badgeLabel).toBe('发现新 digest');
  });

  it('does not advertise an older GitHub reminder when the helper is already ahead', () => {
    expect(buildUpdateReminder({
      currentVersion: '1.2.3',
      helper: {
        imageTag: '1.4.0',
      },
      githubRelease: {
        normalizedVersion: '1.3.0',
        displayVersion: '1.3.0',
        tagName: 'v1.3.0',
      },
      dockerHubTag: null,
    })).toEqual({
      label: '已是最新',
      badgeClassName: 'badge badge-muted',
      detail: '当前运行版本与已发现的部署目标没有明显差异。',
      highlight: false,
    });
  });
});
