import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  getUpdateCenterHelperStatusMock,
  getCurrentRuntimeVersionMock,
  parseStableSemVerMock,
} = vi.hoisted(() => ({
  getUpdateCenterHelperStatusMock: vi.fn(),
  getCurrentRuntimeVersionMock: vi.fn(),
  parseStableSemVerMock: vi.fn(),
}));

vi.mock('./updateCenterHelperClient.js', () => ({
  getUpdateCenterHelperStatus: (...args: unknown[]) => getUpdateCenterHelperStatusMock(...args),
}));

vi.mock('./updateCenterVersionService.js', () => ({
  getCurrentRuntimeVersion: () => getCurrentRuntimeVersionMock(),
  parseStableSemVer: (...args: unknown[]) => parseStableSemVerMock(...args),
}));

import {
  getUpdateCenterDeployBlockMessage,
  normalizeUpdateCenterTargetDigest,
} from './updateCenterDeployGuardService.js';

describe('updateCenterDeployGuardService', () => {
  beforeEach(() => {
    getUpdateCenterHelperStatusMock.mockReset();
    getCurrentRuntimeVersionMock.mockReset();
    parseStableSemVerMock.mockReset();
    getCurrentRuntimeVersionMock.mockReturnValue('1.2.3');
    parseStableSemVerMock.mockImplementation((value: string | null | undefined) => {
      const normalized = String(value || '').trim().replace(/^v/i, '');
      const match = normalized.match(/^(\d+)\.(\d+)\.(\d+)$/);
      if (!match) return null;
      return {
        raw: String(value || ''),
        normalized,
        major: Number.parseInt(match[1], 10),
        minor: Number.parseInt(match[2], 10),
        patch: Number.parseInt(match[3], 10),
      };
    });
  });

  it('normalizes valid digests and drops invalid ones', () => {
    expect(normalizeUpdateCenterTargetDigest(' sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA '))
      .toBe('sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(normalizeUpdateCenterTargetDigest('not-a-real-digest')).toBeNull();
  });

  it('treats digest equality as the source of truth when a digest is supplied', async () => {
    getUpdateCenterHelperStatusMock.mockResolvedValue({
      imageDigest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    });

    await expect(getUpdateCenterDeployBlockMessage({
      config: {
        enabled: true,
        helperBaseUrl: 'http://helper.local',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
      helperToken: 'helper-token',
      targetTag: '1.2.3',
      targetDigest: 'sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
    })).resolves.toBeNull();
  });

  it('falls back to semver equality only when no digest is provided', async () => {
    await expect(getUpdateCenterDeployBlockMessage({
      config: {
        enabled: true,
        helperBaseUrl: 'http://helper.local',
        namespace: 'ai',
        releaseName: 'metapi',
        chartRef: 'oci://ghcr.io/cita-777/charts/metapi',
        imageRepository: '1467078763/metapi',
        githubReleasesEnabled: true,
        dockerHubTagsEnabled: true,
        defaultDeploySource: 'github-release',
      },
      helperToken: 'helper-token',
      targetTag: '1.2.3',
      targetDigest: null,
    })).resolves.toBe('target version is already running');
    expect(getUpdateCenterHelperStatusMock).not.toHaveBeenCalled();
  });
});
