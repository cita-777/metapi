import { beforeEach, describe, expect, it, vi } from 'vitest';

const { fetchMock } = vi.hoisted(() => ({ fetchMock: vi.fn() }));

vi.mock('undici', async () => {
  const actual = await vi.importActual<typeof import('undici')>('undici');
  return { ...actual, fetch: (...args: unknown[]) => fetchMock(...args) };
});

import {
  buildServerReleaseAssetName,
  compareStableSemVer,
  fetchStableGitHubRelease,
  findChecksumsAsset,
  findServerReleaseAsset,
  normalizeUpdateCenterArchitecture,
  parseStableSemVer,
  selectLatestStableGitHubRelease,
} from './updateCenterVersionService.js';

describe('updateCenterVersionService', () => {
  beforeEach(() => fetchMock.mockReset());

  it('normalizes and compares stable semantic versions numerically', () => {
    const first = parseStableSemVer('v1.2.3');
    const second = parseStableSemVer('1.10.0');
    expect(first?.normalized).toBe('1.2.3');
    expect(compareStableSemVer(first!, second!)).toBeLessThan(0);
    expect(parseStableSemVer('1.2.3-beta.1')).toBeNull();
    expect(parseStableSemVer('1.2.3+build.1')).toBeNull();
    expect(parseStableSemVer('01.2.3')).toBeNull();
  });

  it('accepts only the supported Linux architectures', () => {
    expect(normalizeUpdateCenterArchitecture('x64')).toBe('amd64');
    expect(normalizeUpdateCenterArchitecture('aarch64')).toBe('arm64');
    expect(normalizeUpdateCenterArchitecture('arm')).toBeNull();
  });

  it('selects the highest non-prerelease GitHub release and its assets', () => {
    const candidate = selectLatestStableGitHubRelease([
      { tag_name: 'v1.2.0', draft: false, prerelease: false, assets: [] },
      { tag_name: 'v1.3.0-rc.1', draft: false, prerelease: true, assets: [] },
      {
        tag_name: 'v1.10.0',
        html_url: 'https://github.com/cita-777/metapi/releases/tag/v1.10.0',
        draft: false,
        prerelease: false,
        assets: [
          { name: 'metapi-server-v1.10.0-linux-amd64.tar.gz', browser_download_url: 'https://github.com/a' },
          { name: 'checksums.txt', browser_download_url: 'https://github.com/c' },
        ],
      },
    ]);
    expect(candidate?.normalizedVersion).toBe('1.10.0');
    expect(findServerReleaseAsset(candidate!, 'amd64')?.name).toBe(buildServerReleaseAssetName('1.10.0', 'amd64'));
    expect(findChecksumsAsset(candidate!)?.name).toBe('checksums.txt');
  });

  it('fetches a pinned stable release from the official API', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      tag_name: 'v1.4.0',
      draft: false,
      prerelease: false,
      assets: [],
    }), { status: 200 }));
    await expect(fetchStableGitHubRelease('1.4.0')).resolves.toMatchObject({ normalizedVersion: '1.4.0' });
    expect(String(fetchMock.mock.calls[0]?.[0] || '')).toContain('/repos/cita-777/metapi/releases/tags/v1.4.0');
  });
});
