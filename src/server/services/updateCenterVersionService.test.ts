import { describe, expect, it, vi, beforeEach } from 'vitest';

const { fetchMock } = vi.hoisted(() => ({
  fetchMock: vi.fn(),
}));

vi.mock('undici', async () => {
  const actual = await vi.importActual<typeof import('undici')>('undici');
  return {
    ...actual,
    fetch: (...args: unknown[]) => fetchMock(...args),
  };
});

import {
  compareStableSemVer,
  fetchLatestDockerHubTag,
  fetchLatestStableGitHubRelease,
  parseStableSemVer,
  resolvePreferredDeploySource,
  selectLatestDockerHubTag,
  selectLatestStableGitHubRelease,
} from './updateCenterVersionService.js';

describe('update center version service', () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  describe('parseStableSemVer', () => {
    it('accepts stable semver strings with optional leading v', () => {
      expect(parseStableSemVer('1.2.3')).toMatchObject({
        raw: '1.2.3',
        normalized: '1.2.3',
        major: 1,
        minor: 2,
        patch: 3,
      });
      expect(parseStableSemVer('v2.4.6')).toMatchObject({
        raw: 'v2.4.6',
        normalized: '2.4.6',
        major: 2,
        minor: 4,
        patch: 6,
      });
    });

    it('rejects prerelease and invalid versions', () => {
      expect(parseStableSemVer('v1.2.3-alpha.1')).toBeNull();
      expect(parseStableSemVer('latest')).toBeNull();
      expect(parseStableSemVer('2026-03-29')).toBeNull();
      expect(parseStableSemVer('1.2')).toBeNull();
    });
  });

  describe('compareStableSemVer', () => {
    it('compares semver numerically instead of lexicographically', () => {
      const v120 = parseStableSemVer('1.2.0');
      const v1100 = parseStableSemVer('1.10.0');
      const v200 = parseStableSemVer('2.0.0');

      expect(v120).not.toBeNull();
      expect(v1100).not.toBeNull();
      expect(v200).not.toBeNull();
      expect(compareStableSemVer(v120!, v1100!)).toBeLessThan(0);
      expect(compareStableSemVer(v200!, v1100!)).toBeGreaterThan(0);
    });
  });

  describe('selectLatestStableGitHubRelease', () => {
    it('ignores drafts and prereleases and returns the highest stable semver release', () => {
      const latest = selectLatestStableGitHubRelease([
        {
          tag_name: 'v1.2.3-alpha.1',
          html_url: 'https://example.com/pre',
          draft: false,
          prerelease: true,
          published_at: '2026-03-29T00:00:00Z',
          name: 'v1.2.3-alpha.1',
        },
        {
          tag_name: 'v1.9.9',
          html_url: 'https://example.com/older',
          draft: false,
          prerelease: false,
          published_at: '2026-03-28T00:00:00Z',
          name: 'v1.9.9',
        },
        {
          tag_name: 'v1.10.0',
          html_url: 'https://example.com/latest',
          draft: false,
          prerelease: false,
          published_at: '2026-03-27T00:00:00Z',
          name: 'v1.10.0',
        },
        {
          tag_name: 'v9.9.9',
          html_url: 'https://example.com/draft',
          draft: true,
          prerelease: false,
          published_at: '2026-03-30T00:00:00Z',
          name: 'v9.9.9',
        },
      ]);

      expect(latest).toMatchObject({
        rawVersion: 'v1.10.0',
        normalizedVersion: '1.10.0',
        source: 'github-release',
        url: 'https://example.com/latest',
      });
    });
  });

  describe('selectLatestDockerHubTag', () => {
    it('prefers release aliases ahead of semver tags', () => {
      const latest = selectLatestDockerHubTag([
        'latest',
        'main',
        'v1.2.3-beta.1',
        'v1.2.3',
        '1.10.0',
        '20260329',
      ]);

      expect(latest).toMatchObject({
        rawVersion: 'latest',
        normalizedVersion: 'latest',
        source: 'docker-hub-tag',
      });
    });
  });

  describe('resolvePreferredDeploySource', () => {
    it('prefers the configured default source when both channels have valid candidates', () => {
      const preferred = resolvePreferredDeploySource({
        defaultSource: 'github-release',
        githubRelease: {
          source: 'github-release',
          rawVersion: 'v1.10.0',
          normalizedVersion: '1.10.0',
          url: 'https://example.com/release',
        },
        dockerHubTag: {
          source: 'docker-hub-tag',
          rawVersion: '1.10.1',
          normalizedVersion: '1.10.1',
          url: null,
        },
      });

      expect(preferred?.source).toBe('github-release');
      expect(preferred?.normalizedVersion).toBe('1.10.0');
    });
  });

  describe('fetchLatestStableGitHubRelease', () => {
    it('fetches releases and returns the latest stable semver record', async () => {
      fetchMock.mockResolvedValue(new Response(JSON.stringify([
        {
          tag_name: 'v1.2.3-beta.1',
          html_url: 'https://example.com/beta',
          draft: false,
          prerelease: true,
        },
        {
          tag_name: 'v1.2.9',
          html_url: 'https://example.com/older',
          draft: false,
          prerelease: false,
        },
        {
          tag_name: 'v1.10.0',
          html_url: 'https://example.com/latest',
          draft: false,
          prerelease: false,
        },
      ]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

      const latest = await fetchLatestStableGitHubRelease();
      expect(latest).toMatchObject({
        source: 'github-release',
        normalizedVersion: '1.10.0',
        url: 'https://example.com/latest',
      });
      expect(String(fetchMock.mock.calls[0]?.[0] || '')).toContain('/repos/cita-777/metapi/releases');
    });

    it('maps aborted GitHub lookups to a timeout error', async () => {
      const abortError = new Error('aborted');
      (abortError as Error & { name: string }).name = 'AbortError';
      fetchMock.mockRejectedValue(abortError);

      await expect(fetchLatestStableGitHubRelease()).rejects.toThrow('GitHub releases lookup timeout');
    });
  });

  describe('fetchLatestDockerHubTag', () => {
    it('prefers alias tags like latest and includes digest metadata', async () => {
      fetchMock.mockResolvedValue(new Response(JSON.stringify({
        results: [
          {
            name: 'latest',
            digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
            tag_last_pushed: '2026-03-29T11:54:35.591877Z',
          },
          {
            name: 'v1.2.3-rc.1',
          },
          {
            name: 'v1.2.3',
            digest: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
            tag_last_pushed: '2026-03-28T11:54:35.591877Z',
          },
          {
            name: '1.10.0',
            digest: 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
            tag_last_pushed: '2026-03-27T11:54:35.591877Z',
          },
        ],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

      const latest = await fetchLatestDockerHubTag();
      expect(latest).toMatchObject({
        source: 'docker-hub-tag',
        rawVersion: 'latest',
        normalizedVersion: 'latest',
        tagName: 'latest',
        digest: 'sha256:efb2ee6553866bd3268dcc54c02fa5f9789728c51ed4af63328aaba6da67df35',
        displayVersion: 'latest @ sha256:efb2ee655386',
        publishedAt: '2026-03-29T11:54:35.591877Z',
      });
      expect(String(fetchMock.mock.calls[0]?.[0] || '')).toContain('/v2/repositories/1467078763/metapi/tags');
    });

    it('falls back to the highest stable semver tag when no alias tags are present', async () => {
      fetchMock.mockResolvedValue(new Response(JSON.stringify({
        results: [
          { name: 'sha-b9ae85e' },
          { name: 'v1.2.3' },
          { name: '1.10.0', digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
        ],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }));

      const latest = await fetchLatestDockerHubTag();
      expect(latest).toMatchObject({
        source: 'docker-hub-tag',
        rawVersion: '1.10.0',
        normalizedVersion: '1.10.0',
        tagName: '1.10.0',
        digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        displayVersion: '1.10.0 @ sha256:aaaaaaaaaaaa',
      });
    });
  });
});
