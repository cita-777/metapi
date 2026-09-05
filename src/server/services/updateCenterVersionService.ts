import { fetch, type RequestInit as UndiciRequestInit } from 'undici';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { compareStableSemVer, parseStableSemVer, type StableSemVer } from '../shared/stableVersion.js';

export { compareStableSemVer, parseStableSemVer, type StableSemVer } from '../shared/stableVersion.js';

export type UpdateCenterVersionSource = 'github-release';

export type UpdateCenterReleaseAsset = {
  name: string;
  downloadUrl: string;
  size: number | null;
  contentType: string | null;
};

export type UpdateCenterVersionCandidate = {
  source: UpdateCenterVersionSource;
  rawVersion: string;
  normalizedVersion: string;
  url: string | null;
  tagName: string;
  digest: null;
  displayVersion: string;
  publishedAt: string | null;
  assets: UpdateCenterReleaseAsset[];
};

export type GitHubReleaseAssetRecord = {
  name?: string | null;
  browser_download_url?: string | null;
  size?: number | null;
  content_type?: string | null;
};

export type GitHubReleaseRecord = {
  tag_name?: string | null;
  html_url?: string | null;
  draft?: boolean;
  prerelease?: boolean;
  published_at?: string | null;
  name?: string | null;
  assets?: GitHubReleaseAssetRecord[];
};

export const UPDATE_CENTER_RELEASE_REPOSITORY = 'cita-777/metapi';
export const UPDATE_CENTER_GITHUB_RELEASES_URL = `https://api.github.com/repos/${UPDATE_CENTER_RELEASE_REPOSITORY}/releases`;
export const UPDATE_CENTER_GITHUB_RELEASE_BY_TAG_URL = (tag: string) =>
  `https://api.github.com/repos/${UPDATE_CENTER_RELEASE_REPOSITORY}/releases/tags/${encodeURIComponent(tag)}`;
export const UPDATE_CENTER_RELEASE_FETCH_TIMEOUT_MS = 5_000;
export const UPDATE_CENTER_SERVER_ARCHIVE_PREFIX = 'metapi-server-v';

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeReleaseAsset(input: GitHubReleaseAssetRecord): UpdateCenterReleaseAsset | null {
  const name = normalizeString(input.name);
  const downloadUrl = normalizeString(input.browser_download_url);
  if (!name || !downloadUrl) return null;
  return {
    name,
    downloadUrl,
    size: typeof input.size === 'number' && Number.isFinite(input.size) && input.size >= 0
      ? Math.trunc(input.size)
      : null,
    contentType: normalizeString(input.content_type) || null,
  };
}

function toCandidate(release: GitHubReleaseRecord, semver: StableSemVer): UpdateCenterVersionCandidate {
  return {
    source: 'github-release',
    rawVersion: normalizeString(release.tag_name) || semver.raw,
    normalizedVersion: semver.normalized,
    url: normalizeString(release.html_url) || null,
    tagName: normalizeString(release.tag_name) || `v${semver.normalized}`,
    digest: null,
    displayVersion: semver.normalized,
    publishedAt: normalizeString(release.published_at) || null,
    assets: Array.isArray(release.assets)
      ? release.assets
        .map((asset) => normalizeReleaseAsset(asset))
        .filter((asset): asset is UpdateCenterReleaseAsset => !!asset)
      : [],
  };
}

export function normalizeUpdateCenterArchitecture(value: string | null | undefined): 'amd64' | 'arm64' | null {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'x64' || normalized === 'x86_64' || normalized === 'amd64') return 'amd64';
  if (normalized === 'arm64' || normalized === 'aarch64') return 'arm64';
  return null;
}

export function getCurrentUpdateCenterArchitecture(value: string = process.arch): 'amd64' | 'arm64' | null {
  return normalizeUpdateCenterArchitecture(value);
}

export function buildServerReleaseAssetName(version: string, architecture: 'amd64' | 'arm64'): string {
  const semver = parseStableSemVer(version);
  if (!semver) throw new Error(`invalid release version: ${version}`);
  return `${UPDATE_CENTER_SERVER_ARCHIVE_PREFIX}${semver.normalized}-linux-${architecture}.tar.gz`;
}

export function selectLatestStableGitHubRelease(
  releases: GitHubReleaseRecord[],
): UpdateCenterVersionCandidate | null {
  let selected: { semver: StableSemVer; release: GitHubReleaseRecord } | null = null;

  for (const release of releases) {
    if (release?.draft || release?.prerelease) continue;
    const semver = parseStableSemVer(release?.tag_name);
    if (!semver) continue;
    if (!selected || compareStableSemVer(semver, selected.semver) > 0) {
      selected = { semver, release };
    }
  }

  return selected ? toCandidate(selected.release, selected.semver) : null;
}

function normalizeFetchError(error: unknown, label: string): Error {
  if (error instanceof Error && error.name === 'AbortError') {
    return new Error(`${label} timeout (${Math.round(UPDATE_CENTER_RELEASE_FETCH_TIMEOUT_MS / 1000)}s)`);
  }
  if (error instanceof Error && error.message) return error;
  return new Error(`${label} failed`);
}

async function fetchJsonWithTimeout(url: string, init: UndiciRequestInit, label: string): Promise<unknown> {
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), UPDATE_CENTER_RELEASE_FETCH_TIMEOUT_MS);
  timeoutHandle.unref?.();

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`${label} failed with HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    throw normalizeFetchError(error, label);
  } finally {
    clearTimeout(timeoutHandle);
  }
}

function githubHeaders() {
  return {
    accept: 'application/vnd.github+json',
    'user-agent': 'metapi-update-center/2.0',
  };
}

export async function fetchLatestStableGitHubRelease(): Promise<UpdateCenterVersionCandidate | null> {
  const payload = await fetchJsonWithTimeout(
    UPDATE_CENTER_GITHUB_RELEASES_URL,
    { headers: githubHeaders() },
    'GitHub releases lookup',
  );
  return selectLatestStableGitHubRelease(Array.isArray(payload) ? payload as GitHubReleaseRecord[] : []);
}

export async function fetchStableGitHubRelease(version: string): Promise<UpdateCenterVersionCandidate | null> {
  const semver = parseStableSemVer(version);
  if (!semver) return null;
  const payload = await fetchJsonWithTimeout(
    UPDATE_CENTER_GITHUB_RELEASE_BY_TAG_URL(`v${semver.normalized}`),
    { headers: githubHeaders() },
    `GitHub release ${semver.normalized} lookup`,
  ) as GitHubReleaseRecord;
  if (payload?.draft || payload?.prerelease) return null;
  const parsed = parseStableSemVer(payload?.tag_name);
  if (!parsed || parsed.normalized !== semver.normalized) return null;
  return toCandidate(payload, parsed);
}

export function findServerReleaseAsset(
  candidate: UpdateCenterVersionCandidate,
  architecture = getCurrentUpdateCenterArchitecture(),
): UpdateCenterReleaseAsset | null {
  if (!architecture) return null;
  const expected = buildServerReleaseAssetName(candidate.normalizedVersion, architecture);
  return candidate.assets.find((asset) => asset.name === expected) || null;
}

export function findChecksumsAsset(candidate: UpdateCenterVersionCandidate): UpdateCenterReleaseAsset | null {
  return candidate.assets.find((asset) => asset.name === 'checksums.txt') || null;
}

export function getCurrentRuntimeVersion(): string {
  const explicit = normalizeString(process.env.METAPI_RELEASE_VERSION);
  if (explicit) return parseStableSemVer(explicit)?.normalized || explicit;

  const releaseRoot = normalizeString(process.env.METAPI_RELEASE_ROOT);
  const manifestCandidates = [
    releaseRoot ? join(releaseRoot, 'release.json') : '',
    resolve(process.cwd(), 'release.json'),
  ].filter(Boolean);
  for (const manifestPath of manifestCandidates) {
    if (!existsSync(manifestPath)) continue;
    try {
      const payload = JSON.parse(readFileSync(manifestPath, 'utf8')) as { version?: unknown };
      const version = normalizeString(payload.version);
      if (version) return parseStableSemVer(version)?.normalized || version;
    } catch {}
  }

  try {
    const packageJsonPath = resolve(process.cwd(), 'package.json');
    const payload = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { version?: unknown };
    const version = normalizeString(payload.version);
    return version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}
