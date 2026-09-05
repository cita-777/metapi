import { compareStableSemVer, parseStableSemVer } from './stableVersion.js';

export type UpdateVersionCandidateLike = {
  normalizedVersion?: string | null;
  displayVersion?: string | null;
  tagName?: string | null;
};

export type UpdateReminderCandidate = {
  source: 'github-release';
  kind: 'new-version';
  candidateKey: string;
  displayVersion: string;
  tagName: string;
  digest: null;
};

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function normalizeStableVersion(value?: string | null): string {
  return parseStableSemVer(normalizeString(value))?.normalized || '';
}

export function compareStableVersions(left?: string | null, right?: string | null): number | null {
  const leftSemVer = parseStableSemVer(normalizeString(left));
  const rightSemVer = parseStableSemVer(normalizeString(right));
  if (!leftSemVer || !rightSemVer) return null;
  return Math.sign(compareStableSemVer(leftSemVer, rightSemVer));
}

export function buildUpdateReminderCandidateKey(
  _source: 'github-release' = 'github-release',
  candidate: { tagName?: string | null },
): string {
  const tagName = normalizeString(candidate.tagName);
  return tagName ? `github-release:${tagName}` : '';
}

export function resolveUpdateReminderCandidate(input: {
  currentVersion?: string | null;
  latestRelease?: UpdateVersionCandidateLike | null;
  githubRelease?: UpdateVersionCandidateLike | null;
}): UpdateReminderCandidate | null {
  const release = input.latestRelease || input.githubRelease;
  const version = normalizeString(release?.normalizedVersion);
  const tagName = normalizeString(release?.tagName || version);
  if (!version || !tagName) return null;

  const comparison = compareStableVersions(input.currentVersion, version);
  if (comparison !== -1) return null;

  return {
    source: 'github-release',
    kind: 'new-version',
    candidateKey: buildUpdateReminderCandidateKey('github-release', { tagName }),
    displayVersion: normalizeString(release?.displayVersion || version),
    tagName,
    digest: null,
  };
}
