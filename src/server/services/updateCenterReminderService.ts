type UpdateVersionCandidateLike = {
  normalizedVersion?: string | null;
  displayVersion?: string | null;
  tagName?: string | null;
  digest?: string | null;
};

type UpdateHelperRuntimeLike = {
  imageTag?: string | null;
  imageDigest?: string | null;
};

export type UpdateReminderCandidate = {
  source: 'github-release' | 'docker-hub-tag';
  kind: 'new-version' | 'new-digest';
  candidateKey: string;
  displayVersion: string;
};

const STABLE_SEMVER_PATTERN = /^v?(\d+)\.(\d+)\.(\d+)(?:\+[\w.-]+)?$/i;

function normalizeString(value?: string | null): string {
  return String(value || '').trim();
}

function normalizeDigest(value?: string | null): string {
  const digest = normalizeString(value);
  return /^sha256:[a-f0-9]{64}$/i.test(digest) ? digest.toLowerCase() : '';
}

function normalizeStableVersion(value?: string | null): string {
  const raw = normalizeString(value);
  if (!raw) return '';
  const match = raw.match(STABLE_SEMVER_PATTERN);
  if (!match) return '';
  return [
    Number.parseInt(match[1], 10),
    Number.parseInt(match[2], 10),
    Number.parseInt(match[3], 10),
  ].join('.');
}

function compareStableVersions(left?: string | null, right?: string | null): number | null {
  const normalizedLeft = normalizeStableVersion(left);
  const normalizedRight = normalizeStableVersion(right);
  if (!normalizedLeft || !normalizedRight) return null;

  const leftParts = normalizedLeft.split('.').map((item) => Number.parseInt(item, 10));
  const rightParts = normalizedRight.split('.').map((item) => Number.parseInt(item, 10));
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] === rightParts[index]) continue;
    return leftParts[index] < rightParts[index] ? -1 : 1;
  }
  return 0;
}

function isSameImageTarget(
  current: UpdateHelperRuntimeLike | null | undefined,
  target: { tag?: string | null; digest?: string | null },
): boolean {
  const currentDigest = normalizeDigest(current?.imageDigest);
  const targetDigest = normalizeDigest(target.digest);
  if (currentDigest && targetDigest) {
    return currentDigest === targetDigest;
  }

  const currentTag = normalizeString(current?.imageTag);
  const targetTag = normalizeString(target.tag);
  if (!currentTag || !targetTag || currentTag !== targetTag) {
    return false;
  }

  const currentVersion = normalizeStableVersion(currentTag);
  const targetVersion = normalizeStableVersion(targetTag);
  return !!currentVersion && currentVersion === targetVersion;
}

function buildUpdateReminderCandidateKey(
  source: 'github-release' | 'docker-hub-tag',
  candidate: { tagName?: string | null; digest?: string | null },
): string {
  const tagName = normalizeString(candidate.tagName);
  const digest = normalizeDigest(candidate.digest);
  if (!tagName) return '';
  if (source === 'docker-hub-tag' && digest) {
    return `${source}:${tagName}@${digest}`;
  }
  return `${source}:${tagName}`;
}

export function resolveUpdateReminderCandidate(input: {
  currentVersion?: string | null;
  helper: UpdateHelperRuntimeLike | null | undefined;
  githubRelease: UpdateVersionCandidateLike | null | undefined;
  dockerHubTag: UpdateVersionCandidateLike | null | undefined;
}): UpdateReminderCandidate | null {
  const githubCandidateVersion = normalizeString(input.githubRelease?.normalizedVersion);
  const githubTag = normalizeString(input.githubRelease?.tagName || githubCandidateVersion);
  if (githubTag) {
    const versionCompare = compareStableVersions(input.currentVersion, githubCandidateVersion || githubTag);
    const helperVersionCompare = compareStableVersions(input.helper?.imageTag, githubTag);
    if (versionCompare === -1 && helperVersionCompare !== 0) {
      return {
        source: 'github-release',
        kind: 'new-version',
        candidateKey: buildUpdateReminderCandidateKey('github-release', { tagName: githubTag, digest: null }),
        displayVersion: normalizeString(input.githubRelease?.displayVersion || input.githubRelease?.normalizedVersion || githubTag),
      };
    }
  }

  const dockerCandidateVersion = normalizeString(input.dockerHubTag?.normalizedVersion);
  const dockerTag = normalizeString(input.dockerHubTag?.tagName || dockerCandidateVersion);
  const dockerDigest = normalizeDigest(input.dockerHubTag?.digest);
  if (!dockerTag) return null;

  if (isSameImageTarget(input.helper, { tag: dockerTag, digest: dockerDigest })) {
    return null;
  }

  const dockerVersionCompare = compareStableVersions(input.currentVersion, dockerCandidateVersion || dockerTag);
  if (dockerVersionCompare === -1) {
    return {
      source: 'docker-hub-tag',
      kind: 'new-version',
      candidateKey: buildUpdateReminderCandidateKey('docker-hub-tag', { tagName: dockerTag, digest: dockerDigest || null }),
      displayVersion: normalizeString(input.dockerHubTag?.displayVersion || input.dockerHubTag?.normalizedVersion || dockerTag),
    };
  }

  const helperTag = normalizeString(input.helper?.imageTag);
  const helperDigest = normalizeDigest(input.helper?.imageDigest);
  if (dockerDigest && helperTag && helperTag === dockerTag && helperDigest && helperDigest !== dockerDigest) {
    return {
      source: 'docker-hub-tag',
      kind: 'new-digest',
      candidateKey: buildUpdateReminderCandidateKey('docker-hub-tag', { tagName: dockerTag, digest: dockerDigest }),
      displayVersion: normalizeString(input.dockerHubTag?.displayVersion || input.dockerHubTag?.normalizedVersion || dockerTag),
    };
  }

  return null;
}
