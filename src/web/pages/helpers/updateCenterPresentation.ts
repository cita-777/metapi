export type UpdateVersionCandidateLike = {
  normalizedVersion?: string | null;
  displayVersion?: string | null;
  tagName?: string | null;
  digest?: string | null;
};

export type UpdateHelperRuntimeLike = {
  imageTag?: string | null;
  imageDigest?: string | null;
};

export type UpdateDeployState = {
  kind: 'disabled' | 'missing' | 'helper-unhealthy' | 'same-version' | 'same-image' | 'new-version' | 'new-digest' | 'available';
  badgeClassName: string;
  badgeLabel: string;
  reason: string;
  canDeploy: boolean;
  highlight: boolean;
};

export type UpdateReminder = {
  label: string;
  badgeClassName: string;
  detail: string;
  highlight: boolean;
};

const STABLE_SEMVER_PATTERN = /^v?(\d+)\.(\d+)\.(\d+)(?:\+[\w.-]+)?$/i;

function normalizeString(value?: string | null): string {
  return String(value || '').trim();
}

function normalizeDigest(value?: string | null): string {
  const digest = normalizeString(value);
  return /^sha256:[a-f0-9]{64}$/i.test(digest) ? digest.toLowerCase() : '';
}

export function normalizeStableVersion(value?: string | null): string {
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

export function compareStableVersions(left?: string | null, right?: string | null): number | null {
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

export function isSameImageTarget(
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

export function describeGitHubDeployState(input: {
  enabled: boolean;
  helperHealthy: boolean;
  helperError?: string | null;
  currentVersion?: string | null;
  helperImageTag?: string | null;
  candidate: UpdateVersionCandidateLike | null | undefined;
}): UpdateDeployState {
  if (!input.enabled) {
    return {
      kind: 'disabled',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '已停用',
      reason: '当前来源已停用，开启后才会参与检查和部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  const candidateVersion = normalizeString(input.candidate?.normalizedVersion);
  const candidateTag = normalizeString(input.candidate?.tagName || candidateVersion);
  if (!candidateVersion && !candidateTag) {
    return {
      kind: 'missing',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '未发现版本',
      reason: '当前来源还没有可部署版本。',
      canDeploy: false,
      highlight: false,
    };
  }

  if (!input.helperHealthy) {
    return {
      kind: 'helper-unhealthy',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '等待 helper',
      reason: input.helperError || 'Deploy Helper 未健康，先修复 helper 再部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  const versionCompare = compareStableVersions(input.currentVersion, candidateVersion || candidateTag);
  const helperVersionCompare = compareStableVersions(input.helperImageTag, candidateTag);
  if (versionCompare === 0 || helperVersionCompare === 0) {
    return {
      kind: 'same-version',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '当前运行',
      reason: '当前已运行该版本，无需重复部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  if (versionCompare === -1) {
    return {
      kind: 'new-version',
      badgeClassName: 'badge badge-success',
      badgeLabel: '发现新版本',
      reason: '检测到比当前运行版本更新的稳定版，可直接发起部署。',
      canDeploy: true,
      highlight: true,
    };
  }

  return {
    kind: 'available',
    badgeClassName: 'badge badge-info',
    badgeLabel: '可部署',
    reason: '版本可用，点击按钮即可通过 helper 发起滚动更新。',
    canDeploy: true,
    highlight: false,
  };
}

export function describeDockerDeployState(input: {
  enabled: boolean;
  helperHealthy: boolean;
  helperError?: string | null;
  currentVersion?: string | null;
  helper: UpdateHelperRuntimeLike | null | undefined;
  candidate: UpdateVersionCandidateLike | null | undefined;
}): UpdateDeployState {
  if (!input.enabled) {
    return {
      kind: 'disabled',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '已停用',
      reason: '当前来源已停用，开启后才会参与检查和部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  const candidateVersion = normalizeString(input.candidate?.normalizedVersion);
  const candidateTag = normalizeString(input.candidate?.tagName || candidateVersion);
  const candidateDigest = normalizeDigest(input.candidate?.digest);
  if (!candidateVersion && !candidateTag) {
    return {
      kind: 'missing',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '未发现版本',
      reason: '当前来源还没有可部署版本。',
      canDeploy: false,
      highlight: false,
    };
  }

  if (!input.helperHealthy) {
    return {
      kind: 'helper-unhealthy',
      badgeClassName: 'badge badge-warning',
      badgeLabel: '等待 helper',
      reason: input.helperError || 'Deploy Helper 未健康，先修复 helper 再部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  if (isSameImageTarget(input.helper, { tag: candidateTag, digest: candidateDigest })) {
    return {
      kind: 'same-image',
      badgeClassName: 'badge badge-muted',
      badgeLabel: '当前运行',
      reason: '当前已运行该镜像，无需重复部署。',
      canDeploy: false,
      highlight: false,
    };
  }

  const versionCompare = compareStableVersions(input.currentVersion, candidateVersion || candidateTag);
  if (versionCompare === -1) {
    return {
      kind: 'new-version',
      badgeClassName: 'badge badge-success',
      badgeLabel: '发现新版本',
      reason: 'Docker Hub 已出现更高版本，可直接发起部署。',
      canDeploy: true,
      highlight: true,
    };
  }

  const helperTag = normalizeString(input.helper?.imageTag);
  const helperDigest = normalizeDigest(input.helper?.imageDigest);
  if (candidateDigest && helperTag && helperTag === candidateTag && helperDigest && helperDigest !== candidateDigest) {
    return {
      kind: 'new-digest',
      badgeClassName: 'badge badge-success',
      badgeLabel: '发现新 digest',
      reason: '标签未变，但镜像 digest 已更新，适合按镜像级别滚动更新。',
      canDeploy: true,
      highlight: true,
    };
  }

  return {
    kind: 'available',
    badgeClassName: 'badge badge-info',
    badgeLabel: '可部署',
    reason: '版本可用，点击按钮即可通过 helper 发起滚动更新。',
    canDeploy: true,
    highlight: false,
  };
}

export function buildUpdateReminder(input: {
  currentVersion?: string | null;
  helper: UpdateHelperRuntimeLike | null | undefined;
  githubRelease: UpdateVersionCandidateLike | null | undefined;
  dockerHubTag: UpdateVersionCandidateLike | null | undefined;
}): UpdateReminder {
  const hasGitHubCandidate = Boolean(normalizeString(
    input.githubRelease?.displayVersion
      || input.githubRelease?.normalizedVersion
      || input.githubRelease?.tagName,
  ));
  const hasDockerCandidate = Boolean(normalizeString(
    input.dockerHubTag?.displayVersion
      || input.dockerHubTag?.normalizedVersion
      || input.dockerHubTag?.tagName
      || input.dockerHubTag?.digest,
  ));
  if (!hasGitHubCandidate && !hasDockerCandidate) {
    return {
      label: '无法检查更新',
      badgeClassName: 'badge badge-muted',
      detail: '暂未获取到可比较的版本信息。',
      highlight: false,
    };
  }

  const githubState = describeGitHubDeployState({
    enabled: true,
    helperHealthy: true,
    currentVersion: input.currentVersion,
    helperImageTag: input.helper?.imageTag,
    candidate: input.githubRelease,
  });
  if (githubState.kind === 'new-version') {
    return {
      label: '发现新版本',
      badgeClassName: githubState.badgeClassName,
      detail: `GitHub 稳定版 ${normalizeString(input.githubRelease?.displayVersion || input.githubRelease?.normalizedVersion)} 已可部署。`,
      highlight: true,
    };
  }

  const dockerState = describeDockerDeployState({
    enabled: true,
    helperHealthy: true,
    currentVersion: input.currentVersion,
    helper: input.helper,
    candidate: input.dockerHubTag,
  });
  if (dockerState.kind === 'new-version' || dockerState.kind === 'new-digest') {
    return {
      label: dockerState.badgeLabel,
      badgeClassName: dockerState.badgeClassName,
      detail: dockerState.kind === 'new-digest'
        ? 'Docker Hub 的 alias tag 已指向新 digest，可按需部署。'
        : `Docker Hub ${normalizeString(input.dockerHubTag?.displayVersion || input.dockerHubTag?.normalizedVersion)} 已可部署。`,
      highlight: dockerState.highlight,
    };
  }

  return {
    label: '已是最新',
    badgeClassName: 'badge badge-muted',
    detail: '当前运行版本与已发现的部署目标没有明显差异。',
    highlight: false,
  };
}
