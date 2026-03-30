import type { UpdateCenterConfig } from './updateCenterConfigService.js';
import { getUpdateCenterHelperStatus } from './updateCenterHelperClient.js';
import { getCurrentRuntimeVersion, parseStableSemVer } from './updateCenterVersionService.js';

function normalizeDigest(value: string | null | undefined) {
  const digest = String(value || '').trim();
  return /^sha256:[a-f0-9]{64}$/i.test(digest) ? digest.toLowerCase() : '';
}

function isSameTargetVersion(currentVersion: string, targetTag: string) {
  const current = parseStableSemVer(currentVersion);
  const target = parseStableSemVer(targetTag);
  return !!current && !!target && current.normalized === target.normalized;
}

export function normalizeUpdateCenterTargetDigest(value: string | null | undefined): string | null {
  return normalizeDigest(value) || null;
}

export async function getUpdateCenterDeployBlockMessage(input: {
  config: UpdateCenterConfig;
  helperToken: string;
  targetTag: string;
  targetDigest: string | null;
}): Promise<string | null> {
  const normalizedTargetDigest = normalizeDigest(input.targetDigest);
  if (normalizedTargetDigest) {
    try {
      const helperStatus = await getUpdateCenterHelperStatus(input.config, input.helperToken);
      const currentDigest = normalizeDigest(helperStatus?.imageDigest);
      if (currentDigest && currentDigest === normalizedTargetDigest) {
        return 'target image is already running';
      }
    } catch {
      return null;
    }

    return null;
  }

  if (isSameTargetVersion(getCurrentRuntimeVersion(), input.targetTag)) {
    return 'target version is already running';
  }

  return null;
}
