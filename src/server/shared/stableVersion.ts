export type StableSemVer = {
  raw: string;
  normalized: string;
  major: number;
  minor: number;
  patch: number;
};

const STABLE_SEMVER_PATTERN = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/i;

export function parseStableSemVer(input: string | null | undefined): StableSemVer | null {
  const raw = String(input || '').trim();
  if (!raw) return null;
  const match = raw.match(STABLE_SEMVER_PATTERN);
  if (!match) return null;
  const major = Number.parseInt(match[1], 10);
  const minor = Number.parseInt(match[2], 10);
  const patch = Number.parseInt(match[3], 10);
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return {
    raw,
    normalized: `${major}.${minor}.${patch}`,
    major,
    minor,
    patch,
  };
}

export function compareStableSemVer(a: StableSemVer, b: StableSemVer): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}
