import { isAbsolute, resolve } from 'node:path';

const RELEASE_ROOT_ENV = 'METAPI_RELEASE_ROOT';

function readConfiguredReleaseRoot(env: NodeJS.ProcessEnv): string | null {
  const configured = typeof env[RELEASE_ROOT_ENV] === 'string'
    ? env[RELEASE_ROOT_ENV]!.trim()
    : '';
  return configured ? resolve(configured) : null;
}

export function resolveRuntimeAssetPath(
  releaseRelativePath: string,
  fallbackPath: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  if (isAbsolute(releaseRelativePath)) {
    throw new Error('release asset path must be relative');
  }

  const releaseRoot = readConfiguredReleaseRoot(env);
  return releaseRoot
    ? resolve(releaseRoot, releaseRelativePath)
    : resolve(fallbackPath);
}

export const __runtimeAssetPathTestUtils = {
  readConfiguredReleaseRoot,
};
