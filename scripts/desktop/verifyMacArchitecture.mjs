import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAC_BINARY_SEGMENTS = ['Metapi.app', 'Contents', 'MacOS', 'Metapi'];

function walkDirectories(rootDir) {
  const queue = [rootDir];
  const files = [];

  while (queue.length > 0) {
    const currentDir = queue.shift();
    if (!currentDir) {
      continue;
    }

    for (const entry of readdirSync(currentDir, { withFileTypes: true })) {
      const entryPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        queue.push(entryPath);
        continue;
      }

      if (entry.isFile()) {
        files.push(entryPath);
      }
    }
  }

  return files;
}

export function findPackagedMacBinaries(releaseDir) {
  const normalizedSuffix = MAC_BINARY_SEGMENTS.join('/');

  return walkDirectories(releaseDir).filter((filePath) =>
    filePath.replaceAll('\\', '/').endsWith(normalizedSuffix),
  );
}

export function normalizeExpectedMacArch(expectedArch) {
  if (expectedArch === 'x64') {
    return 'x86_64';
  }

  if (expectedArch === 'arm64') {
    return 'arm64';
  }

  throw new Error(`Unsupported expected mac architecture: ${expectedArch}`);
}

export function inspectBinaryArchsWithLipo(binaryPath) {
  try {
    return execFileSync('lipo', ['-archs', binaryPath], { encoding: 'utf8' }).trim();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Unable to detect architecture via lipo for ${binaryPath}: ${message}`);
  }
}

export function verifyMacArchitecture({
  releaseDir,
  expectedArch,
  inspectBinaryArchs = inspectBinaryArchsWithLipo,
}) {
  const binaries = findPackagedMacBinaries(releaseDir);
  if (binaries.length === 0) {
    throw new Error(`No packaged macOS app binary found under ${releaseDir}`);
  }

  const expectedBinaryArch = normalizeExpectedMacArch(expectedArch);

  return binaries.map((binaryPath) => {
    const archs = inspectBinaryArchs(binaryPath).trim().replace(/\s+/g, ' ');
    if (!archs) {
      throw new Error(`Unable to detect architecture via lipo for ${binaryPath}`);
    }

    if (archs !== expectedBinaryArch) {
      throw new Error(`Expected ${expectedBinaryArch}-only binary but got: ${archs}`);
    }

    return { binaryPath, archs };
  });
}

function parseArgValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) {
    return undefined;
  }

  return args[index + 1];
}

function main() {
  const args = process.argv.slice(2);
  const releaseDirArg = parseArgValue(args, '--release-dir');
  const expectedArch = parseArgValue(args, '--expected-arch');

  if (!releaseDirArg || !expectedArch) {
    throw new Error('Usage: node scripts/desktop/verifyMacArchitecture.mjs --release-dir <dir> --expected-arch <x64|arm64>');
  }

  const releaseDir = resolve(releaseDirArg);
  const verifiedBinaries = verifyMacArchitecture({ releaseDir, expectedArch });

  for (const { binaryPath, archs } of verifiedBinaries) {
    console.log(`${binaryPath} => ${archs}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
