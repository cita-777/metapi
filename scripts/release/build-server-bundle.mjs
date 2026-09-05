import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import * as tar from 'tar';

const SCRIPT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const MAX_ARCHIVE_PATH_LENGTH = 4_096;

function parseArgs(argv) {
  const options = { version: '', arch: '', outDir: resolve(SCRIPT_ROOT, 'release-server'), allowCrossArch: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--version') options.version = String(argv[++index] || '');
    else if (arg === '--arch') options.arch = String(argv[++index] || '');
    else if (arg === '--out-dir') options.outDir = resolve(String(argv[++index] || options.outDir));
    else if (arg === '--allow-cross-arch') options.allowCrossArch = true;
    else if (arg === '--help' || arg === '-h') {
      console.log('Usage: node scripts/release/build-server-bundle.mjs [--version 1.2.3] [--arch amd64|arm64] [--out-dir path] [--allow-cross-arch]');
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

function assertNativeBuildTarget(arch, allowCrossArch) {
  const explicitlyAllowed = allowCrossArch || ['1', 'true', 'yes', 'on'].includes(String(process.env.METAPI_ALLOW_CROSS_ARCH_BUILD || '').trim().toLowerCase());
  if (explicitlyAllowed) return;
  if (process.platform !== 'linux') {
    throw new Error('server release bundles must be built on Linux; pass --allow-cross-arch only for inspection builds');
  }
  const hostArch = normalizeArch(process.arch);
  if (hostArch !== arch) {
    throw new Error(`server release bundle target ${arch} does not match native host architecture ${hostArch}`);
  }
}

function normalizeVersion(input) {
  const value = String(input || '').trim().replace(/^v/i, '');
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)) throw new Error(`Invalid release version: ${input}`);
  return value;
}

function normalizeArch(input) {
  const value = String(input || '').trim().toLowerCase();
  if (value === 'x64' || value === 'x86_64' || value === 'amd64') return 'amd64';
  if (value === 'arm64' || value === 'aarch64') return 'arm64';
  throw new Error(`Unsupported server bundle architecture: ${input || process.arch}`);
}

function ensureFile(path, label) {
  if (!existsSync(path) || !lstatSync(path).isFile()) throw new Error(`${label} is missing: ${path}`);
}

function copyIfPresent(source, target) {
  if (!existsSync(source)) return;
  cpSync(source, target, { recursive: true, force: true });
}

function removeSymlinks(root) {
  if (!existsSync(root)) return;
  for (const entry of readdirSync(root)) {
    const fullPath = join(root, entry);
    const stat = lstatSync(fullPath);
    if (stat.isSymbolicLink()) {
      rmSync(fullPath, { force: true, recursive: true });
      continue;
    }
    if (stat.isDirectory()) removeSymlinks(fullPath);
  }
}

function removeNativeTestArtifacts(root) {
  if (!existsSync(root)) return;
  for (const path of collectFiles(root)) {
    if (path.endsWith('/test_extension.node') || path.endsWith('\\test_extension.node')) {
      rmSync(path, { force: true });
    }
  }
}

function removeRuntimeNoise(distRoot) {
  for (const path of [
    'desktop',
    'shared',
  ]) {
    rmSync(join(distRoot, path), { recursive: true, force: true });
  }
  if (!existsSync(distRoot)) return;
  for (const path of collectFiles(distRoot)) {
    if (path.endsWith('.d.ts')) rmSync(path, { force: true });
  }
}

function collectFiles(root, current = root, result = []) {
  for (const entry of readdirSync(current).sort((left, right) => left < right ? -1 : left > right ? 1 : 0)) {
    const fullPath = join(current, entry);
    const stat = lstatSync(fullPath);
    if (stat.isSymbolicLink()) throw new Error(`Symlinks are not allowed in release staging: ${relative(root, fullPath)}`);
    if (stat.isDirectory()) collectFiles(root, fullPath, result);
    else result.push(fullPath);
  }
  return result;
}

function hashPayload(root) {
  const hash = createHash('sha256');
  for (const path of collectFiles(root).filter((item) => relative(root, item) !== 'release.json')) {
    const relativePath = relative(root, path).replaceAll('\\', '/');
    if (relativePath.length > MAX_ARCHIVE_PATH_LENGTH) throw new Error(`Release path is too long: ${relativePath}`);
    hash.update(relativePath);
    hash.update('\0');
    hash.update(readFileSync(path));
    hash.update('\0');
  }
  return hash.digest('hex');
}

async function bundleServerEntries(staging) {
  const entryPoints = [
    ['dist/server/index.js', 'dist/server/index.js'],
    ['dist/server/db/migrate.js', 'dist/server/db/migrate.js'],
  ];
  for (const [input, output] of entryPoints) {
    const source = resolve(SCRIPT_ROOT, input);
    const destination = join(staging, output);
    ensureFile(source, `compiled server entrypoint ${input}`);
    await build({
      entryPoints: [source],
      outfile: destination,
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node25',
      packages: 'external',
      sourcemap: false,
      legalComments: 'none',
      metafile: false,
    });
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const packageJson = JSON.parse(readFileSync(resolve(SCRIPT_ROOT, 'package.json'), 'utf8'));
  const version = normalizeVersion(options.version || packageJson.version);
  const arch = normalizeArch(options.arch || process.arch);
  assertNativeBuildTarget(arch, options.allowCrossArch);
  const artifactName = `metapi-server-v${version}-linux-${arch}.tar.gz`;
  const outDir = options.outDir;
  mkdirSync(outDir, { recursive: true });
  const staging = join(outDir, `.staging-${version}-${arch}-${process.pid}`);
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });

  try {
    copyIfPresent(resolve(SCRIPT_ROOT, 'dist'), join(staging, 'dist'));
    removeSymlinks(join(staging, 'dist'));
    removeRuntimeNoise(join(staging, 'dist'));
    copyIfPresent(resolve(SCRIPT_ROOT, 'drizzle'), join(staging, 'drizzle'));
    copyIfPresent(resolve(SCRIPT_ROOT, 'node_modules'), join(staging, 'node_modules'));
    // npm creates convenience links under node_modules/.bin.  They are not
    // needed at runtime and are deliberately removed so the updater can
    // reject every symlink in an untrusted archive.
    removeSymlinks(join(staging, 'node_modules'));
    ensureFile(resolve(SCRIPT_ROOT, 'package.json'), 'package.json');
    cpSync(resolve(SCRIPT_ROOT, 'package.json'), join(staging, 'package.json'));
    copyIfPresent(resolve(SCRIPT_ROOT, 'package-lock.json'), join(staging, 'package-lock.json'));
    await bundleServerEntries(staging);
    if (existsSync(join(staging, 'package-lock.json'))) {
      execFileSync(process.env.npm_execpath || 'npm', ['prune', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', staging], {
        cwd: SCRIPT_ROOT,
        stdio: 'ignore',
        env: process.env,
      });
      execFileSync(process.env.npm_execpath || 'npm', ['rebuild', 'better-sqlite3', '--no-audit', '--no-fund', '--prefix', staging], {
        cwd: SCRIPT_ROOT,
        stdio: 'ignore',
        env: process.env,
      });
      removeSymlinks(join(staging, 'node_modules'));
      removeNativeTestArtifacts(join(staging, 'node_modules'));
    }

    const manifest = {
      schemaVersion: 1,
      version,
      channel: 'stable',
      platform: 'linux',
      arch,
      nodeMajor: 25,
      entrypoint: 'dist/server/index.js',
      migrationEntrypoint: 'dist/server/db/migrate.js',
      artifactName,
      artifactSha256: hashPayload(staging),
      gitSha: String(process.env.GITHUB_SHA || '').trim() || null,
    };
    writeFileSync(join(staging, 'release.json'), `${JSON.stringify(manifest, null, 2)}\n`);

    const archivePath = join(outDir, artifactName);
    rmSync(archivePath, { force: true });
    await tar.c({ cwd: staging, file: archivePath, gzip: true, portable: true }, ['.']);
    const archiveHash = createHash('sha256').update(readFileSync(archivePath)).digest('hex');
    writeFileSync(join(outDir, `${artifactName}.sha256`), `${archiveHash}  ${artifactName}\n`);
    writeFileSync(join(outDir, 'checksums.txt'), `${archiveHash}  ${artifactName}\n`);
    console.log(JSON.stringify({ artifact: archivePath, checksum: archiveHash, manifest }, null, 2));
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}

export {
  assertNativeBuildTarget,
  hashPayload,
  normalizeArch,
  normalizeVersion,
  parseArgs,
};
