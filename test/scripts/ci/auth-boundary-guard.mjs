// Fail when the auth-boundary files differ from main, unless test/ci/auth-boundary-allow.txt
// contains a non-comment reason. Default is fail.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const BOUNDARY_FILES = [
  { id: 'apiPath', path: 'src/server/middleware/apiPath.ts', pick: 'file' },
  { id: 'auth', path: 'src/server/middleware/auth.ts', pick: 'file' },
  { id: 'isPublicApiRoute', path: 'src/server/desktop.ts', pick: 'public-route' },
  { id: 'trustProxy', path: 'src/server/config.ts', pick: 'trust-proxy' },
];

export const ALLOW_FILE = 'test/ci/auth-boundary-allow.txt';

export function normalizeText(text) {
  return String(text ?? '').replaceAll('\r\n', '\n');
}

export function extractIsPublicApiRoute(source) {
  const text = normalizeText(source);
  const start = text.indexOf('export function isPublicApiRoute');
  if (start < 0) return null;
  const open = text.indexOf('{', start);
  if (open < 0) return null;
  let depth = 0;
  for (let index = open; index < text.length; index += 1) {
    const char = text[index];
    if (char === '{') depth += 1;
    else if (char === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(start, index + 1);
    }
  }
  return null;
}

export function extractTrustProxyPortion(source) {
  const lines = normalizeText(source).split('\n').filter((line) => (
    /trustedProxies:\s*parseCsvList\(env\.TRUSTED_PROXIES\)/.test(line)
    || /trustProxy:\s*appConfig\.trustedProxies\.length > 0 \? appConfig\.trustedProxies : false/.test(line)
  ));
  return lines.length > 0 ? lines.join('\n') : null;
}

export function selectPortion(source, pick) {
  if (pick === 'public-route') return extractIsPublicApiRoute(source);
  if (pick === 'trust-proxy') return extractTrustProxyPortion(source);
  return normalizeText(source);
}

export function readAllowReason(text) {
  return normalizeText(text)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .join('\n');
}

export function compareBoundary(baseFiles, headFiles) {
  return BOUNDARY_FILES.map((file) => {
    const base = selectPortion(baseFiles[file.path], file.pick);
    const head = selectPortion(headFiles[file.path], file.pick);
    return {
      id: file.id,
      path: file.path,
      changed: base === null || head === null || base !== head,
      missing: base === null || head === null,
    };
  }).filter((item) => item.changed);
}

export function decideAuthBoundary(changes, allowReason) {
  if (changes.length === 0) return { ok: true, allowed: false, changes };
  if (allowReason) return { ok: true, allowed: true, changes, reason: allowReason };
  return { ok: false, allowed: false, changes };
}

function readTreeFile(root, file) {
  const fullPath = resolve(root, file);
  if (!existsSync(fullPath)) return null;
  return readFileSync(fullPath, 'utf8');
}

function gitShow(base, file) {
  try {
    return execFileSync('git', ['show', `${base}:${file}`], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    return null;
  }
}

function loadPair(options) {
  const baseFiles = {};
  const headFiles = {};
  for (const file of BOUNDARY_FILES) {
    if (options.baseRoot) {
      baseFiles[file.path] = readTreeFile(options.baseRoot, file.path);
    } else {
      baseFiles[file.path] = gitShow(options.base, file.path);
    }
    headFiles[file.path] = options.headRoot
      ? readTreeFile(options.headRoot, file.path)
      : readTreeFile(options.root, file.path);
  }
  return { baseFiles, headFiles };
}

export function evaluateAuthBoundary(options) {
  const root = resolve(options.root || process.cwd());
  const { baseFiles, headFiles } = loadPair({ ...options, root });
  const changes = compareBoundary(baseFiles, headFiles);
  const allowPath = resolve(root, ALLOW_FILE);
  const allowReason = existsSync(allowPath) ? readAllowReason(readFileSync(allowPath, 'utf8')) : '';
  const decision = decideAuthBoundary(changes, allowReason);
  return { ...decision, allowPath };
}

function printDecision(decision, baseLabel) {
  if (decision.changes.length === 0) {
    console.log(`auth boundary: matches ${baseLabel}`);
    return;
  }
  console.log(`auth boundary: differs from ${baseLabel}`);
  for (const change of decision.changes) {
    console.log(`- ${change.path}${change.missing ? ' (missing portion)' : ''}`);
  }
  if (decision.allowed) {
    console.log(`allowed: ${decision.reason}`);
    return;
  }
  console.log(`Write a non-comment reason in ${ALLOW_FILE}, or keep these files identical to main.`);
}

function parseArgs(argv) {
  const options = { root: process.cwd(), base: 'origin/main' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--base') options.base = argv[++index];
    else if (arg === '--root') options.root = resolve(argv[++index]);
    else if (arg === '--base-root') options.baseRoot = resolve(argv[++index]);
    else if (arg === '--head-root') options.headRoot = resolve(argv[++index]);
    else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

const isMain = process.argv[1]
  && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1]);

if (isMain) {
  try {
    const options = parseArgs(process.argv.slice(2));
    const decision = evaluateAuthBoundary(options);
    printDecision(decision, options.baseRoot || options.base);
    process.exitCode = decision.ok ? 0 : 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
