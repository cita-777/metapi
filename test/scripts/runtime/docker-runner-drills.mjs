// Temp-directory drills that call run() once scripts/runtime/docker-runner.mjs exports it.
// That module is not on this main, so the vitest file skips these drills.
// They become required in the runner PR.
// run() must honor { once: true } / METAPI_RUNNER_ONCE=1 and stop child processes before it resolves.
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
  chownSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { join, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

export const RUNNER_RELATIVE_PATH = 'scripts/runtime/docker-runner.mjs';

export const DRILL_NAMES = [
  'first-start',
  'upgrade',
  'health-check-failure-rollback-db',
  'tampered-volume-rollback',
  'node-major-mismatch',
  'image-newer-than-runtime',
  'wrong-volume-ownership',
  'pg-dump-missing',
  'pg-dump-wrong-version',
  'backup-write-failure',
];

const NODE_MAJOR = Number.parseInt(process.versions.node.split('.')[0] || '0', 10);

export function probeRunner(root = process.cwd()) {
  const file = resolve(root, RUNNER_RELATIVE_PATH);
  if (!existsSync(file)) {
    return {
      available: false,
      file,
      reason: 'scripts/runtime/docker-runner.mjs is not on this main. These drills become required in the runner PR.',
    };
  }
  const source = readFileSync(file, 'utf8');
  const exported = /export\s+(?:async\s+)?function\s+run\s*\(/.test(source)
    || /export\s*\{[^}]*\brun\b[^}]*\}/s.test(source);
  if (!exported) {
    return {
      available: false,
      file,
      reason: 'scripts/runtime/docker-runner.mjs does not export run(). These drills become required in the runner PR.',
    };
  }
  return { available: true, file, reason: '' };
}

function reservePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close(() => resolvePort(port));
    });
  });
}

function manifest(version, nodeMajor) {
  return {
    schemaVersion: 1,
    version,
    channel: 'stable',
    platform: 'linux',
    arch: process.arch === 'arm64' ? 'arm64' : 'amd64',
    nodeMajor,
    entrypoint: 'server.mjs',
    migrationEntrypoint: 'migrate.mjs',
  };
}

function serverSource(mode) {
  if (mode === 'fail') return 'process.exit(1);\n';
  return `
import { createServer } from 'node:http';
const port = Number(process.env.PORT || 0);
const server = createServer((req, res) => {
  if ((req.url || '').split('?')[0] === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, version: process.env.METAPI_RELEASE_VERSION || '' }));
    setTimeout(() => process.exit(0), 20);
    return;
  }
  res.writeHead(404).end();
});
server.listen(port, '127.0.0.1');
`;
}

function migrateSource(mode) {
  if (mode !== 'rewrite-db') return 'process.exit(0);\n';
  return `
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const dataDir = process.env.DATA_DIR;
if (!dataDir) process.exit(2);
mkdirSync(dataDir, { recursive: true });
writeFileSync(join(dataDir, 'hub.db'), 'rows=9\\n');
writeFileSync(new URL('./migrate-ran', import.meta.url), '1');
`;
}

function writeRelease(dir, { version, nodeMajor = NODE_MAJOR, server = 'ok', migrate = 'noop', bytes = 'ok' }) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'release.json'), JSON.stringify(manifest(version, nodeMajor)));
  writeFileSync(join(dir, 'server.mjs'), serverSource(server).replace("console.log('ok')", `console.log(${JSON.stringify(bytes)})`));
  if (server === 'ok') {
    writeFileSync(join(dir, 'server.mjs'), serverSource('ok'));
    writeFileSync(join(dir, 'payload.txt'), bytes);
  }
  writeFileSync(join(dir, 'migrate.mjs'), migrateSource(migrate));
}

function linkCurrent(runtime, version) {
  symlinkSync(`releases/${version}`, join(runtime, 'current'));
}

function writePending(runtime, targetVersion, previousVersion) {
  writeFileSync(join(runtime, 'pending.json'), JSON.stringify({
    schemaVersion: 1,
    taskId: `drill-${targetVersion}`,
    targetVersion,
    previousVersion,
    phase: 'restarting',
    rollbackBudget: 1,
    reason: 'install',
    createdAt: '2026-11-12T00:00:00.000Z',
    updatedAt: '2026-11-12T00:00:00.000Z',
  }));
}

function currentVersion(runtime) {
  const link = readlinkSync(join(runtime, 'current'));
  const releaseJson = JSON.parse(readFileSync(join(runtime, link, 'release.json'), 'utf8'));
  return releaseJson.version;
}

function baseEnv(runtime, bootstrap, dataDir, port, extra = {}) {
  return {
    PATH: extra.PATH || process.env.PATH || '',
    HOME: process.env.HOME || tmpdir(),
    LANG: 'C',
    METAPI_RUNTIME_DIR: runtime,
    METAPI_BOOTSTRAP_DIR: bootstrap,
    METAPI_RUNNER_ONCE: '1',
    DATA_DIR: dataDir,
    PORT: String(port),
    ...extra,
  };
}

async function callRun(runnerFile, options) {
  const imported = await import(`${pathToFileURL(runnerFile).href}?drill=${Date.now()}-${Math.random().toString(16).slice(2)}`);
  if (typeof imported.run !== 'function') {
    throw new Error('scripts/runtime/docker-runner.mjs must export run()');
  }
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error('run() did not finish; the runner PR must honor once:true and stop child processes'));
    }, 12000);
  });
  try {
    return await Promise.race([
      imported.run({ once: true, healthTimeoutMs: 800, ...options }),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function expectStopped(runnerFile, options, pattern) {
  let message = '';
  let failed = false;
  try {
    const value = await callRun(runnerFile, options);
    if (value && value.ok === false) {
      failed = true;
      message = String(value.error || value.message || '');
    }
  } catch (error) {
    failed = true;
    message = error instanceof Error ? error.message : String(error);
  }
  if (!failed) throw new Error('expected run() to stop this drill');
  if (pattern && !pattern.test(message)) {
    throw new Error(`run() stopped without the expected explanation: ${message}`);
  }
}

function makeRoot() {
  const root = mkdtempSync(join(tmpdir(), 'metapi-runner-drill-'));
  const runtime = join(root, 'runtime');
  const bootstrap = join(root, 'bootstrap');
  const dataDir = join(runtime, 'data');
  mkdirSync(dataDir, { recursive: true });
  return { root, runtime, bootstrap, dataDir };
}

function cleanup(root, dataDir) {
  try {
    chmodSync(dataDir, 0o755);
  } catch {
    // The directory may already be writable.
  }
  rmSync(root, { recursive: true, force: true });
}

async function withLayout(work) {
  const layout = makeRoot();
  const port = await reservePort();
  try {
    await work({ ...layout, port });
  } finally {
    cleanup(layout.root, layout.dataDir);
  }
}

function optionsFor(runnerFile, layout, extraEnv = {}, extra = {}) {
  return {
    runnerFile,
    runtimeDir: layout.runtime,
    bootstrapDir: layout.bootstrap,
    env: baseEnv(layout.runtime, layout.bootstrap, layout.dataDir, layout.port, extraEnv),
    ...extra,
  };
}

async function runNamedDrill(name, runnerFile) {
  if (name === 'first-start') {
    await withLayout(async (layout) => {
      writeRelease(layout.bootstrap, { version: '1.0.0' });
      await callRun(runnerFile, optionsFor(runnerFile, layout));
      if (currentVersion(layout.runtime) !== '1.0.0') {
        throw new Error('first start did not select the bootstrap release');
      }
    });
    return;
  }

  if (name === 'upgrade') {
    await withLayout(async (layout) => {
      writeRelease(layout.bootstrap, { version: '1.0.0' });
      writeRelease(join(layout.runtime, 'releases', '1.0.0'), { version: '1.0.0' });
      writeRelease(join(layout.runtime, 'releases', '1.1.0'), { version: '1.1.0' });
      linkCurrent(layout.runtime, '1.0.0');
      writePending(layout.runtime, '1.1.0', '1.0.0');
      await callRun(runnerFile, optionsFor(runnerFile, layout));
      if (currentVersion(layout.runtime) !== '1.1.0') throw new Error('upgrade did not select 1.1.0');
      if (readlinkSync(join(layout.runtime, 'previous')) !== 'releases/1.0.0') {
        throw new Error('upgrade did not keep 1.0.0 as previous');
      }
      if (existsSync(join(layout.runtime, 'pending.json'))) throw new Error('pending file was left behind');
    });
    return;
  }

  if (name === 'health-check-failure-rollback-db') {
    await withLayout(async (layout) => {
      const original = 'rows=2\n';
      writeFileSync(join(layout.dataDir, 'hub.db'), original);
      writeRelease(layout.bootstrap, { version: '1.0.0' });
      writeRelease(join(layout.runtime, 'releases', '1.0.0'), { version: '1.0.0' });
      writeRelease(join(layout.runtime, 'releases', '1.1.0'), { version: '1.1.0', server: 'fail', migrate: 'rewrite-db' });
      linkCurrent(layout.runtime, '1.0.0');
      symlinkSync('releases/1.0.0', join(layout.runtime, 'previous'));
      writePending(layout.runtime, '1.1.0', '1.0.0');
      await callRun(runnerFile, optionsFor(runnerFile, layout));
      if (currentVersion(layout.runtime) !== '1.0.0') throw new Error('rollback did not return to 1.0.0');
      const restored = readFileSync(join(layout.dataDir, 'hub.db'), 'utf8');
      if (restored !== original) throw new Error('database was not restored from the pre-migration backup');
      if (!existsSync(join(layout.runtime, 'releases', '1.1.0', 'migrate-ran'))) {
        throw new Error('migration did not run before the health check failed');
      }
    });
    return;
  }

  if (name === 'tampered-volume-rollback') {
    await withLayout(async (layout) => {
      writeRelease(layout.bootstrap, { version: '1.0.0', bytes: 'image' });
      writeRelease(join(layout.runtime, 'releases', '1.0.0'), { version: '1.0.0', bytes: 'image' });
      const payloadPath = join(layout.runtime, 'releases', '1.0.0', 'payload.txt');
      const installed = readFileSync(payloadPath);
      writeFileSync(join(layout.runtime, 'integrity.json'), JSON.stringify({
        version: '1.0.0',
        sha256: createHash('sha256').update(installed).digest('hex'),
      }));
      writeFileSync(payloadPath, 'tampered');
      linkCurrent(layout.runtime, '1.0.0');
      await callRun(runnerFile, optionsFor(runnerFile, layout));
      const selected = join(layout.runtime, readlinkSync(join(layout.runtime, 'current')), 'payload.txt');
      if (readFileSync(selected, 'utf8') !== 'image') {
        throw new Error('tampered volume was not replaced by the image payload');
      }
    });
    return;
  }

  if (name === 'node-major-mismatch') {
    await withLayout(async (layout) => {
      writeRelease(layout.bootstrap, { version: '1.0.0', nodeMajor: NODE_MAJOR });
      writeRelease(join(layout.runtime, 'releases', '9.0.0'), { version: '9.0.0', nodeMajor: NODE_MAJOR + 20 });
      linkCurrent(layout.runtime, '9.0.0');
      const notes = [];
      const warn = console.warn;
      const error = console.error;
      console.warn = (...args) => { notes.push(args.map(String).join(' ')); warn(...args); };
      console.error = (...args) => { notes.push(args.map(String).join(' ')); error(...args); };
      try {
        const result = await callRun(runnerFile, optionsFor(runnerFile, layout));
        notes.push(JSON.stringify(result ?? null));
      } finally {
        console.warn = warn;
        console.error = error;
      }
      const statePath = join(layout.runtime, 'state.json');
      if (existsSync(statePath)) notes.push(readFileSync(statePath, 'utf8'));
      if (currentVersion(layout.runtime) !== '1.0.0') throw new Error('node major mismatch did not fall back to the image');
      if (!/node/i.test(notes.join('\n'))) throw new Error('node major mismatch did not record a warning');
    });
    return;
  }

  if (name === 'image-newer-than-runtime') {
    await withLayout(async (layout) => {
      writeRelease(layout.bootstrap, { version: '1.2.0' });
      writeRelease(join(layout.runtime, 'releases', '1.0.0'), { version: '1.0.0' });
      linkCurrent(layout.runtime, '1.0.0');
      await callRun(runnerFile, optionsFor(runnerFile, layout));
      if (currentVersion(layout.runtime) !== '1.2.0') throw new Error('newer image did not replace the runtime release');
    });
    return;
  }

  if (name === 'wrong-volume-ownership') {
    await withLayout(async (layout) => {
      writeRelease(layout.bootstrap, { version: '1.0.0' });
      const before = statSync(layout.runtime).uid;
      let usedRealOwner = false;
      try {
        chownSync(layout.runtime, 1, 1);
        usedRealOwner = statSync(layout.runtime).uid === 1;
      } catch {
        usedRealOwner = false;
      }
      const extra = usedRealOwner ? {} : { expectedVolumeUid: before + 1 };
      await expectStopped(
        runnerFile,
        optionsFor(runnerFile, layout, {}, extra),
        /owner|ownership|属主|chown/i,
      );
      const after = statSync(layout.runtime).uid;
      const expectedUid = usedRealOwner ? 1 : before;
      if (after !== expectedUid) throw new Error('run() changed the volume owner');
    });
    return;
  }

  if (name === 'pg-dump-missing' || name === 'pg-dump-wrong-version') {
    await withLayout(async (layout) => {
      writeRelease(layout.bootstrap, { version: '1.0.0' });
      writeRelease(join(layout.runtime, 'releases', '1.0.0'), { version: '1.0.0' });
      writeRelease(join(layout.runtime, 'releases', '1.1.0'), { version: '1.1.0', migrate: 'rewrite-db' });
      linkCurrent(layout.runtime, '1.0.0');
      writePending(layout.runtime, '1.1.0', '1.0.0');
      const bin = join(layout.root, 'bin');
      mkdirSync(bin);
      if (name === 'pg-dump-wrong-version') {
        const script = join(bin, 'pg_dump');
        writeFileSync(script, '#!/bin/sh\necho "pg_dump (PostgreSQL) 16.1"\nexit 0\n');
        chmodSync(script, 0o755);
      }
      await expectStopped(
        runnerFile,
        optionsFor(runnerFile, layout, {
          PATH: bin,
          DB_TYPE: 'postgres',
          METAPI_PG_SERVER_MAJOR: '18',
        }),
        /pg_dump/i,
      );
      if (existsSync(join(layout.runtime, 'releases', '1.1.0', 'migrate-ran'))) {
        throw new Error('migration ran without a usable pg_dump');
      }
      if (currentVersion(layout.runtime) !== '1.0.0') throw new Error('version changed without a usable pg_dump');
    });
    return;
  }

  if (name === 'backup-write-failure') {
    await withLayout(async (layout) => {
      writeFileSync(join(layout.dataDir, 'hub.db'), 'rows=2\n');
      writeFileSync(join(layout.dataDir, 'backups'), 'not-a-directory\n');
      writeRelease(layout.bootstrap, { version: '1.0.0' });
      writeRelease(join(layout.runtime, 'releases', '1.0.0'), { version: '1.0.0' });
      writeRelease(join(layout.runtime, 'releases', '1.1.0'), { version: '1.1.0', migrate: 'rewrite-db' });
      linkCurrent(layout.runtime, '1.0.0');
      writePending(layout.runtime, '1.1.0', '1.0.0');
      await expectStopped(runnerFile, optionsFor(runnerFile, layout), /backup|备份|ENOTDIR|EEXIST/i);
      if (existsSync(join(layout.runtime, 'releases', '1.1.0', 'migrate-ran'))) {
        throw new Error('migration ran after the backup write failed');
      }
      if (readFileSync(join(layout.dataDir, 'hub.db'), 'utf8') !== 'rows=2\n') {
        throw new Error('database changed after the backup write failed');
      }
      if (currentVersion(layout.runtime) !== '1.0.0') throw new Error('version changed after the backup write failed');
    });
    return;
  }

  throw new Error(`unknown drill: ${name}`);
}

export async function runDrill(name, root = process.cwd()) {
  const probe = probeRunner(root);
  if (!probe.available) throw new Error(probe.reason);
  await runNamedDrill(name, probe.file);
}

const isMain = process.argv[1]
  && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1]);

if (isMain) {
  const name = process.argv[2];
  if (!DRILL_NAMES.includes(name)) {
    console.error(`usage: node test/scripts/runtime/docker-runner-drills.mjs <${DRILL_NAMES.join('|')}>`);
    process.exitCode = 1;
  } else {
    runDrill(name).catch((error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
  }
}
