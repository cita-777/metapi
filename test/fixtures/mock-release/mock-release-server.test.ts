import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  PACKAGE_NAME,
  SCENARIOS,
  buildScenario,
  listTarEntries,
  startMockReleaseServer,
} from './mock-release-server.mjs';

function sha256(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex');
}

function checksumNames(text: string): string[] {
  return text.split('\n').filter(Boolean).map((line) => line.split(/\s+/).slice(1).join(' '));
}

function walk(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir)) {
    const fullPath = join(dir, entry);
    if (statSync(fullPath).isDirectory()) files.push(...walk(fullPath));
    else files.push(fullPath);
  }
  return files;
}

describe('mock release server fixture', () => {
  it('serves a normal package whose checksum matches the bytes', () => {
    const scenario = buildScenario('normal');
    const hash = sha256(scenario.tar);
    expect(scenario.checksums.toString('utf8')).toContain(`${hash}  ${PACKAGE_NAME}`);
    expect(JSON.parse(scenario.manifest.toString('utf8')).version).toBe(scenario.manifestVersion);
    const names = listTarEntries(scenario.tar).map((entry) => entry.name);
    expect(names).toContain('server.js');
    expect(names.some((name) => name.includes('..'))).toBe(false);
  });

  it('serves a package whose bytes no longer match checksums.txt', () => {
    const scenario = buildScenario('swapped');
    const recorded = scenario.checksums.toString('utf8').match(/[0-9a-f]{64}/)?.[0];
    expect(recorded).toBeTruthy();
    expect(sha256(scenario.tar)).not.toBe(recorded);
  });

  it('serves a tar with a parent-path entry and a symlink entry', () => {
    const parent = listTarEntries(buildScenario('tar-parent').tar);
    expect(parent.some((entry) => entry.name.includes('../'))).toBe(true);
    const link = listTarEntries(buildScenario('tar-symlink').tar);
    expect(link.some((entry) => entry.typeflag === '2' && entry.linkname.includes('..'))).toBe(true);
  });

  it('serves checksums.txt with the package row missing', () => {
    const scenario = buildScenario('checksum-missing');
    expect(checksumNames(scenario.checksums.toString('utf8'))).not.toContain(PACKAGE_NAME);
  });

  it('serves checksums.txt with two different hashes for the same filename', () => {
    const lines = buildScenario('checksum-duplicate').checksums.toString('utf8').trim().split('\n');
    const hashes = lines
      .filter((line) => line.endsWith(`  ${PACKAGE_NAME}`))
      .map((line) => line.split(/\s+/)[0]);
    expect(hashes).toHaveLength(2);
    expect(new Set(hashes).size).toBe(2);
  });

  it('serves a complete older release at a newer advertised version', () => {
    const scenario = buildScenario('older-as-newer');
    expect(scenario.advertisedVersion).toBe('2.0.0');
    expect(JSON.parse(scenario.manifest.toString('utf8')).version).toBe('1.0.0');
    expect(scenario.checksums.toString('utf8')).toContain(sha256(scenario.tar));
    expect(scenario.checksums.toString('utf8')).toContain(sha256(scenario.manifest));
  });

  it('serves every scenario on loopback', async () => {
    const server = await startMockReleaseServer();
    expect(server.url.startsWith('http://127.0.0.1:')).toBe(true);
    try {
      const index = await fetch(`${server.url}/fixture`);
      expect(await index.json()).toEqual({ scenarios: SCENARIOS });
      for (const scenario of SCENARIOS) {
        const response = await fetch(`${server.url}/fixture/${scenario}/${PACKAGE_NAME}`);
        expect(response.status).toBe(200);
        expect(Buffer.from(await response.arrayBuffer()).equals(buildScenario(scenario).tar)).toBe(true);
      }
    } finally {
      await server.close();
    }
  });

  it('refuses a non-loopback bind and is not referenced from src', async () => {
    expect(() => startMockReleaseServer({ host: '0.0.0.0' })).toThrow(/loopback/);
    const sources = walk(join(process.cwd(), 'src')).filter((file) => /\.(ts|tsx|js|mjs)$/.test(file));
    const hits = sources.filter((file) => readFileSync(file, 'utf8').includes('mock-release-server'));
    expect(hits).toEqual([]);
  });
});
