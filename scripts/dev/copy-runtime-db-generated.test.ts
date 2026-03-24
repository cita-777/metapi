import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { copyRuntimeDbGeneratedAssets } from './copy-runtime-db-generated.js';

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('copyRuntimeDbGeneratedAssets', () => {
  it('copies generated runtime db artifacts and shared runtime modules into dist', () => {
    const repoRoot = mkdtempSync(join(tmpdir(), 'metapi-runtime-db-assets-'));
    tempDirs.push(repoRoot);

    const sourceDir = join(repoRoot, 'src', 'server', 'db', 'generated');
    const nestedDir = join(sourceDir, 'fixtures');
    const sharedDir = join(repoRoot, 'src', 'shared');
    const staleSharedDistDir = join(repoRoot, 'dist', 'shared');
    mkdirSync(nestedDir, { recursive: true });
    mkdirSync(sharedDir, { recursive: true });
    mkdirSync(staleSharedDistDir, { recursive: true });
    writeFileSync(join(sourceDir, 'mysql.bootstrap.sql'), 'create table demo ();');
    writeFileSync(join(nestedDir, 'baseline.json'), '{"ok":true}');
    writeFileSync(join(sharedDir, 'tokenRouteContract.d.ts'), 'export declare const demo: number;\n');
    writeFileSync(join(sharedDir, 'tokenRouteContract.js'), 'export const demo = 1;\n');
    writeFileSync(join(sharedDir, 'tokenRouteContract.test.ts'), 'throw new Error("should not ship");\n');
    writeFileSync(join(staleSharedDistDir, 'tokenRouteContract.test.ts'), 'stale test artifact\n');

    copyRuntimeDbGeneratedAssets(repoRoot);

    expect(
      readFileSync(join(repoRoot, 'dist', 'server', 'db', 'generated', 'mysql.bootstrap.sql'), 'utf8'),
    ).toBe('create table demo ();');
    expect(
      readFileSync(join(repoRoot, 'dist', 'server', 'db', 'generated', 'fixtures', 'baseline.json'), 'utf8'),
    ).toBe('{"ok":true}');
    expect(
      readFileSync(join(repoRoot, 'dist', 'shared', 'tokenRouteContract.js'), 'utf8'),
    ).toBe('export const demo = 1;\n');
    expect(
      readFileSync(join(repoRoot, 'dist', 'shared', 'tokenRouteContract.d.ts'), 'utf8'),
    ).toBe('export declare const demo: number;\n');
    expect(
      existsSync(join(repoRoot, 'dist', 'shared', 'tokenRouteContract.test.ts')),
    ).toBe(false);
  });
});
