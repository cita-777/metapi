import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

import { verifyMacArchitecture } from './verifyMacArchitecture.mjs';

const tempDirs: string[] = [];

function createReleaseBinary() {
  const releaseDir = mkdtempSync(join(tmpdir(), 'metapi-mac-arch-'));
  tempDirs.push(releaseDir);

  const binaryPath = join(releaseDir, 'mac-x64', 'Metapi.app', 'Contents', 'MacOS', 'Metapi');
  mkdirSync(dirname(binaryPath), { recursive: true });
  writeFileSync(binaryPath, 'binary');

  return { releaseDir, binaryPath };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe('verifyMacArchitecture', () => {
  it('accepts x64 binaries when lipo reports x86_64', () => {
    const { releaseDir, binaryPath } = createReleaseBinary();

    expect(
      verifyMacArchitecture({
        releaseDir,
        expectedArch: 'x64',
        inspectBinaryArchs: () => 'x86_64',
      }),
    ).toEqual([{ archs: 'x86_64', binaryPath }]);
  });

  it('rejects x64 binaries when lipo reports arm64', () => {
    const { releaseDir } = createReleaseBinary();

    expect(() =>
      verifyMacArchitecture({
        releaseDir,
        expectedArch: 'x64',
        inspectBinaryArchs: () => 'arm64',
      }),
    ).toThrow(/Expected x86_64-only binary but got: arm64/);
  });
});
