import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import {
  assertNativeBuildTarget,
  normalizeArch,
  normalizeVersion,
  parseArgs,
} from './build-server-bundle.mjs';

describe('server release bundle builder', () => {
  it('normalizes only the supported release versions and architectures', () => {
    expect(normalizeVersion('v1.2.3')).toBe('1.2.3');
    expect(normalizeArch('x86_64')).toBe('amd64');
    expect(normalizeArch('aarch64')).toBe('arm64');
    expect(() => normalizeVersion('1.2.3-rc.1')).toThrow();
    expect(() => normalizeVersion('01.2.3')).toThrow();
    expect(() => normalizeArch('armv7')).toThrow();
  });

  it('parses an explicit architecture and cross-build inspection flag', () => {
    expect(parseArgs(['--version', '1.2.3', '--arch', 'arm64', '--out-dir', '/tmp/metapi-release', '--allow-cross-arch'])).toMatchObject({
      version: '1.2.3',
      arch: 'arm64',
      outDir: '/tmp/metapi-release',
      allowCrossArch: true,
    });
  });

  it('requires native Linux builds unless inspection mode is explicit', () => {
    expect(() => assertNativeBuildTarget('arm64', true)).not.toThrow();
    if (process.platform !== 'linux') {
      expect(() => assertNativeBuildTarget('arm64', false)).toThrow(/built on Linux/);
    }
  });

  it('keeps the published bundle focused on server runtime files', () => {
    const builderSource = readFileSync(new URL('./build-server-bundle.mjs', import.meta.url), 'utf8');
    expect(builderSource).toContain("'desktop'");
    expect(builderSource).toContain("path.endsWith('.d.ts')");
    expect(builderSource).toContain("['rebuild', 'better-sqlite3'");
    expect(builderSource).toContain("test_extension.node");
  });
});
