import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function source(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('local update center architecture boundaries', () => {
  it('keeps archive, network, hashing, and filesystem ownership in the service', () => {
    const route = readFileSync(new URL('../routes/api/updateCenter.ts', import.meta.url), 'utf8');
    const service = source('./updateCenterLocalUpdateService.ts');

    expect(route).toContain("from '../../services/updateCenterLocalUpdateService.js'");
    for (const forbidden of ["from 'node:fs", "from 'node:fs/promises'", "from 'undici'", "from 'tar'", 'createHash(', 'tarExtract(']) {
      expect(route).not.toContain(forbidden);
    }
    expect(service).toContain("from 'node:fs/promises'");
    expect(service).toContain("from 'undici'");
    expect(service).toContain("from 'tar'");
    expect(service).toContain('extractUpdateCenterArchive');
    expect(service).toContain('atomicallySetPointer');
  });

  it('does not reintroduce the removed helper or cluster deployment owners', () => {
    expect(existsSync(new URL('../update-helper/index.ts', import.meta.url))).toBe(false);
    expect(existsSync(new URL('../../../deploy/k3s/metapi-deploy-helper.yaml', import.meta.url))).toBe(false);
    expect(existsSync(new URL('../../../docs/k3s-update-center.md', import.meta.url))).toBe(false);
    expect(existsSync(new URL('./updateCenterHelperClient.ts', import.meta.url))).toBe(false);
    expect(existsSync(new URL('./updateCenterDeployGuardService.ts', import.meta.url))).toBe(false);
  });
});
