import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('downstreamClientContext architecture boundaries', () => {
  it('keeps shared downstream client detection outside the route layer and avoids individual profile helper imports', () => {
    const source = readSource('../../proxy-core/downstreamClientContext.ts');

    expect(source).toContain("from './cliProfiles/registry.js'");
    expect(source).toContain("from './cliProfiles/types.js'");
    expect(source).not.toContain("from './cliProfiles/codexProfile.js'");
    expect(source).not.toContain("from './cliProfiles/claudeCodeProfile.js'");
  });
});
