import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('downstreamClientContext architecture boundaries', () => {
  it('keeps protocol-level client metadata on cli profiles instead of importing individual profile helpers', () => {
    const source = readSource('./downstreamClientContext.ts');

    expect(source).toContain("from '../../proxy-core/cliProfiles/registry.js'");
    expect(source).toContain("from '../../proxy-core/cliProfiles/types.js'");
    expect(source).not.toContain("from '../../proxy-core/cliProfiles/codexProfile.js'");
    expect(source).not.toContain("from '../../proxy-core/cliProfiles/claudeCodeProfile.js'");
  });
});
