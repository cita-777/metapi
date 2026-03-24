import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('account token route architecture boundaries', () => {
  it('keeps legacy token repair from forcing route rebuilds inline', () => {
    const source = readSource('./accountTokens.ts');
    expect(source).not.toContain('rebuildRoutes: true');
  });
});
