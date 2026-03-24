import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('modelService discovery architecture boundaries', () => {
  it('keeps platform-specific oauth discovery HTTP logic in a dedicated discovery registry', () => {
    const source = readSource('./modelService.ts');

    expect(source).toContain("from './platformDiscoveryRegistry.js'");
    expect(source).not.toContain('function discoverCodexModelsFromCloud');
    expect(source).not.toContain('function discoverClaudeModelsFromCloud');
    expect(source).not.toContain('function validateGeminiCliOauthConnection');
    expect(source).not.toContain('function discoverAntigravityModelsFromCloud');
  });
});
