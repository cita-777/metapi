import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('schema metadata architecture boundaries', () => {
  it('keeps logical column type heuristics in a shared schemaMetadata helper', () => {
    const contractSource = readSource('./schemaContract.ts');
    const introspectionSource = readSource('./schemaIntrospection.ts');

    expect(contractSource).toContain("from './schemaMetadata.js'");
    expect(introspectionSource).toContain("from './schemaMetadata.js'");

    for (const source of [contractSource, introspectionSource]) {
      expect(source).not.toContain('function isBooleanLikeColumn');
      expect(source).not.toContain('function isDateTimeLikeColumn');
      expect(source).not.toContain('function isJsonLikeColumn');
    }
  });
});
