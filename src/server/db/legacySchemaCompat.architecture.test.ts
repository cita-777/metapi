import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('legacySchemaCompat architecture boundaries', () => {
  it('derives feature-owned legacy mutations from compatibility specs instead of hardcoding a second full whitelist', () => {
    const source = readSource('./legacySchemaCompat.ts');

    expect(source).toContain('ACCOUNT_TOKEN_COLUMN_COMPATIBILITY_SPECS');
    expect(source).toContain('PROXY_FILE_COLUMN_COMPATIBILITY_SPECS');
    expect(source).toContain('ROUTE_GROUPING_COLUMN_COMPATIBILITY_SPECS');
    expect(source).toContain('SITE_COLUMN_COMPATIBILITY_SPECS');
    expect(source).toContain('SITE_TABLE_COMPATIBILITY_SPECS');
  });
});
