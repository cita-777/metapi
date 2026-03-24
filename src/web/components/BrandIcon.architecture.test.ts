import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function readSource(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

describe('BrandIcon architecture boundaries', () => {
  it('keeps brand registry rules outside the React render component', () => {
    const source = readSource('./BrandIcon.tsx');

    expect(source).toContain("from './brandRegistry.js'");
    expect(source).not.toContain('const BRAND_DEFINITIONS');
    expect(source).not.toContain('function getBrand(');
  });
});
