import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('App mobile layout', () => {
  it('sets data-layout attribute when switching layouts', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/App.tsx'), 'utf8');

    expect(source).toContain('useIsMobile(768)');
    expect(source).toContain("document.documentElement.setAttribute('data-layout'");
  });
});
