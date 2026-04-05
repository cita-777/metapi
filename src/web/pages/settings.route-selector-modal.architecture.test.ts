import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Settings route selector modal extraction', () => {
  it('no longer keeps a downstream route selector inside Settings', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/Settings.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).not.toContain("import RouteSelectorModal from './settings/RouteSelectorModal.js'");
    expect(source).not.toContain('selectorOpen');
    expect(source).not.toContain('selectorRoutes');
  });
});
