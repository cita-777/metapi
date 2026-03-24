import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Settings route selector modal extraction', () => {
  it('delegates the downstream route selector portal to a dedicated settings component', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/Settings.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).toContain("import RouteSelectorModal from './settings/RouteSelectorModal.js'");
    expect(source).not.toContain('{selectorModalPresence.shouldRender && (() => {');
  });
});
