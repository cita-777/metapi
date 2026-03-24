import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Settings factory reset modal extraction', () => {
  it('delegates the destructive factory reset portal to a dedicated settings component', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/Settings.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).toContain("import FactoryResetModal from './settings/FactoryResetModal.js'");
    expect(source).not.toContain('{factoryResetPresence.shouldRender && (() => {');
  });
});
