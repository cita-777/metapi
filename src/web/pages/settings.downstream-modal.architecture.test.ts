import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Settings downstream modal extraction', () => {
  it('delegates the downstream API key portal to a dedicated settings component', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/Settings.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).toContain("import DownstreamApiKeyModal from './settings/DownstreamApiKeyModal.js'");
    expect(source).not.toContain('{downstreamModalPresence.shouldRender && (() => {');
  });
});
