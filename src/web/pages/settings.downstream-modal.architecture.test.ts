import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Settings downstream modal extraction', () => {
  it('no longer keeps a dedicated downstream API key editor inside Settings', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/Settings.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).not.toContain("import DownstreamApiKeyModal from './settings/DownstreamApiKeyModal.js'");
    expect(source).not.toContain('downstreamModalOpen');
    expect(source).not.toContain('downstreamCreate');
  });
});
