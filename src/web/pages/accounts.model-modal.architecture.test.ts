import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Accounts model modal extraction', () => {
  it('delegates the account model management modal to a dedicated accounts component', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/web/pages/Accounts.tsx'), 'utf8').replace(/\r\n/g, '\n');

    expect(source).toContain("import AccountModelsModal from './accounts/AccountModelsModal.js'");
    expect(source).not.toContain('open={modelModal.open}');
  });
});
