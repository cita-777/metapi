import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  compareBoundary,
  decideAuthBoundary,
  extractIsPublicApiRoute,
  extractTrustProxyPortion,
  readAllowReason,
} from './auth-boundary-guard.mjs';

const desktop = readFileSync(join(process.cwd(), 'src/server/desktop.ts'), 'utf8');
const config = readFileSync(join(process.cwd(), 'src/server/config.ts'), 'utf8');

function writeTree(root: string, desktopBody: string) {
  mkdirSync(join(root, 'src/server/middleware'), { recursive: true });
  mkdirSync(join(root, 'src/server'), { recursive: true });
  writeFileSync(join(root, 'src/server/middleware/apiPath.ts'), 'export const api = 1;\n');
  writeFileSync(join(root, 'src/server/middleware/auth.ts'), 'export const auth = 1;\n');
  writeFileSync(join(root, 'src/server/desktop.ts'), desktopBody);
  writeFileSync(join(root, 'src/server/config.ts'), 'trustedProxies: parseCsvList(env.TRUSTED_PROXIES),\ntrustProxy: appConfig.trustedProxies.length > 0 ? appConfig.trustedProxies : false,\n');
}

describe('auth boundary guard', () => {
  it('extracts isPublicApiRoute and the trustProxy lines from main', () => {
    expect(extractIsPublicApiRoute(desktop)).toContain('export function isPublicApiRoute');
    expect(extractTrustProxyPortion(config)).toContain('trustProxy:');
    expect(extractTrustProxyPortion(config)).toContain('trustedProxies:');
    expect(readAllowReason('# only a comment\n\n')).toBe('');
    expect(readAllowReason('# note\nreviewed API rename\n')).toBe('reviewed API rename');
  });

  it('fails a changed boundary unless a reason is present', () => {
    const base = {
      'src/server/middleware/apiPath.ts': 'same\n',
      'src/server/middleware/auth.ts': 'same\n',
      'src/server/desktop.ts': desktop,
      'src/server/config.ts': config,
    };
    const head = { ...base, 'src/server/middleware/auth.ts': 'changed\n' };
    const changes = compareBoundary(base, head);
    expect(changes.map((item: { id: string }) => item.id)).toEqual(['auth']);
    expect(decideAuthBoundary(changes, '').ok).toBe(false);
    expect(decideAuthBoundary(changes, 'reviewed API rename').ok).toBe(true);
    expect(decideAuthBoundary([], '').ok).toBe(true);
  });

  it('exits 0 for identical trees and 1 after an unapproved edit', () => {
    const root = mkdtempSync(join(tmpdir(), 'metapi-auth-guard-'));
    const base = join(root, 'base');
    const head = join(root, 'head');
    const body = 'export function isPublicApiRoute(url: string): boolean {\n  return false;\n}\n';
    writeTree(base, body);
    writeTree(head, body);
    const script = new URL('./auth-boundary-guard.mjs', import.meta.url).pathname;
    const same = spawnSync(process.execPath, [script, '--base-root', base, '--head-root', head, '--root', head], { encoding: 'utf8' });
    expect(same.status).toBe(0);
    writeTree(head, 'export function isPublicApiRoute(url: string): boolean {\n  return true;\n}\n');
    const changed = spawnSync(process.execPath, [script, '--base-root', base, '--head-root', head, '--root', head], { encoding: 'utf8' });
    expect(changed.status).toBe(1);
    expect(changed.stdout).toContain('src/server/desktop.ts');
    expect(changed.stdout).not.toContain('return true');
  });
});
