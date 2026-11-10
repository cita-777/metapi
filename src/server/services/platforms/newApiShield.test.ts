import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';

const vmCalls: string[] = [];
vi.mock('node:vm', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:vm')>();
  return {
    ...actual,
    createContext: (...args: Parameters<typeof actual.createContext>) => {
      vmCalls.push('createContext');
      return actual.createContext(...args);
    },
    runInContext: (...args: Parameters<typeof actual.runInContext>) => {
      vmCalls.push('runInContext');
      return actual.runInContext(...args);
    },
  };
});

const { solveNewApiAcwScV2 } = await import('./newApiShield.js');
const { NewApiAdapter } = await import('./newApi.js');

const CHALLENGE_HTML = readFileSync(new URL('./__fixtures__/anyrouter-challenge.html', import.meta.url), 'utf8');
const CHALLENGE_ACW = '699dbedad126579b6bc0ebb91eaae8d7af3548b5';
const MARKER = '__metapiShieldTestMarker';

afterEach(() => {
  vmCalls.length = 0;
  delete (globalThis as Record<string, unknown>)[MARKER];
});

describe('new-api shield challenge solver', () => {
  it('solves the challenge by parsing data only, without node:vm', () => {
    expect(solveNewApiAcwScV2(CHALLENGE_HTML)).toBe(CHALLENGE_ACW);
    const adapter = new NewApiAdapter() as unknown as { solveAcwScV2(html: string): string | null };
    expect(adapter.solveAcwScV2(CHALLENGE_HTML)).toBe(CHALLENGE_ACW);
    expect(vmCalls).toEqual([]);
  });

  it('does not run upstream-supplied script from the challenge page', () => {
    // Replace the page's helper functions with script that would leave a marker if executed.
    const marker = `globalThis.${MARKER}=true;`;
    const tampered = CHALLENGE_HTML
      .replace('function a0i(){', `function a0i(){${marker}`)
      .replace('(function(a,c){', `(function(a,c){${marker}`);
    expect(tampered).not.toBe(CHALLENGE_HTML);

    solveNewApiAcwScV2(tampered);
    const adapter = new NewApiAdapter() as unknown as { solveAcwScV2(html: string): string | null };
    adapter.solveAcwScV2(tampered);

    expect((globalThis as Record<string, unknown>)[MARKER]).toBeUndefined();
    expect(vmCalls).toEqual([]);
  });

  it('fails closed when the seed cannot be parsed unambiguously', () => {
    expect(solveNewApiAcwScV2('<html><script>var arg1="ABC123";</script></html>')).toBeNull();
    const withoutTable = CHALLENGE_HTML.replace(/function a0i\(\)\{var N=\[[^\]]*\]/, 'function a0i(){var N=[]');
    expect(solveNewApiAcwScV2(withoutTable)).toBeNull();
  });
});
