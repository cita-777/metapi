import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';

const html = readFileSync(resolve(process.cwd(), 'src/web/index.html'), 'utf8');
const initScriptMatch = html.match(/<script>\s*\(function\(\)\{([\s\S]*?)\}\)\(\);\s*<\/script>/);

if (!initScriptMatch?.[1]) {
  throw new Error('Theme initialization script is missing from src/web/index.html');
}
const initScript = initScriptMatch[1];

function resolveTheme(storage: Record<string, string>, prefersDark: boolean): string | null {
  let theme: string | null = null;
  const context = {
    localStorage: {
      getItem: (key: string) => storage[key] ?? null,
    },
    window: {
      matchMedia: () => ({ matches: prefersDark }),
    },
    document: {
      documentElement: {
        setAttribute: (_name: string, value: string) => { theme = value; },
      },
    },
  };
  vm.runInNewContext(initScript, context);
  return theme;
}

describe('index theme initialization', () => {
  it('uses the current theme_mode key before React mounts', () => {
    expect(resolveTheme({ theme_mode: 'dark' }, false)).toBe('dark');
    expect(resolveTheme({ theme_mode: 'light' }, true)).toBe('light');
  });

  it('supports system preference and the legacy theme key', () => {
    expect(resolveTheme({ theme_mode: 'system' }, true)).toBe('dark');
    expect(resolveTheme({ theme: 'dark' }, false)).toBe('dark');
  });
});
