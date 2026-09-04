import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

const webRoot = join(process.cwd(), 'src/web');

function collectSourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return collectSourceFiles(path);
    if (!/\.(?:ts|tsx)$/.test(entry.name) || /\.test\.(?:ts|tsx)$/.test(entry.name)) return [];
    return [path];
  });
}

describe('web UI architecture boundary', () => {
  it('keeps Radix imports inside components/ui', () => {
    const allSources = collectSourceFiles(webRoot);
    const uiSources = allSources.filter((path) => {
      const relativePath = relative(webRoot, path).replaceAll('\\', '/');
      return relativePath.startsWith('components/ui/');
    });
    expect(uiSources.some((path) => /@radix-ui\//.test(readFileSync(path, 'utf8')))).toBe(true);

    const directImportsOutsideBoundary = allSources
      .filter((path) => {
        const relativePath = relative(webRoot, path).replaceAll('\\', '/');
        return !relativePath.startsWith('components/ui/');
      })
      .filter((path) => /@radix-ui\//.test(readFileSync(path, 'utf8')))
      .map((path) => relative(process.cwd(), path));

    expect(directImportsOutsideBoundary).toEqual([]);
  });

  it('keeps the compatibility facades third-party-free', () => {
    for (const path of [
      join(webRoot, 'components/CenteredModal.tsx'),
      join(webRoot, 'components/MobileDrawer.tsx'),
      join(webRoot, 'components/ModernSelect.tsx'),
    ]) {
      expect(readFileSync(path, 'utf8')).not.toContain('@radix-ui/');
    }
  });
});
