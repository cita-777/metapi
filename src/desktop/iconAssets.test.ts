import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('desktop icon assets', () => {
  it('keeps runtime icon paths aligned to the generated desktop icon', async () => {
    const {
      DESKTOP_BUILD_ICON_RELATIVE_PATH,
      DESKTOP_RUNTIME_ICON_RELATIVE_PATH,
      getDesktopRuntimeIconPath,
    } = await import('./iconAssets.js');

    expect(DESKTOP_RUNTIME_ICON_RELATIVE_PATH).toBe(join('dist', 'web', 'desktop-icon.png'));
    expect(DESKTOP_BUILD_ICON_RELATIVE_PATH).toBe(join('build', 'desktop-icon.png'));
    expect(getDesktopRuntimeIconPath('/app')).toBe(join('/app', 'dist', 'web', 'desktop-icon.png'));
  });

  it('points electron-builder at the generated desktop package icon', async () => {
    const configPath = join(process.cwd(), 'electron-builder.yml');
    const config = await readFile(configPath, 'utf8');

    expect(config).toContain('icon: build/desktop-icon.png');
  });
});
