import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('desktop icon assets', () => {
  it('keeps runtime icon paths aligned to the generated desktop icon', async () => {
    const {
      DESKTOP_BUILD_ICON_RELATIVE_PATH,
      DESKTOP_RUNTIME_ICON_RELATIVE_PATH,
      DESKTOP_TRAY_TEMPLATE_ICON_RELATIVE_PATH,
      getDesktopRuntimeIconPath,
      getDesktopTrayIconPath,
    } = await import('./iconAssets.js');

    expect(DESKTOP_RUNTIME_ICON_RELATIVE_PATH).toBe(join('dist', 'web', 'desktop-icon.png'));
    expect(DESKTOP_BUILD_ICON_RELATIVE_PATH).toBe(join('build', 'desktop-icon.png'));
    expect(DESKTOP_TRAY_TEMPLATE_ICON_RELATIVE_PATH).toBe(join('dist', 'web', 'desktop-tray-template.png'));
    expect(getDesktopRuntimeIconPath('/app')).toBe(join('/app', 'dist', 'web', 'desktop-icon.png'));
    expect(getDesktopTrayIconPath('/app', 'darwin')).toBe(join('/app', 'dist', 'web', 'desktop-tray-template.png'));
    expect(getDesktopTrayIconPath('/app', 'win32')).toBe(join('/app', 'dist', 'web', 'desktop-icon.png'));
  });

  it('points electron-builder at the generated desktop package icon', async () => {
    const configPath = join(process.cwd(), 'electron-builder.yml');
    const config = await readFile(configPath, 'utf8');

    expect(config).toContain('icon: build/desktop-icon.png');
  });

  it('builds Linux desktop packages for AppImage, deb, and rpm distributions', async () => {
    const configPath = join(process.cwd(), 'electron-builder.yml');
    const require = createRequire(import.meta.url);
    const { load } = require('js-yaml') as { load: (source: string) => { linux?: { target?: string[] } } };
    const config = load(await readFile(configPath, 'utf8'));

    expect(config.linux?.target).toEqual(expect.arrayContaining(['AppImage', 'deb', 'rpm']));
  });
});
