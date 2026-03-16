import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import sharp from 'sharp';
import { afterEach, describe, expect, it } from 'vitest';

const tempDirs: string[] = [];

async function makeTempDir() {
  const dir = await mkdtemp(join(tmpdir(), 'metapi-desktop-icons-'));
  tempDirs.push(dir);
  return dir;
}

function alphaAt(buffer: Buffer, width: number, x: number, y: number) {
  return buffer[(y * width + x) * 4 + 3];
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('generateDesktopIconAssets', () => {
  it('writes rounded desktop icon outputs for build and runtime usage', async () => {
    const { generateDesktopIconAssets } = await import('./generate-icons.mjs');

    const dir = await makeTempDir();
    const sourcePath = join(dir, 'logo.png');
    const buildOutputPath = join(dir, 'build.png');
    const webOutputPath = join(dir, 'desktop-icon.png');

    await sharp({
      create: {
        width: 512,
        height: 512,
        channels: 4,
        background: { r: 255, g: 112, b: 48, alpha: 1 },
      },
    }).png().toFile(sourcePath);

    await generateDesktopIconAssets({
      sourcePath,
      buildOutputPath,
      webOutputPath,
    });

    const buildMeta = await sharp(buildOutputPath).metadata();
    const webMeta = await sharp(webOutputPath).metadata();

    expect(buildMeta.width).toBe(512);
    expect(buildMeta.height).toBe(512);
    expect(webMeta.width).toBe(512);
    expect(webMeta.height).toBe(512);

    const { data, info } = await sharp(buildOutputPath)
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });

    expect(alphaAt(data, info.width, 0, 0)).toBe(0);
    expect(alphaAt(data, info.width, 12, 12)).toBe(0);
    expect(alphaAt(data, info.width, Math.floor(info.width / 2), 6)).toBe(0);
    expect(alphaAt(data, info.width, Math.floor(info.width / 2), Math.floor(info.height / 2))).toBe(255);

    expect(await sharp(buildOutputPath).png().toBuffer())
      .toEqual(await sharp(webOutputPath).png().toBuffer());
  });
});
