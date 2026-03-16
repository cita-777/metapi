import { mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import sharp from 'sharp';

export const DESKTOP_ICON_SIZE = 512;
export const DESKTOP_ICON_PADDING = 40;
export const DESKTOP_ICON_RADIUS = 96;

function createRoundedMask(size, cornerRadius) {
  return Buffer.from(
    `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg"><rect width="${size}" height="${size}" rx="${cornerRadius}" ry="${cornerRadius}" fill="#fff"/></svg>`,
  );
}

async function renderDesktopIconBuffer({
  sourcePath,
  size = DESKTOP_ICON_SIZE,
  padding = DESKTOP_ICON_PADDING,
  cornerRadius = DESKTOP_ICON_RADIUS,
}) {
  const innerSize = size - padding * 2;
  const roundedMask = createRoundedMask(innerSize, Math.min(cornerRadius, Math.floor(innerSize / 2)));

  const roundedInner = await sharp(sourcePath)
    .resize(innerSize, innerSize, {
      fit: 'contain',
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    })
    .composite([{ input: roundedMask, blend: 'dest-in' }])
    .png()
    .toBuffer();

  return sharp({
    create: {
      width: size,
      height: size,
      channels: 4,
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    },
  })
    .composite([{ input: roundedInner, left: padding, top: padding }])
    .png()
    .toBuffer();
}

export async function generateDesktopIconAssets({
  sourcePath = join(process.cwd(), 'src', 'web', 'public', 'logo.png'),
  buildOutputPath = join(process.cwd(), 'build', 'desktop-icon.png'),
  webOutputPath = join(process.cwd(), 'src', 'web', 'public', 'desktop-icon.png'),
  size = DESKTOP_ICON_SIZE,
  padding = DESKTOP_ICON_PADDING,
  cornerRadius = DESKTOP_ICON_RADIUS,
} = {}) {
  const outputBuffer = await renderDesktopIconBuffer({
    sourcePath,
    size,
    padding,
    cornerRadius,
  });

  await Promise.all([
    mkdir(dirname(buildOutputPath), { recursive: true }),
    mkdir(dirname(webOutputPath), { recursive: true }),
  ]);

  await Promise.all([
    sharp(outputBuffer).toFile(buildOutputPath),
    sharp(outputBuffer).toFile(webOutputPath),
  ]);

  return {
    buildOutputPath,
    webOutputPath,
  };
}

const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isDirectRun) {
  const outputs = await generateDesktopIconAssets();
  console.log(`[metapi-desktop] Generated desktop icons:
- ${outputs.buildOutputPath}
- ${outputs.webOutputPath}`);
}
