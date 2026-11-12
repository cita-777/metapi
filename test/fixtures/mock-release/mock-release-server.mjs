// Test double for a release download origin. It binds to loopback only.
// Production code has no setting that points at this server.
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const PACKAGE_NAME = 'metapi-server.tar';

export const SCENARIOS = [
  'normal',
  'swapped',
  'tar-parent',
  'tar-symlink',
  'checksum-missing',
  'checksum-duplicate',
  'older-as-newer',
];

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function putString(header, offset, length, value) {
  header.write(String(value), offset, length, 'utf8');
}

function putOctal(header, offset, length, value) {
  const text = Number(value).toString(8).padStart(length - 1, '0');
  if (text.length > length - 1) {
    throw new Error('tar header field is too large');
  }
  header.write(text, offset, length - 1, 'ascii');
  header[offset + length - 1] = 0;
}

function readCString(header, offset, length) {
  const slice = header.subarray(offset, offset + length);
  const end = slice.indexOf(0);
  const bytes = end === -1 ? slice : slice.subarray(0, end);
  return bytes.toString('utf8').replace(/\0+$/g, '').trim();
}

function ustarHeader(entry) {
  const header = Buffer.alloc(512);
  const name = entry.name;
  if (Buffer.byteLength(name) > 100) {
    throw new Error(`tar entry name is too long: ${name}`);
  }
  putString(header, 0, 100, name);
  putOctal(header, 100, 8, 0o644);
  putOctal(header, 108, 8, 0);
  putOctal(header, 116, 8, 0);
  putOctal(header, 124, 12, entry.size);
  putOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = entry.typeflag;
  if (entry.linkname) putString(header, 157, 100, entry.linkname);
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  putString(header, 265, 32, 'metapi');
  putString(header, 297, 32, 'metapi');
  let sum = 0;
  for (const byte of header) sum += byte;
  const checksum = sum.toString(8).padStart(6, '0');
  header.write(checksum, 148, 6, 'ascii');
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

export function createTar(entries) {
  const chunks = [];
  for (const entry of entries) {
    const typeflag = entry.type === 'symlink' ? 50 : 48;
    const content = entry.type === 'symlink' ? Buffer.alloc(0) : Buffer.from(entry.content ?? '');
    chunks.push(ustarHeader({
      name: entry.name,
      size: content.length,
      typeflag,
      linkname: entry.linkname || '',
    }));
    if (content.length > 0) {
      chunks.push(content);
      const padding = (512 - (content.length % 512)) % 512;
      if (padding > 0) chunks.push(Buffer.alloc(padding));
    }
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

export function listTarEntries(buffer) {
  const entries = [];
  let offset = 0;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = readCString(header, 0, 100);
    const prefix = readCString(header, 345, 155);
    const sizeText = readCString(header, 124, 12).trim();
    const size = sizeText ? Number.parseInt(sizeText, 8) : 0;
    const typeflag = String.fromCharCode(header[156] || 48);
    const linkname = readCString(header, 157, 100);
    offset += 512;
    const content = Buffer.from(buffer.subarray(offset, offset + size));
    offset += Math.ceil(size / 512) * 512;
    entries.push({
      name: prefix ? `${prefix}/${name}` : name,
      typeflag,
      linkname,
      content,
    });
  }
  return entries;
}

function releaseManifest(version) {
  return Buffer.from(`${JSON.stringify({
    schemaVersion: 1,
    version,
    files: [PACKAGE_NAME],
  }, null, 2)}\n`);
}

function checksumLine(hash, name) {
  return `${hash}  ${name}\n`;
}

function packageEntries(version, extra = []) {
  return [
    { name: 'server.js', type: 'file', content: `console.log(${JSON.stringify(version)});\n` },
    { name: 'release.json', type: 'file', content: releaseManifest(version) },
    ...extra,
  ];
}

function scenarioAssets(scenario) {
  if (scenario === 'normal') {
    const version = '1.4.0';
    const tar = createTar(packageEntries(version));
    const manifest = releaseManifest(version);
    const checksums = Buffer.from(
      checksumLine(sha256(tar), PACKAGE_NAME) + checksumLine(sha256(manifest), 'release.json'),
    );
    return { advertisedVersion: version, manifestVersion: version, tar, manifest, checksums };
  }

  if (scenario === 'swapped') {
    const version = '1.4.0';
    const original = createTar(packageEntries(version));
    const manifest = releaseManifest(version);
    const checksums = Buffer.from(
      checksumLine(sha256(original), PACKAGE_NAME) + checksumLine(sha256(manifest), 'release.json'),
    );
    const tar = Buffer.from(original);
    tar[tar.length - 1] ^= 0xff;
    return { advertisedVersion: version, manifestVersion: version, tar, manifest, checksums };
  }

  if (scenario === 'tar-parent') {
    const version = '1.4.0';
    const tar = createTar(packageEntries(version, [
      { name: '../outside.txt', type: 'file', content: 'outside\n' },
    ]));
    const manifest = releaseManifest(version);
    const checksums = Buffer.from(checksumLine(sha256(tar), PACKAGE_NAME));
    return { advertisedVersion: version, manifestVersion: version, tar, manifest, checksums };
  }

  if (scenario === 'tar-symlink') {
    const version = '1.4.0';
    const tar = createTar(packageEntries(version, [
      { name: 'linked.txt', type: 'symlink', linkname: '../outside.txt' },
    ]));
    const manifest = releaseManifest(version);
    const checksums = Buffer.from(checksumLine(sha256(tar), PACKAGE_NAME));
    return { advertisedVersion: version, manifestVersion: version, tar, manifest, checksums };
  }

  if (scenario === 'checksum-missing') {
    const version = '1.4.0';
    const tar = createTar(packageEntries(version));
    const manifest = releaseManifest(version);
    const checksums = Buffer.from(checksumLine(sha256(manifest), 'release.json'));
    return { advertisedVersion: version, manifestVersion: version, tar, manifest, checksums };
  }

  if (scenario === 'checksum-duplicate') {
    const version = '1.4.0';
    const tar = createTar(packageEntries(version));
    const manifest = releaseManifest(version);
    const realHash = sha256(tar);
    const otherHash = realHash.replace(/^./, realHash.startsWith('a') ? 'b' : 'a');
    const checksums = Buffer.from(
      checksumLine(realHash, PACKAGE_NAME) + checksumLine(otherHash, PACKAGE_NAME),
    );
    return { advertisedVersion: version, manifestVersion: version, tar, manifest, checksums };
  }

  if (scenario === 'older-as-newer') {
    const manifestVersion = '1.0.0';
    const advertisedVersion = '2.0.0';
    const tar = createTar(packageEntries(manifestVersion));
    const manifest = releaseManifest(manifestVersion);
    const checksums = Buffer.from(
      checksumLine(sha256(tar), PACKAGE_NAME) + checksumLine(sha256(manifest), 'release.json'),
    );
    return { advertisedVersion, manifestVersion, tar, manifest, checksums };
  }

  return null;
}

export function buildScenario(scenario) {
  const assets = scenarioAssets(scenario);
  if (!assets) {
    throw new Error(`unknown release fixture scenario: ${scenario}`);
  }
  return assets;
}

function assetBody(assets, name) {
  if (name === PACKAGE_NAME) return { body: assets.tar, type: 'application/octet-stream' };
  if (name === 'checksums.txt') return { body: assets.checksums, type: 'text/plain; charset=utf-8' };
  if (name === 'release.json') return { body: assets.manifest, type: 'application/json; charset=utf-8' };
  return null;
}

export function startMockReleaseServer({ host = '127.0.0.1', port = 0 } = {}) {
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error('mock release server only binds to loopback');
  }

  const server = createServer((request, response) => {
    const url = new URL(request.url || '/', 'http://127.0.0.1');
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.writeHead(405).end();
      return;
    }
    if (url.pathname === '/fixture') {
      const body = Buffer.from(JSON.stringify({ scenarios: SCENARIOS }));
      response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      response.end(request.method === 'HEAD' ? undefined : body);
      return;
    }

    const match = url.pathname.match(/^\/fixture\/([^/]+)\/([^/]+)$/);
    if (!match) {
      response.writeHead(404).end();
      return;
    }
    const assets = scenarioAssets(decodeURIComponent(match[1]));
    const asset = assets && assetBody(assets, decodeURIComponent(match[2]));
    if (!asset) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, {
      'content-type': asset.type,
      'content-length': asset.body.length,
    });
    response.end(request.method === 'HEAD' ? undefined : asset.body);
  });

  return new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const address = server.address();
      const boundPort = typeof address === 'object' && address ? address.port : port;
      resolveListen({
        host,
        port: boundPort,
        url: `http://127.0.0.1:${boundPort}`,
        close: () => new Promise((done, fail) => {
          server.close((error) => (error ? fail(error) : done()));
        }),
      });
    });
  });
}

const isMain = process.argv[1]
  && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1]);

if (isMain) {
  const portFlag = process.argv.indexOf('--port');
  const port = portFlag >= 0 ? Number(process.argv[portFlag + 1]) : 0;
  startMockReleaseServer({ port }).then((started) => {
    console.log(started.url);
  }).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
