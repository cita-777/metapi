// Register a staging-only site, account, and route refresh against a loopback mock upstream.
// This talks to a running staging server. It does not write a committed seed.
// AUTH_TOKEN is read from the environment and is never printed.
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1']);

export function assertLoopbackUpstream(upstream) {
  const url = new URL(upstream);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!LOOPBACK.has(host)) {
    throw new Error('staging helper only accepts a loopback mock upstream');
  }
  return url.origin;
}

export function siteBody(upstream, name) {
  return {
    name,
    url: assertLoopbackUpstream(upstream),
    platform: 'openai',
    status: 'active',
  };
}

export function accountBody(siteId) {
  return {
    siteId,
    username: 'staging-mock',
    accessToken: 'staging-mock-key',
    credentialMode: 'apikey',
    checkinEnabled: false,
  };
}

async function send(fetchImpl, base, token, method, path, body) {
  const response = await fetchImpl(`${base}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify(body),
  });
  const text = typeof response.text === 'function' ? await response.text() : '';
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (response.status >= 400) {
    throw new Error(`${method} ${path} returned ${response.status}`);
  }
  return payload;
}

export async function registerStagingUpstream({
  base,
  upstream,
  name = 'metapi-staging-mock',
  token = process.env.AUTH_TOKEN,
  fetchImpl = fetch,
}) {
  if (!token) throw new Error('AUTH_TOKEN is required');
  const site = await send(fetchImpl, base, token, 'POST', '/api/sites', siteBody(upstream, name));
  const siteId = Number(site?.id);
  if (!Number.isInteger(siteId) || siteId <= 0) {
    throw new Error('POST /api/sites did not return an id');
  }
  const account = await send(fetchImpl, base, token, 'POST', '/api/accounts', accountBody(siteId));
  const accountId = Number(account?.id);
  if (!Number.isInteger(accountId) || accountId <= 0) {
    throw new Error('POST /api/accounts did not return an id');
  }
  await send(fetchImpl, base, token, 'POST', '/api/routes/rebuild', { refreshModels: true, wait: true });
  return { siteId, accountId, name, upstream: assertLoopbackUpstream(upstream) };
}

function parseArgs(argv) {
  const options = { name: 'metapi-staging-mock', dryRun: false, base: '', upstream: '' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--base') options.base = argv[++index];
    else if (arg === '--upstream') options.upstream = argv[++index];
    else if (arg === '--name') options.name = argv[++index];
    else if (arg === '--dry-run') options.dryRun = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!options.upstream) throw new Error('--upstream is required');
  if (!options.dryRun && !options.base) throw new Error('--base is required');
  return options;
}

const isMain = process.argv[1]
  && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1]);

if (isMain) {
  Promise.resolve().then(async () => {
    const options = parseArgs(process.argv.slice(2));
    const site = siteBody(options.upstream, options.name);
    if (options.dryRun) {
      console.log(`POST /api/sites ${JSON.stringify(site)}`);
      console.log('POST /api/accounts after the site id is returned');
      console.log('POST /api/routes/rebuild {"refreshModels":true,"wait":true}');
      return;
    }
    const created = await registerStagingUpstream(options);
    console.log(`site=${created.siteId} account=${created.accountId} upstream=${created.upstream}`);
  }).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
