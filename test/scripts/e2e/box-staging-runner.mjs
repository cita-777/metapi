// Box-staging e2e runner. Filter with --tag so one PR can run its subset.
// The original Windows 50-case list is not in this repository; pass --cases when that file is available.
// Tokens are read from AUTH_TOKEN and PROXY_TOKEN and are never printed.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_CASES = fileURLToPath(new URL('../../fixtures/e2e/cases.json', import.meta.url));

export function loadCases(file) {
  const parsed = JSON.parse(readFileSync(file, 'utf8'));
  if (!Array.isArray(parsed.cases)) throw new Error('case file is missing a cases array');
  return parsed;
}

export function selectCases(cases, tags) {
  if (!tags.length) return cases;
  const wanted = new Set(tags);
  return cases.filter((item) => (item.tags || []).some((tag) => wanted.has(tag)));
}

function stepsOf(testCase) {
  if (Array.isArray(testCase.steps) && testCase.steps.length > 0) return testCase.steps;
  return [testCase];
}

function tokenFor(auth, env) {
  if (auth === 'admin') {
    if (!env.AUTH_TOKEN) throw new Error('AUTH_TOKEN is required');
    return env.AUTH_TOKEN;
  }
  if (auth === 'proxy') {
    if (!env.PROXY_TOKEN) throw new Error('PROXY_TOKEN is required');
    return env.PROXY_TOKEN;
  }
  return '';
}

function checkResponse(response, expectSpec) {
  if (!expectSpec) return null;
  if (expectSpec.status != null && response.status !== expectSpec.status) {
    return `status ${response.status}`;
  }
  if (expectSpec.bodyIncludes && !response.text.includes(expectSpec.bodyIncludes)) {
    return 'response body did not include the expected text';
  }
  return null;
}

export async function executeCases(cases, { base, env = process.env, fetchImpl = fetch } = {}) {
  const results = [];
  for (const testCase of cases) {
    const result = { id: testCase.id, ok: true, detail: '' };
    try {
      for (const step of stepsOf(testCase)) {
        const headers = { accept: '*/*' };
        const token = tokenFor(step.auth || 'none', env);
        if (token) headers.authorization = `Bearer ${token}`;
        let body;
        if (step.body !== undefined) {
          headers['content-type'] = 'application/json';
          body = JSON.stringify(step.body);
        }
        const response = await fetchImpl(`${base}${step.path}`, {
          method: step.method || 'GET',
          headers,
          body,
        });
        const text = typeof response.text === 'function'
          ? await response.text()
          : String(response.body ?? '');
        const failure = checkResponse({ status: response.status, text }, step.expect);
        if (failure) {
          result.ok = false;
          result.detail = failure;
          break;
        }
      }
    } catch (error) {
      result.ok = false;
      result.detail = error instanceof Error ? error.message : String(error);
    }
    results.push(result);
  }
  return results;
}

function parseArgs(argv) {
  const options = {
    cases: DEFAULT_CASES,
    tags: [],
    base: '',
    list: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--cases') options.cases = resolve(argv[++index]);
    else if (arg === '--base') options.base = argv[++index];
    else if (arg === '--list') options.list = true;
    else if (arg === '--tag') {
      for (const tag of String(argv[++index] || '').split(',')) {
        if (tag.trim()) options.tags.push(tag.trim());
      }
    } else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

function formatList(cases) {
  return cases.map((item) => `${item.id}\t${(item.tags || []).join(',')}\t${item.title || ''}`).join('\n');
}

const isMain = process.argv[1]
  && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1]);

if (isMain) {
  Promise.resolve().then(async () => {
    const options = parseArgs(process.argv.slice(2));
    const catalog = loadCases(options.cases);
    const selected = selectCases(catalog.cases, options.tags);
    if (options.list || !options.base) {
      console.log(formatList(selected));
      console.log(`${selected.length} case(s)`);
      return;
    }
    const results = await executeCases(selected, { base: options.base });
    for (const result of results) {
      console.log(`${result.ok ? 'PASS' : 'FAIL'} ${result.id}${result.detail ? ` ${result.detail}` : ''}`);
    }
    process.exitCode = results.every((result) => result.ok) ? 0 : 1;
  }).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
