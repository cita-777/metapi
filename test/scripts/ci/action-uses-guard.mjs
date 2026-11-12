// .github/workflows/*.yml must use 40-character action SHAs, except local ./ actions.
// Main still has floating tags, so the default mode warns and exits 0.
// The release.yml pin PR should set METAPI_ENFORCE_ACTION_SHA=1. After that, floating tags fail.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const USES_LINE = /^\s*(?:-\s*)?uses:\s*['"]?([^'"#\s]+)/;
const SHA_USES = /@([0-9a-fA-F]{40})$/;

export function parseUsesValues(source) {
  const values = [];
  const lines = String(source).replaceAll('\r\n', '\n').split('\n');
  for (const line of lines) {
    if (/^\s*#/.test(line)) continue;
    const match = line.match(USES_LINE);
    if (match) values.push(match[1]);
  }
  return values;
}

export function classifyUses(value) {
  if (value.startsWith('./')) return 'local';
  if (SHA_USES.test(value)) return 'sha';
  return 'floating';
}

export function collectWorkflowUses(root) {
  const workflowDir = join(root, '.github', 'workflows');
  let names = [];
  try {
    names = readdirSync(workflowDir).filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'));
  } catch {
    return [];
  }
  const found = [];
  for (const name of names.sort()) {
    const relative = join('.github', 'workflows', name);
    const fullPath = join(workflowDir, name);
    if (!statSync(fullPath).isFile()) continue;
    const source = readFileSync(fullPath, 'utf8');
    for (const value of parseUsesValues(source)) {
      found.push({ file: relative.replaceAll('\\', '/'), value, kind: classifyUses(value) });
    }
  }
  return found;
}

export function evaluateActionUses({ root = process.cwd(), enforce = false } = {}) {
  const uses = collectWorkflowUses(resolve(root));
  const floating = uses.filter((item) => item.kind === 'floating');
  return {
    uses,
    floating,
    enforce,
    exitCode: enforce && floating.length > 0 ? 1 : 0,
  };
}

export function formatActionUsesReport(result) {
  const lines = [];
  if (result.enforce) {
    lines.push(result.floating.length === 0
      ? 'action uses check: all uses are 40-character SHAs or local ./ actions'
      : 'action uses check: floating tags are not allowed');
  } else if (result.floating.length === 0) {
    lines.push('action uses check: all uses are 40-character SHAs or local ./ actions');
  } else {
    lines.push('action uses check: warn (main still has floating tags; this check fails the build only after the release.yml pin PR sets METAPI_ENFORCE_ACTION_SHA=1)');
  }
  for (const item of result.floating) {
    lines.push(`- ${item.file} ${item.value}`);
  }
  return lines.join('\n');
}

function parseArgs(argv) {
  const options = { root: process.cwd(), enforce: process.env.METAPI_ENFORCE_ACTION_SHA === '1' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--root') options.root = resolve(argv[++index]);
    else if (arg === '--enforce') options.enforce = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return options;
}

const isMain = process.argv[1]
  && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1]);

if (isMain) {
  try {
    const options = parseArgs(process.argv.slice(2));
    const result = evaluateActionUses(options);
    console.log(formatActionUsesReport(result));
    process.exitCode = result.exitCode;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
