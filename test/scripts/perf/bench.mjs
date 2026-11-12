// Several rounds, median, and an optional main -> candidate -> main alternation.
// AUTH_TOKEN is read from the environment and never printed.
// A latency regression is flagged only when a sample is slower by more than 20% and more than 1ms.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertLoopbackUrl } from '../loopback-url.mjs';

export function median(values) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

export function percentile(sorted, p) {
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
}

export function isLatencyRegression(current, baseline) {
  if (!Number.isFinite(current) || !Number.isFinite(baseline) || baseline <= 0) return false;
  const delta = current - baseline;
  return delta / baseline > 0.2 && delta > 1;
}

export function alternatePasses() {
  return ['baseline', 'candidate', 'baseline'];
}

function readOption(argv, name, fallback) {
  const index = argv.indexOf(name);
  if (index < 0) return fallback;
  const value = argv[index + 1];
  argv.splice(index, 2);
  return value;
}

export function parseBenchArgs(argv) {
  const args = [...argv];
  const rounds = Number(readOption(args, '--rounds', 3));
  const samples = Number(readOption(args, '--n', 200));
  const warmup = Number(readOption(args, '--warmup', 20));
  const out = readOption(args, '--out', '');
  const compare = readOption(args, '--compare', '');
  const alternate = readOption(args, '--alternate', '');
  const concurrency = String(readOption(args, '--concurrency', '1,10'))
    .split(',')
    .map((item) => Number(item.trim()))
    .filter((item) => Number.isInteger(item) && item > 0);
  const base = args[0] || 'http://127.0.0.1:4100';
  if (!Number.isInteger(rounds) || rounds < 1) throw new Error('--rounds must be a positive integer');
  if (!Number.isInteger(samples) || samples < 1) throw new Error('--n must be a positive integer');
  if (!Number.isInteger(warmup) || warmup < 0) throw new Error('--warmup must be a non-negative integer');
  if (concurrency.length === 0) throw new Error('--concurrency must list positive integers');
  return { rounds, samples, warmup, out, compare, alternate, concurrency, base };
}

function authHeaders() {
  const token = process.env.AUTH_TOKEN;
  if (!token) throw new Error('AUTH_TOKEN is required');
  return { Authorization: `Bearer ${token}` };
}

function targets() {
  return [
    ['GET /', '/', null],
    ['GET /api/sites', '/api/sites', 'admin'],
    ['GET /api/stats/dashboard', '/api/stats/dashboard', 'admin'],
  ];
}

export async function measureOnce(base, path, headers, { samples, warmup, concurrency }) {
  const requestHeaders = { ...headers, connection: 'close' };
  for (let index = 0; index < warmup; index += 1) {
    const response = await fetch(base + path, { headers: requestHeaders });
    await response.arrayBuffer();
  }
  const latencies = [];
  let bad = 0;
  let next = 0;
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (next < samples) {
      next += 1;
      const started = performance.now();
      const response = await fetch(base + path, { headers: requestHeaders });
      await response.arrayBuffer();
      if (response.status !== 200) bad += 1;
      latencies.push(performance.now() - started);
    }
  }));
  if (bad) throw new Error(`${path} returned ${bad} non-200 responses`);
  latencies.sort((left, right) => left - right);
  return { p50: percentile(latencies, 50), p95: percentile(latencies, 95) };
}

export function assertLoopbackBase(base) {
  assertLoopbackUrl(base, 'bench only accepts a loopback --base');
}

export async function measureBase(base, options) {
  assertLoopbackBase(base);
  const headersFor = (kind) => (kind === 'admin' ? authHeaders() : {});
  const result = {};
  for (const concurrency of options.concurrency) {
    for (const [name, path, kind] of targets()) {
      const rounds = [];
      for (let round = 0; round < options.rounds; round += 1) {
        rounds.push(await measureOnce(base, path, headersFor(kind), { ...options, concurrency }));
      }
      result[`${name} c=${concurrency}`] = {
        p50: Number(median(rounds.map((item) => item.p50)).toFixed(2)),
        p95: Number(median(rounds.map((item) => item.p95)).toFixed(2)),
        rounds: rounds.map((item) => [Number(item.p50.toFixed(2)), Number(item.p95.toFixed(2))]),
      };
    }
  }
  return result;
}

export function compareResults(current, baseline) {
  const lines = [];
  let flagged = 0;
  for (const [key, value] of Object.entries(current)) {
    let line = `${key}: p50=${value.p50}ms p95=${value.p95}ms`;
    const base = baseline?.[key];
    if (base) {
      for (const metric of ['p50', 'p95']) {
        if (!isLatencyRegression(value[metric], base[metric])) continue;
        flagged += 1;
        const delta = value[metric] - base[metric];
        const ratio = (delta / base[metric]) * 100;
        line += ` [regression ${metric} +${ratio.toFixed(0)}% / +${delta.toFixed(2)}ms]`;
      }
    }
    lines.push(line);
  }
  return { lines, flagged };
}

function medianBaseline(passes) {
  const keys = new Set(passes.flatMap((pass) => Object.keys(pass)));
  const combined = {};
  for (const key of keys) {
    combined[key] = {
      p50: Number(median(passes.map((pass) => pass[key].p50)).toFixed(2)),
      p95: Number(median(passes.map((pass) => pass[key].p95)).toFixed(2)),
    };
  }
  return combined;
}

export async function runBench(options) {
  assertLoopbackBase(options.base);
  if (options.alternate) {
    assertLoopbackUrl(options.alternate, 'bench only accepts a loopback --alternate');
  }
  if (!options.alternate) {
    const current = await measureBase(options.base, options);
    const baseline = options.compare ? JSON.parse(readFileSync(options.compare, 'utf8')) : null;
    return { current, baseline, passes: ['candidate'] };
  }
  const measured = [];
  for (const role of alternatePasses()) {
    const url = role === 'baseline' ? options.alternate : options.base;
    measured.push({ role, result: await measureBase(url, options) });
  }
  const baselinePasses = measured.filter((item) => item.role === 'baseline').map((item) => item.result);
  return {
    current: measured.find((item) => item.role === 'candidate').result,
    baseline: medianBaseline(baselinePasses),
    passes: measured.map((item) => item.role),
  };
}

function printReport(comparison, { compared }) {
  for (const line of comparison.lines) console.log(line);
  if (!compared) return 0;
  if (comparison.flagged) {
    console.log(`flagged ${comparison.flagged} (slower by more than 20% and more than 1ms)`);
    return 2;
  }
  console.log('no regression over the threshold (more than 20% and more than 1ms)');
  return 0;
}

const isMain = process.argv[1]
  && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1]);

if (isMain) {
  Promise.resolve().then(async () => {
    const options = parseBenchArgs(process.argv.slice(2));
    const outcome = await runBench(options);
    if (options.out) writeFileSync(options.out, JSON.stringify(outcome.current, null, 2));
    if (options.alternate) console.log(`passes: ${outcome.passes.join(' -> ')}`);
    const comparison = compareResults(outcome.current, outcome.baseline);
    process.exitCode = printReport(comparison, { compared: Boolean(outcome.baseline) });
  }).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
