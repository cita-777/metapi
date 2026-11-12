import { createServer } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { alternatePasses, isLatencyRegression, median, runBench as measureBench } from './bench.mjs';

function listen(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{}');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((done, fail) => server.close((error) => (error ? fail(error) : done()))),
      });
    });
  });
}

function runBench(args: string[], env: NodeJS.ProcessEnv): Promise<{ status: number | null; output: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { env });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, output }));
  });
}

describe('latency bench', () => {
  it('takes the median and flags only when slower by more than 20% and more than 1ms', () => {
    expect(median([3, 1, 2])).toBe(2);
    expect(alternatePasses()).toEqual(['baseline', 'candidate', 'baseline']);
    expect(isLatencyRegression(12, 10)).toBe(false);
    expect(isLatencyRegression(11, 10)).toBe(false);
    expect(isLatencyRegression(11.1, 10)).toBe(false);
    expect(isLatencyRegression(13, 10)).toBe(true);
  });

  it('does not print AUTH_TOKEN', async () => {
    const server = await listen();
    const token = 'bench-token-should-not-appear';
    const out = join(mkdtempSync(join(tmpdir(), 'metapi-bench-')), 'out.json');
    try {
      const result = await runBench([
        new URL('./bench.mjs', import.meta.url).pathname,
        '--rounds', '1',
        '--n', '2',
        '--warmup', '0',
        '--concurrency', '1',
        '--out', out,
        server.url,
      ], { ...process.env, AUTH_TOKEN: token });
      expect(result.status, result.output).toBe(0);
      expect(result.output).not.toContain(token);
      expect(result.output).toContain('GET /');
      expect(JSON.parse(readFileSync(out, 'utf8'))['GET / c=1'].p50).toEqual(expect.any(Number));
    } finally {
      await server.close();
    }
  });

  it('rejects a non-loopback base and alternate before any fetch', async () => {
    const original = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      throw new Error('unexpected fetch');
    };
    const options = { rounds: 1, samples: 1, warmup: 0, concurrency: [1] };
    try {
      await expect(measureBench({ ...options, base: 'https://example.com' })).rejects.toThrow(/loopback --base/);
      await expect(measureBench({
        ...options,
        base: 'http://127.0.0.1:4100',
        alternate: 'https://example.com',
      })).rejects.toThrow(/loopback --alternate/);
      expect(calls).toBe(0);
    } finally {
      globalThis.fetch = original;
    }
  });
});
