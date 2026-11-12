import { createServer } from 'node:http';
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { describe, expect, it } from 'vitest';

function run(command: string, args: string[], env: NodeJS.ProcessEnv): Promise<{ status: number | null; output: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.on('error', reject);
    child.on('close', (status) => resolve({ status, output }));
  });
}

describe('startup measurement', () => {
  it('takes three samples, reports the median, and does not print AUTH_TOKEN', async () => {
    const server = createServer((_request, response) => {
      response.writeHead(200).end('ok');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    const holder = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)']);
    const staging = mkdtempSync(join(tmpdir(), 'metapi-startup-'));
    const token = 'startup-token-should-not-appear';
    mkdirSync(join(staging, 'run'));
    writeFileSync(join(staging, '.env'), `AUTH_TOKEN=${token}\n`);
    writeFileSync(join(staging, 'count'), '0');
    writeFileSync(join(staging, 'stop.sh'), '#!/bin/sh\nexit 0\n');
    writeFileSync(join(staging, 'start.sh'), `#!/bin/sh
n=$(cat count)
n=$((n + 1))
echo "$n" > count
case "$n" in
  1) echo "约 100ms" ;;
  2) echo "约 300ms" ;;
  *) echo "约 200ms" ;;
esac
echo "$METAPI_TEST_PID" > run/app.pid
`);
    chmodSync(join(staging, 'stop.sh'), 0o755);
    chmodSync(join(staging, 'start.sh'), 0o755);
    try {
      const result = await run('bash', [
        new URL('./startup.sh', import.meta.url).pathname,
        '--staging-dir', staging,
        '--base', `http://127.0.0.1:${port}`,
        '--rounds', '3',
      ], {
        ...process.env,
        METAPI_STARTUP_SETTLE_SEC: '0',
        METAPI_BENCH_N: '1',
        METAPI_BENCH_CONCURRENCY: '1',
        METAPI_TEST_PID: String(holder.pid),
        AUTH_TOKEN: token,
      });
      expect(result.status, result.output).toBe(0);
      expect(result.output).toContain('median startup=200ms');
      expect(result.output).not.toContain(token);
    } finally {
      holder.kill();
      await new Promise((done, fail) => server.close((error) => (error ? fail(error) : done(undefined))));
    }
  }, 20000);
});
