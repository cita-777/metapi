import { describe, expect, it } from 'vitest';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { type AddressInfo } from 'node:net';
import { detectPlatform, getAdapter } from './index.js';

async function withHttpServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
  run: (baseUrl: string) => Promise<void>,
) {
  // Avoid flakiness: CPA uses port 8317 by convention, and our platform detection
  // includes a fast-path for localhost:8317. Random ephemeral ports can collide.
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const server = createServer(handler);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });

    const { port } = server.address() as AddressInfo;
    if (port === 8317) {
      await new Promise<void>((resolve, reject) => {
        server.close((err?: Error) => (err ? reject(err) : resolve()));
      });
      continue;
    }

    const baseUrl = `http://127.0.0.1:${port}`;
    try {
      await run(baseUrl);
      return;
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err?: Error) => (err ? reject(err) : resolve()));
      });
    }
  }

  throw new Error('withHttpServer: unable to allocate a test port that avoids 8317');
}

describe('getAdapter platform aliases', () => {
  it('returns dedicated anyrouter adapter for anyrouter alias', () => {
    const adapter = getAdapter('anyrouter');
    expect(adapter?.platformName).toBe('anyrouter');
  });

  it('handles case-insensitive platform strings', () => {
    const adapter = getAdapter('Veloera');
    expect(adapter?.platformName).toBe('veloera');
  });

  it('returns undefined for unknown platforms', () => {
    expect(getAdapter('unknown-platform')).toBeUndefined();
  });

  it('supports canonical openai/claude/gemini adapters', () => {
    expect(getAdapter('openai')?.platformName).toBe('openai');
    expect(getAdapter('claude')?.platformName).toBe('claude');
    expect(getAdapter('gemini')?.platformName).toBe('gemini');
  });

  it('supports dedicated codex adapter and aliases', () => {
    expect(getAdapter('codex')?.platformName).toBe('codex');
    expect(getAdapter('chatgpt-codex')?.platformName).toBe('codex');
  });

  it('detects anyrouter URL before generic new-api adapter', async () => {
    const adapter = await detectPlatform('https://anyrouter.top');
    expect(adapter?.platformName).toBe('anyrouter');
  });

  it('detects done-hub URL before generic adapters', async () => {
    const adapter = await detectPlatform('https://demo.donehub.example');
    expect(adapter?.platformName).toBe('done-hub');
  });

  it('detects official openai/claude/gemini upstream URLs', async () => {
    const openai = await detectPlatform('https://api.openai.com');
    const claude = await detectPlatform('https://api.anthropic.com');
    const gemini = await detectPlatform('https://generativelanguage.googleapis.com');

    expect(openai?.platformName).toBe('openai');
    expect(claude?.platformName).toBe('claude');
    expect(gemini?.platformName).toBe('gemini');
  });

  it('detects one-hub by title under custom domain before generic new-api', async () => {
    await withHttpServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><head><title>One-Hub Console</title></head><body></body></html>');
        return;
      }
      if (req.url === '/api/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          data: { system_name: 'New API' },
        }));
        return;
      }
      res.writeHead(404).end();
    }, async (baseUrl) => {
      const adapter = await detectPlatform(baseUrl);
      expect(adapter?.platformName).toBe('one-hub');
    });
  });

  it('detects done-hub by title under custom domain', async () => {
    await withHttpServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><head><title>Done-Hub Panel</title></head><body></body></html>');
        return;
      }
      res.writeHead(404).end();
    }, async (baseUrl) => {
      const adapter = await detectPlatform(baseUrl);
      expect(adapter?.platformName).toBe('done-hub');
    });
  });

  it('detects veloera by title under custom domain before generic new-api', async () => {
    await withHttpServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><head><title>Veloera 管理台</title></head><body></body></html>');
        return;
      }
      if (req.url === '/api/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          data: { system_name: 'new-api fork' },
        }));
        return;
      }
      res.writeHead(404).end();
    }, async (baseUrl) => {
      const adapter = await detectPlatform(baseUrl);
      expect(adapter?.platformName).toBe('veloera');
    });
  });

  it('falls back to new-api by title when api/status is unavailable', async () => {
    await withHttpServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><head><title>Super-API Dashboard</title></head><body></body></html>');
        return;
      }
      res.writeHead(404).end();
    }, async (baseUrl) => {
      const adapter = await detectPlatform(baseUrl);
      expect(adapter?.platformName).toBe('new-api');
    });
  });
});
