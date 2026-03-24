import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import { OpenAiAdapter } from './openai.js';
import { ClaudeAdapter } from './claude.js';
import { GeminiAdapter } from './gemini.js';
import { CliProxyApiAdapter } from './cliproxyapi.js';

interface RequestSnapshot {
  method: string;
  url: string;
  headers: IncomingMessage['headers'];
}

describe('official llm upstream adapters', () => {
  let server: ReturnType<typeof createServer>;
  let baseUrl: string;
  let requests: RequestSnapshot[] = [];

  beforeEach(async () => {
    requests = [];
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      requests.push({
        method: req.method || 'GET',
        url: req.url || '/',
        headers: req.headers,
      });

      if (req.url === '/openai/v1/models') {
        if (req.headers.authorization !== 'Bearer sk-openai') {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'unauthorized' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          object: 'list',
          data: [{ id: 'gpt-4.1' }, { id: 'gpt-4o-mini' }],
        }));
        return;
      }

      if (req.url === '/claude/v1/models') {
        if (req.headers['x-api-key'] !== 'sk-claude' || req.headers['anthropic-version'] !== '2023-06-01') {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'unauthorized' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          data: [{ id: 'claude-sonnet-4-5-20250929' }, { id: 'claude-haiku-4-5-20251001' }],
        }));
        return;
      }

      if (req.url === '/cliproxy/v1/models') {
        if (req.headers.authorization !== 'Bearer sk-cpa') {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'unauthorized' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          object: 'list',
          data: [{ id: 'gpt-5.4' }, { id: 'gpt-5.2-codex' }],
        }));
        return;
      }

      if (req.url?.startsWith('/gemini/v1beta/models')) {
        const url = new URL(req.url, 'http://127.0.0.1');
        if (url.searchParams.get('key') !== 'gemini-key') {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'unauthorized' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          models: [
            { name: 'models/gemini-2.5-flash' },
            { name: 'models/gemini-2.5-pro' },
          ],
        }));
        return;
      }

      if (req.url === '/gemini-openai/v1beta/openai/models') {
        if (req.headers.authorization !== 'Bearer gemini-key') {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'unauthorized' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          object: 'list',
          data: [{ id: 'gemini-2.5-flash' }],
        }));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err?: Error) => (err ? reject(err) : resolve()));
    });
  });

  it('fetches models from openai upstream', async () => {
    const adapter = new OpenAiAdapter();
    const models = await adapter.getModels(`${baseUrl}/openai`, 'sk-openai');
    expect(models).toEqual(['gpt-4.1', 'gpt-4o-mini']);
  });

  it('fetches models from claude upstream with anthropic headers', async () => {
    const adapter = new ClaudeAdapter();
    const models = await adapter.getModels(`${baseUrl}/claude`, 'sk-claude');
    expect(models).toEqual(['claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001']);
  });

  it('fetches models from cliproxy openai-compatible upstream', async () => {
    const adapter = new CliProxyApiAdapter();
    const models = await adapter.getModels(`${baseUrl}/cliproxy`, 'sk-cpa');
    expect(models).toEqual(['gpt-5.4', 'gpt-5.2-codex']);
  });

  it('fetches models from gemini native endpoint and normalizes model names', async () => {
    const adapter = new GeminiAdapter();
    const models = await adapter.getModels(`${baseUrl}/gemini/v1beta`, 'gemini-key');
    expect(models).toEqual(['gemini-2.5-flash', 'gemini-2.5-pro']);
  });

  it('fetches models from gemini openai-compatible endpoint when configured', async () => {
    const adapter = new GeminiAdapter();
    const models = await adapter.getModels(`${baseUrl}/gemini-openai/v1beta/openai`, 'gemini-key');
    expect(models).toEqual(['gemini-2.5-flash']);
  });
});
