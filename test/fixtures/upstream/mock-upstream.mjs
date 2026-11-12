// Loopback OpenAI-compatible upstream for staging proxy, stream, and billing drills.
// Bind address is loopback so it can also run inside a netns. It does not call the network.
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

export const MOCK_MODEL = 'mock-chat';

export function chatCompletionBody() {
  return {
    id: 'chatcmpl-mock',
    object: 'chat.completion',
    choices: [
      {
        index: 0,
        message: { role: 'assistant', content: 'ok' },
        finish_reason: 'stop',
      },
    ],
    usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
  };
}

export function chatStreamChunks() {
  return [
    'data: {"id":"chatcmpl-mock","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"ok"}}]}\n\n',
    'data: {"id":"chatcmpl-mock","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}\n\n',
    'data: [DONE]\n\n',
  ].join('');
}

function readBody(request) {
  return new Promise((resolveBody, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => resolveBody(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });
}

export function startMockUpstream({ host = '127.0.0.1', port = 0 } = {}) {
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error('mock upstream only binds to loopback');
  }

  const server = createServer(async (request, response) => {
    const url = new URL(request.url || '/', 'http://127.0.0.1');
    const path = url.pathname;

    if (request.method === 'GET' && path === '/healthz') {
      response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify({ ok: true }));
      return;
    }

    if (request.method === 'GET' && (path === '/v1/models' || path === '/models')) {
      response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify({
        object: 'list',
        data: [{ id: MOCK_MODEL, object: 'model' }],
      }));
      return;
    }

    if (request.method === 'POST' && (path === '/v1/chat/completions' || path === '/chat/completions')) {
      const raw = await readBody(request);
      let stream = false;
      try {
        stream = JSON.parse(raw || '{}').stream === true;
      } catch {
        stream = false;
      }
      if (stream) {
        response.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' });
        response.end(chatStreamChunks());
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify(chatCompletionBody()));
      return;
    }

    response.writeHead(404, { 'content-type': 'application/json; charset=utf-8' });
    response.end(JSON.stringify({ error: 'not found' }));
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
  startMockUpstream({ port }).then((started) => {
    console.log(started.url);
  }).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
