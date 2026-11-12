import { describe, expect, it } from 'vitest';
import { MOCK_MODEL, startMockUpstream } from './mock-upstream.mjs';

describe('mock upstream', () => {
  it('answers models, a chat completion, and a stream on loopback', async () => {
    const server = await startMockUpstream();
    expect(server.host).toBe('127.0.0.1');
    try {
      const models = await fetch(`${server.url}/v1/models`);
      expect(models.status).toBe(200);
      expect(await models.json()).toMatchObject({ data: [{ id: MOCK_MODEL }] });

      const chat = await fetch(`${server.url}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: MOCK_MODEL, messages: [{ role: 'user', content: 'ping' }] }),
      });
      expect(chat.status).toBe(200);
      const completion = await chat.json();
      expect(completion.choices[0].message.content).toBe('ok');
      expect(completion.usage.total_tokens).toBe(4);

      const stream = await fetch(`${server.url}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: MOCK_MODEL, stream: true, messages: [{ role: 'user', content: 'ping' }] }),
      });
      expect(stream.status).toBe(200);
      expect(stream.headers.get('content-type')).toContain('text/event-stream');
      const body = await stream.text();
      expect(body).toContain('data:');
      expect(body).toContain('total_tokens');
    } finally {
      await server.close();
    }
  });

  it('refuses a non-loopback bind', async () => {
    expect(() => startMockUpstream({ host: '0.0.0.0' })).toThrow(/loopback/);
  });
});
