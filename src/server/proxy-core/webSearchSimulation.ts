import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { anthropicMessagesTransformer } from '../transformers/anthropic/messages/index.js';
import {
  extractResponsesWebSearchQuery,
  hasResponsesWebSearchOnlyRequest,
} from './responsesPreflight.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

const SEARCH_SIMULATION_MODEL = '__search';

function findSearchTool(body: Record<string, unknown>): Record<string, unknown> | null {
  const tools = Array.isArray(body.tools) ? body.tools : [];
  for (const tool of tools) {
    if (!isRecord(tool)) continue;
    const type = asTrimmedString(tool.type).toLowerCase();
    const name = asTrimmedString(tool.name).toLowerCase();
    if (
      type === 'web_search'
      || type === 'web_search_preview'
      || type === 'web_search_preview_2025_03_11'
      || type === 'web_search_20250305'
      || type === 'google_search'
      || name === 'web_search'
      || name === 'google_search'
    ) {
      return tool;
    }
  }
  return null;
}

function toSearchMaxResults(tool: Record<string, unknown> | null): number {
  const raw = tool?.max_uses ?? tool?.max_results ?? tool?.maxResults;
  if (typeof raw !== 'number' || !Number.isFinite(raw)) return 10;
  return Math.max(1, Math.min(20, Math.trunc(raw)));
}

function buildSearchInjectHeaders(request: FastifyRequest): Record<string, string | string[]> {
  const headers: Record<string, string | string[]> = {};
  for (const [rawKey, rawValue] of Object.entries(request.headers as Record<string, string | string[]>)) {
    const key = rawKey.toLowerCase();
    if (
      key === 'host'
      || key === 'content-length'
      || key === 'content-type'
      || key === 'connection'
      || key === 'transfer-encoding'
    ) {
      continue;
    }
    if (rawValue === undefined) continue;
    headers[rawKey] = rawValue;
  }
  return headers;
}

function extractAnthropicSearchQuery(body: Record<string, unknown>): string {
  const messages = Array.isArray(body.messages) ? body.messages : [];
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (!isRecord(message)) continue;
    if (asTrimmedString(message.role).toLowerCase() !== 'user') continue;
    const content = message.content;
    if (typeof content === 'string' && content.trim()) return content.trim();
    if (!Array.isArray(content)) continue;
    const parts = content
      .map((item) => {
        if (typeof item === 'string') return item.trim();
        if (!isRecord(item)) return '';
        const type = asTrimmedString(item.type).toLowerCase();
        if (type && type !== 'text' && type !== 'input_text') return '';
        return asTrimmedString(item.text ?? item.content);
      })
      .filter((item) => item.length > 0);
    if (parts.length > 0) return parts.join('\n');
  }
  return '';
}

async function callLocalSearchRoute(input: {
  app: FastifyInstance;
  request: FastifyRequest;
  query: string;
  model: string;
  maxResults: number;
}): Promise<{ statusCode: number; payload: unknown }> {
  const searchResponse = await input.app.inject({
    method: 'POST',
    url: '/v1/search',
    headers: buildSearchInjectHeaders(input.request),
    payload: {
      model: input.model,
      query: input.query,
      max_results: input.maxResults,
    },
  });

  let payload: unknown = null;
  try {
    payload = JSON.parse(searchResponse.body);
  } catch {
    payload = searchResponse.body;
  }

  return {
    statusCode: searchResponse.statusCode,
    payload,
  };
}

function normalizeSearchResults(payload: unknown): unknown[] {
  if (!isRecord(payload)) return [];
  const data = Array.isArray(payload.data) ? payload.data : [];
  const results = Array.isArray(payload.results) ? payload.results : [];
  return data.length > 0 ? data : results;
}

function buildSyntheticResponsesPayload(input: {
  body: Record<string, unknown>;
  query: string;
  searchPayload: unknown;
}) {
  const createdAt = Math.floor(Date.now() / 1000);
  const responseId = `resp_web_search_${randomUUID()}`;
  const searchCallId = `ws_${randomUUID()}`;
  const results = normalizeSearchResults(input.searchPayload);
  const outputText = results.length > 0 ? JSON.stringify(results) : '[]';

  return {
    id: responseId,
    object: 'response',
    created_at: createdAt,
    model: asTrimmedString(input.body.model) || 'unknown',
    status: 'completed',
    output_text: outputText,
    output: [
      {
        id: searchCallId,
        type: 'web_search_call',
        status: 'completed',
        action: {
          type: 'search',
          query: input.query,
        },
      },
      {
        id: `msg_${searchCallId}`,
        type: 'message',
        role: 'assistant',
        status: 'completed',
        content: [{
          type: 'output_text',
          text: outputText,
        }],
      },
    ],
    usage: {
      input_tokens: 0,
      output_tokens: 0,
      total_tokens: 0,
    },
  };
}

function serializeResponsesSse(payload: Record<string, unknown>): string[] {
  return [
    `event: response.completed\ndata: ${JSON.stringify({
      type: 'response.completed',
      response: payload,
    })}\n\n`,
    'data: [DONE]\n\n',
  ];
}

async function sendAnthropicSearchSimulation(input: {
  app: FastifyInstance;
  request: FastifyRequest;
  reply: FastifyReply;
  body: Record<string, unknown>;
  openAiBody: Record<string, unknown>;
  searchBody: Record<string, unknown>;
}): Promise<boolean> {
  const tool = findSearchTool(input.searchBody) || findSearchTool(input.openAiBody);
  const query = extractAnthropicSearchQuery(input.body) || extractResponsesWebSearchQuery(input.openAiBody);
  if (!query) return false;

  const search = await callLocalSearchRoute({
    app: input.app,
    request: input.request,
    query,
    model: SEARCH_SIMULATION_MODEL,
    maxResults: toSearchMaxResults(tool),
  });
  if (search.statusCode < 200 || search.statusCode >= 300) {
    input.reply.code(search.statusCode).send(search.payload);
    return true;
  }

  const responsesPayload = buildSyntheticResponsesPayload({
    body: input.openAiBody,
    query,
    searchPayload: search.payload,
  });
  if (input.body.stream === true) {
    const streamContext = anthropicMessagesTransformer.createStreamContext(asTrimmedString(input.body.model) || 'unknown');
    const claudeContext = anthropicMessagesTransformer.createDownstreamContext();
    const lines = anthropicMessagesTransformer.serializeUpstreamFinalAsStream(
      responsesPayload,
      asTrimmedString(input.body.model) || 'unknown',
      '',
      streamContext,
      claudeContext,
    );
    input.reply
      .code(200)
      .header('Content-Type', 'text/event-stream; charset=utf-8')
      .header('Cache-Control', 'no-cache, no-transform')
      .send(lines.join(''));
    return true;
  }

  const normalized = anthropicMessagesTransformer.transformFinalResponse(
    responsesPayload,
    asTrimmedString(input.body.model) || 'unknown',
    '',
  );
  input.reply.code(200).send(anthropicMessagesTransformer.serializeFinalResponse(normalized, {
    promptTokens: 0,
    completionTokens: 0,
    totalTokens: 0,
  }));
  return true;
}

async function sendResponsesSearchSimulation(input: {
  app: FastifyInstance;
  request: FastifyRequest;
  reply: FastifyReply;
  body: Record<string, unknown>;
}): Promise<boolean> {
  if (!hasResponsesWebSearchOnlyRequest(input.body)) return false;
  const tool = findSearchTool(input.body);
  const query = extractResponsesWebSearchQuery(input.body);
  if (!query) return false;

  const search = await callLocalSearchRoute({
    app: input.app,
    request: input.request,
    query,
    model: SEARCH_SIMULATION_MODEL,
    maxResults: toSearchMaxResults(tool),
  });
  if (search.statusCode < 200 || search.statusCode >= 300) {
    input.reply.code(search.statusCode).send(search.payload);
    return true;
  }

  const payload = buildSyntheticResponsesPayload({
    body: input.body,
    query,
    searchPayload: search.payload,
  });
  if (input.body.stream === true) {
    input.reply
      .code(200)
      .header('Content-Type', 'text/event-stream; charset=utf-8')
      .header('Cache-Control', 'no-cache, no-transform')
      .send(serializeResponsesSse(payload).join(''));
    return true;
  }

  input.reply.code(200).send(payload);
  return true;
}

export async function maybeHandleWebSearchOnlySimulation(input: {
  app: FastifyInstance;
  request: FastifyRequest;
  reply: FastifyReply;
  downstreamFormat: 'responses' | 'claude';
  body: Record<string, unknown>;
  openAiBody?: Record<string, unknown>;
}): Promise<boolean> {
  if (input.downstreamFormat === 'responses') {
    return sendResponsesSearchSimulation({
      app: input.app,
      request: input.request,
      reply: input.reply,
      body: input.body,
    });
  }

  const openAiBody = input.openAiBody;
  const rawBodyHasSearchOnly = hasResponsesWebSearchOnlyRequest(input.body);
  const openAiBodyHasSearchOnly = !!openAiBody && hasResponsesWebSearchOnlyRequest(openAiBody);
  if (!openAiBody || (!rawBodyHasSearchOnly && !openAiBodyHasSearchOnly)) return false;
  return sendAnthropicSearchSimulation({
    app: input.app,
    request: input.request,
    reply: input.reply,
    body: input.body,
    openAiBody,
    searchBody: rawBodyHasSearchOnly ? input.body : openAiBody,
  });
}

export function isResponsesWebSearchOnlyRequest(body: Record<string, unknown>): boolean {
  return hasResponsesWebSearchOnlyRequest(body);
}
