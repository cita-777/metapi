import { describe, expect, it, vi } from 'vitest';
import * as modelTesterSessionModule from './modelTesterSession.js';
import {
  DEBUG_TABS,
  DEFAULT_INPUTS,
  DEFAULT_MODE_STATE,
  DEFAULT_PARAMETER_ENABLED,
  MODEL_TESTER_SESSION_VERSION,
  MESSAGE_STATUS,
  buildApiPayload,
  buildEmbeddingsRequestEnvelope,
  buildFileUploadRequestEnvelope,
  buildGeminiNativeConversationProxyEnvelope,
  buildRawProxyRequestEnvelope,
  buildSearchRequestEnvelope,
  attachForcedChannelToEnvelope,
  collectModelTesterModelNames,
  countConversationTurns,
  createConversationUserMessage,
  extractConversationUploadedFilesFromMessage,
  filterModelTesterModelNames,
  parseCustomRequestBody,
  parseModelTesterSession,
  serializeModelTesterSession,
  syncMessagesToCustomRequestBody,
  toApiMessages,
  type ChatMessage,
  type ModelTesterSessionState,
} from './modelTesterSession.js';

describe('modelTesterSession', () => {
  it('counts only user messages as turns', () => {
    const turns = countConversationTurns([
      { id: '1', role: 'user', content: 'hello', createAt: 1 },
      { id: '2', role: 'assistant', content: 'hi', createAt: 2 },
      { id: '3', role: 'system', content: 'meta', createAt: 3 },
      { id: '4', role: 'user', content: 'again', createAt: 4 },
    ]);
    expect(turns).toBe(2);
  });

  it('serializes and parses full playground session state', () => {
    const state: ModelTesterSessionState = {
      version: MODEL_TESTER_SESSION_VERSION,
      input: 'draft',
      inputs: {
        ...DEFAULT_INPUTS,
        mode: 'search',
        protocol: 'gemini',
        targetFormat: 'gemini',
        model: 'gemini-2.5-pro',
        systemPrompt: 'be concise',
        temperature: 0.6,
        top_p: 0.9,
        max_tokens: 2048,
        frequency_penalty: 0.1,
        presence_penalty: 0.2,
        seed: 12,
        stream: true,
        searchMaxResults: 7,
      },
      parameterEnabled: {
        ...DEFAULT_PARAMETER_ENABLED,
        max_tokens: true,
        seed: true,
      },
      messages: [
        { id: 'm1', role: 'user', content: 'hello', createAt: 1 },
        { id: 'm2', role: 'assistant', content: 'hi', createAt: 2, status: MESSAGE_STATUS.COMPLETE },
      ],
      pendingPayload: {
        method: 'POST',
        path: '/v1/search',
        requestKind: 'json',
        stream: false,
        jobMode: false,
        rawMode: false,
        forcedChannelId: 44,
        jsonBody: { model: '__search', query: 'hello', max_results: 7 },
      },
      pendingJobId: 'job-1',
      forcedChannelId: 44,
      customRequestMode: true,
      customRequestBody: '{"model":"gemini-2.5-pro","contents":[]}',
      showDebugPanel: true,
      activeDebugTab: DEBUG_TABS.REQUEST,
      conversationFiles: [
        {
          localId: 'draft-file-1',
          name: 'draft.pdf',
          mimeType: 'application/pdf',
          dataUrl: 'data:application/pdf;base64,JVBERi0x',
          fileId: 'file-metapi-draft',
          status: 'uploaded',
          errorMessage: null,
        },
      ],
      modeState: {
        ...DEFAULT_MODE_STATE,
        searchQuery: 'hello',
        searchAllowedDomains: 'openai.com, google.com',
      },
    };

    const serialized = serializeModelTesterSession(state);
    const restored = parseModelTesterSession(serialized);

    expect(restored).toEqual(state);
  });

  it('supports parsing legacy session format into conversation/openai defaults', () => {
    const restored = parseModelTesterSession(JSON.stringify({
      model: 'gpt-4o',
      temperature: 0.5,
      input: 'legacy',
      messages: [{ role: 'user', content: 'hello' }],
      pendingPayload: null,
    }));

    expect(restored?.inputs.model).toBe('gpt-4o');
    expect(restored?.inputs.protocol).toBe('openai');
    expect(restored?.inputs.mode).toBe('conversation');
    expect(restored?.inputs.temperature).toBe(0.5);
    expect(restored?.parameterEnabled).toEqual(DEFAULT_PARAMETER_ENABLED);
  });

  it('returns null for malformed or missing session payload', () => {
    expect(parseModelTesterSession(null)).toBeNull();
    expect(parseModelTesterSession('not-json')).toBeNull();
    expect(parseModelTesterSession(JSON.stringify({ messages: [] }))).toBeNull();
  });

  it('drops loading assistant placeholders when building API payload messages', () => {
    const payloadMessages = toApiMessages([
      { id: '1', role: 'user', content: 'hello', createAt: 1 },
      { id: '2', role: 'assistant', content: '', createAt: 2, status: MESSAGE_STATUS.LOADING },
      { id: '3', role: 'assistant', content: 'done', createAt: 3, status: MESSAGE_STATUS.COMPLETE },
    ]);

    expect(payloadMessages).toEqual([
      { role: 'user', content: 'hello' },
      { role: 'assistant', content: 'done' },
    ]);
  });

  it('builds conversation payload as generic proxy envelope', () => {
    const payload = buildApiPayload(
      [{ id: 'u1', role: 'user', content: 'hello', createAt: 1 }],
      {
        ...DEFAULT_INPUTS,
        model: 'gpt-4o-mini',
        protocol: 'openai',
        systemPrompt: 'You are helpful.',
        temperature: 0.5,
        top_p: 0.8,
        max_tokens: 200,
        frequency_penalty: 0.2,
        presence_penalty: 0.3,
        seed: 42,
        stream: true,
      },
      {
        temperature: true,
        top_p: false,
        max_tokens: true,
        frequency_penalty: true,
        presence_penalty: false,
        seed: true,
      },
    );

    expect(payload).toEqual({
      method: 'POST',
      path: '/v1/chat/completions',
      requestKind: 'json',
      stream: true,
      jobMode: false,
      rawMode: false,
      jsonBody: {
        model: 'gpt-4o-mini',
        messages: [
          { role: 'system', content: 'You are helpful.' },
          { role: 'user', content: 'hello' },
        ],
        stream: true,
        temperature: 0.5,
        max_tokens: 200,
        frequency_penalty: 0.2,
        seed: 42,
      },
    });
  });

  it('attaches a forced channel id to tester envelopes without mutating the request body', () => {
    const base = buildEmbeddingsRequestEnvelope('hello', {
      ...DEFAULT_INPUTS,
      model: 'text-embedding-3-small',
    });

    const payload = attachForcedChannelToEnvelope(base, 42);

    expect(payload).toEqual({
      method: 'POST',
      path: '/v1/embeddings',
      requestKind: 'json',
      stream: false,
      jobMode: false,
      rawMode: false,
      forcedChannelId: 42,
      jsonBody: {
        model: 'text-embedding-3-small',
        input: 'hello',
      },
    });
  });

  it('builds multipart upload envelopes for /v1/files', () => {
    expect(buildFileUploadRequestEnvelope({
      name: 'paper.pdf',
      mimeType: 'application/pdf',
      dataUrl: 'data:application/pdf;base64,JVBERi0xLjc=',
    })).toEqual({
      method: 'POST',
      path: '/v1/files',
      requestKind: 'multipart',
      stream: false,
      jobMode: false,
      rawMode: false,
      multipartFields: {
        purpose: 'assistants',
      },
      multipartFiles: [
        {
          field: 'file',
          name: 'paper.pdf',
          mimeType: 'application/pdf',
          dataUrl: 'data:application/pdf;base64,JVBERi0xLjc=',
        },
      ],
    });
  });

  it('creates user conversation messages that preserve uploaded file references', () => {
    const message = createConversationUserMessage('请总结附件', [
      {
        fileId: 'file-metapi-123',
        filename: 'paper.pdf',
        mimeType: 'application/pdf',
      },
    ]);

    expect(message.role).toBe('user');
    expect(message.content).toBe('请总结附件');
    expect(message.parts).toEqual([
      {
        type: 'input_file',
        fileId: 'file-metapi-123',
        filename: 'paper.pdf',
        mimeType: 'application/pdf',
      },
    ]);
  });

  it('extracts inline conversation file data for retry flows', () => {
    const files = extractConversationUploadedFilesFromMessage({
      id: 'u1',
      role: 'user',
      content: '请总结附件',
      createAt: 1,
      parts: [
        {
          type: 'input_file',
          filename: 'brief.pdf',
          mimeType: 'application/pdf',
          data: 'data:application/pdf;base64,JVBERi0xLjQK',
        },
      ],
    });

    expect(files).toEqual([
      {
        filename: 'brief.pdf',
        mimeType: 'application/pdf',
        data: 'data:application/pdf;base64,JVBERi0xLjQK',
      },
    ]);
  });

  it('extracts uploaded file references for retry flows', () => {
    const files = extractConversationUploadedFilesFromMessage({
      id: 'u2',
      role: 'user',
      content: '请继续分析',
      createAt: 2,
      parts: [
        {
          type: 'input_file',
          fileId: 'file-metapi-456',
          filename: 'appendix.txt',
          mimeType: 'text/plain',
        },
      ],
    });

    expect(files).toEqual([
      {
        fileId: 'file-metapi-456',
        filename: 'appendix.txt',
        mimeType: 'text/plain',
      },
    ]);
  });

  it('hydrates local file ids into inline replay files for claude', async () => {
    const resolveConversationReplayFiles = (modelTesterSessionModule as Record<string, any>).resolveConversationReplayFiles;
    const loader = vi.fn(async () => ({
      filename: 'brief.pdf',
      mimeType: 'application/pdf',
      data: 'data:application/pdf;base64,JVBERi0x',
    }));

    const files = await resolveConversationReplayFiles?.(
      [
        {
          fileId: 'file-metapi-123',
          filename: 'brief.pdf',
          mimeType: 'application/pdf',
        },
      ],
      'claude',
      loader,
    );

    expect(loader).toHaveBeenCalledWith('file-metapi-123');
    expect(files).toEqual([
      {
        fileId: 'file-metapi-123',
        filename: 'brief.pdf',
        mimeType: 'application/pdf',
        data: 'data:application/pdf;base64,JVBERi0x',
      },
    ]);
  });

  it('preserves file reference parts when building responses conversation payloads', () => {
    const payload = buildApiPayload(
      [{
        id: 'u1',
        role: 'user',
        content: '请总结上传文件',
        createAt: 1,
        parts: [
          {
            type: 'input_file',
            fileId: 'file_123',
            filename: 'notes.txt',
            mimeType: 'text/plain',
          },
        ],
      } as ChatMessage],
      {
        ...DEFAULT_INPUTS,
        model: 'gpt-5',
        protocol: 'responses',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(payload.jsonBody).toEqual({
      model: 'gpt-5',
      input: [
        {
          role: 'user',
          content: [
            { type: 'input_text', text: '请总结上传文件' },
            { type: 'input_file', file_id: 'file_123', filename: 'notes.txt' },
          ],
        },
      ],
      stream: false,
      temperature: 0.7,
    });
  });

  it('serializes assistant history as output_text for responses payloads', () => {
    const payload = buildApiPayload(
      [
        { id: 'u1', role: 'user', content: '先看附件', createAt: 1 },
        { id: 'a1', role: 'assistant', content: '我已经看过摘要', createAt: 2 },
      ],
      {
        ...DEFAULT_INPUTS,
        model: 'gpt-5.2',
        protocol: 'responses',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(payload.jsonBody).toEqual({
      model: 'gpt-5.2',
      input: [
        {
          role: 'user',
          content: [
            { type: 'input_text', text: '先看附件' },
          ],
        },
        {
          role: 'assistant',
          content: [
            { type: 'output_text', text: '我已经看过摘要' },
          ],
        },
      ],
      stream: false,
      temperature: 0.7,
    });
  });

  it('builds gemini conversation envelope with generationConfig', () => {
    const payload = buildApiPayload(
      [{ id: 'u1', role: 'user', content: 'hello', createAt: 1 }],
      {
        ...DEFAULT_INPUTS,
        model: 'gemini-2.5-pro',
        protocol: 'gemini',
        systemPrompt: 'system text',
        temperature: 0.2,
        max_tokens: 300,
      },
      {
        ...DEFAULT_PARAMETER_ENABLED,
        max_tokens: true,
      },
    );

    expect(payload.path).toBe('/v1beta/models/gemini-2.5-pro:generateContent');
    expect(payload.jsonBody).toEqual({
      systemInstruction: { parts: [{ text: 'system text' }] },
      contents: [{ role: 'user', parts: [{ text: 'hello' }] }],
      generationConfig: { temperature: 0.2, maxOutputTokens: 300 },
    });
  });

  it('builds gemini native proxy envelope without loading assistant placeholders', () => {
    const payload = buildGeminiNativeConversationProxyEnvelope(
      [
        { id: 'u1', role: 'user', content: 'hello', createAt: 1 },
        { id: 'a1', role: 'assistant', content: '', createAt: 2, status: MESSAGE_STATUS.LOADING },
        { id: 'a2', role: 'assistant', content: 'partial', createAt: 3, status: MESSAGE_STATUS.INCOMPLETE },
        { id: 'a3', role: 'assistant', content: 'done', createAt: 4, status: MESSAGE_STATUS.COMPLETE },
      ],
      {
        ...DEFAULT_INPUTS,
        model: 'gemini-2.5-pro',
        protocol: 'gemini',
        systemPrompt: 'system text',
        stream: true,
      },
      {
        ...DEFAULT_PARAMETER_ENABLED,
        max_tokens: true,
      },
    );

    expect(payload.path).toBe('/gemini/v1beta/models/gemini-2.5-pro:generateContent?alt=sse');
    expect(payload.jobMode).toBe(false);
    expect(payload.jsonBody).toEqual({
      systemInstruction: { parts: [{ text: 'system text' }] },
      contents: [
        { role: 'user', parts: [{ text: 'hello' }] },
        { role: 'model', parts: [{ text: 'done' }] },
      ],
      generationConfig: { temperature: 0.7, maxOutputTokens: 4096 },
    });
  });

  it('serializes conversation file parts into openai and responses payloads', () => {
    const message = {
      id: 'u1',
      role: 'user' as const,
      content: 'summarize this',
      createAt: 1,
      parts: [
        {
          type: 'input_file' as const,
          fileId: 'file_metapi_123',
          filename: 'paper.pdf',
          mimeType: 'application/pdf',
        },
      ],
    };

    const openaiPayload = buildApiPayload(
      [message],
      {
        ...DEFAULT_INPUTS,
        model: 'gpt-4.1',
        protocol: 'openai',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(openaiPayload.jsonBody).toEqual({
      model: 'gpt-4.1',
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'summarize this' },
          {
            type: 'file',
            file: {
              file_id: 'file_metapi_123',
              filename: 'paper.pdf',
              mime_type: 'application/pdf',
            },
          },
        ],
      },
      ],
      stream: false,
      temperature: 0.7,
      frequency_penalty: 0,
      presence_penalty: 0,
    });

    const responsesPayload = buildApiPayload(
      [message],
      {
        ...DEFAULT_INPUTS,
        model: 'gpt-4.1',
        protocol: 'responses',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(responsesPayload.jsonBody).toEqual({
      model: 'gpt-4.1',
      input: [
        {
          role: 'user',
          content: [
            { type: 'input_text', text: 'summarize this' },
            {
              type: 'input_file',
              file_id: 'file_metapi_123',
              filename: 'paper.pdf',
            },
          ],
        },
      ],
      stream: false,
      temperature: 0.7,
    });
  });

  it('prefers native file ids over inline backups for OpenAI and Responses payloads', () => {
    const message = {
      id: 'u1',
      role: 'user' as const,
      content: 'reuse native file id',
      createAt: 1,
      parts: [
        {
          type: 'input_file' as const,
          fileId: 'file-metapi-123',
          filename: 'brief.pdf',
          mimeType: 'application/pdf',
          data: 'data:application/pdf;base64,JVBERi0x',
        },
      ],
    };

    const openAiPayload = buildApiPayload(
      [message],
      {
        ...DEFAULT_INPUTS,
        model: 'gpt-4.1',
        protocol: 'openai',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(openAiPayload.jsonBody).toEqual({
      model: 'gpt-4.1',
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'reuse native file id' },
            {
              type: 'file',
              file: {
                file_id: 'file-metapi-123',
                filename: 'brief.pdf',
                mime_type: 'application/pdf',
              },
            },
          ],
        },
      ],
      stream: false,
      temperature: 0.7,
      frequency_penalty: 0,
      presence_penalty: 0,
    });

    const responsesPayload = buildApiPayload(
      [message],
      {
        ...DEFAULT_INPUTS,
        model: 'gpt-4.1',
        protocol: 'responses',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(responsesPayload.jsonBody).toEqual({
      model: 'gpt-4.1',
      input: [
        {
          role: 'user',
          content: [
            { type: 'input_text', text: 'reuse native file id' },
            {
              type: 'input_file',
              file_id: 'file-metapi-123',
              filename: 'brief.pdf',
            },
          ],
        },
      ],
      stream: false,
      temperature: 0.7,
    });
  });

  it('strips data URL wrappers when replaying inline files into OpenAI chat payloads', () => {
    const payload = buildApiPayload(
      [{
        id: 'u1',
        role: 'user',
        content: 'summarize this inline file',
        createAt: 1,
        parts: [
          {
            type: 'input_file',
            filename: 'brief.pdf',
            mimeType: 'application/pdf',
            data: 'data:application/pdf;base64,JVBERi0x',
          },
        ],
      } as ChatMessage],
      {
        ...DEFAULT_INPUTS,
        model: 'gpt-4.1',
        protocol: 'openai',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(payload.jsonBody).toEqual({
      model: 'gpt-4.1',
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'summarize this inline file' },
            {
              type: 'file',
              file: {
                file_data: 'JVBERi0x',
                filename: 'brief.pdf',
                mime_type: 'application/pdf',
              },
            },
          ],
        },
      ],
      stream: false,
      temperature: 0.7,
      frequency_penalty: 0,
      presence_penalty: 0,
    });
  });

  it('builds Claude conversation payloads with inline document blocks for conversation files', () => {
    const payload = buildApiPayload(
      [{
        id: 'u1',
        role: 'user',
        content: 'summarize this',
        createAt: 1,
        parts: [
          {
            type: 'input_file',
            filename: 'brief.pdf',
            mimeType: 'application/pdf',
            data: 'data:application/pdf;base64,JVBERi0xLjc=',
          },
        ],
      } as ChatMessage],
      {
        ...DEFAULT_INPUTS,
        model: 'claude-opus-4-6',
        protocol: 'claude',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(payload.jsonBody).toEqual({
      model: 'claude-opus-4-6',
      stream: false,
      max_tokens: 4096,
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'summarize this' },
            {
              type: 'document',
              source: {
                type: 'base64',
                media_type: 'application/pdf',
                data: 'JVBERi0xLjc=',
              },
              title: 'brief.pdf',
            },
          ],
        },
      ],
      temperature: 0.7,
    });
  });

  it('builds Claude conversation payloads with image blocks for inline image attachments', () => {
    const payload = buildApiPayload(
      [{
        id: 'u1',
        role: 'user',
        content: 'describe this image',
        createAt: 1,
        parts: [
          {
            type: 'input_file',
            filename: 'chart.png',
            mimeType: 'image/png',
            data: 'data:image/png;base64,QUFBQQ==',
          },
        ],
      } as ChatMessage],
      {
        ...DEFAULT_INPUTS,
        model: 'claude-opus-4-6',
        protocol: 'claude',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(payload.jsonBody).toEqual({
      model: 'claude-opus-4-6',
      stream: false,
      max_tokens: 4096,
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'describe this image' },
            {
              type: 'image',
              source: {
                type: 'base64',
                media_type: 'image/png',
                data: 'QUFBQQ==',
              },
            },
          ],
        },
      ],
      temperature: 0.7,
    });
  });

  it('builds Gemini conversation payloads with inlineData document parts for conversation files', () => {
    const payload = buildApiPayload(
      [{
        id: 'u1',
        role: 'user',
        content: 'summarize this',
        createAt: 1,
        parts: [
          {
            type: 'input_file',
            filename: 'brief.pdf',
            mimeType: 'application/pdf',
            data: 'data:application/pdf;base64,JVBERi0xLjc=',
          },
        ],
      } as ChatMessage],
      {
        ...DEFAULT_INPUTS,
        model: 'gemini-2.5-pro',
        protocol: 'gemini',
      },
      DEFAULT_PARAMETER_ENABLED,
    );

    expect(payload.jsonBody).toEqual({
      contents: [
        {
          role: 'user',
          parts: [
            { text: 'summarize this' },
            {
              inlineData: {
                mimeType: 'application/pdf',
                data: 'JVBERi0xLjc=',
              },
            },
          ],
        },
      ],
      generationConfig: { temperature: 0.7 },
    });
  });

  it('builds embeddings and search envelopes', () => {
    expect(buildEmbeddingsRequestEnvelope('hello', { ...DEFAULT_INPUTS, model: 'text-embedding-3-large' })).toEqual({
      method: 'POST',
      path: '/v1/embeddings',
      requestKind: 'json',
      stream: false,
      jobMode: false,
      rawMode: false,
      jsonBody: {
        model: 'text-embedding-3-large',
        input: 'hello',
      },
    });

    expect(buildSearchRequestEnvelope(
      { ...DEFAULT_INPUTS, model: '__search', searchMaxResults: 3 },
      { ...DEFAULT_MODE_STATE, searchQuery: 'what is ai', searchAllowedDomains: 'openai.com', searchBlockedDomains: 'example.com' },
    )).toEqual({
      method: 'POST',
      path: '/v1/search',
      requestKind: 'json',
      stream: false,
      jobMode: false,
      rawMode: false,
      jsonBody: {
        model: '__search',
        query: 'what is ai',
        max_results: 3,
        allowed_domains: ['openai.com'],
        blocked_domains: ['example.com'],
      },
    });
  });

  it('parses raw custom body without dropping unknown fields', () => {
    const parsed = parseCustomRequestBody('{"model":"gpt-5","include":["foo"],"reasoning":{"effort":"high"}}');
    expect(parsed).toEqual({
      model: 'gpt-5',
      include: ['foo'],
      reasoning: { effort: 'high' },
    });
  });

  it('syncs messages into custom request body while preserving unknown fields', () => {
    const synced = syncMessagesToCustomRequestBody(
      '{"model":"legacy","metadata":{"trace":"keep"}}',
      [{ id: '1', role: 'user', content: 'new', createAt: 1 }],
      { ...DEFAULT_INPUTS, model: 'gpt-4o', protocol: 'responses', systemPrompt: 'system' },
    );

    expect(JSON.parse(synced)).toEqual({
      model: 'gpt-4o',
      metadata: { trace: 'keep' },
      input: 'new',
      instructions: 'system',
      stream: false,
      temperature: 0.7,
    });
  });

  it('builds raw proxy envelope for passthrough mode', () => {
    expect(buildRawProxyRequestEnvelope('POST', '/v1/responses', 'json', '{"foo":1}', { stream: true })).toEqual({
      method: 'POST',
      path: '/v1/responses',
      requestKind: 'json',
      stream: true,
      jobMode: false,
      rawMode: true,
      rawJsonText: '{"foo":1}',
    });
  });

  it('merges marketplace models with exact enabled route models for tester options', () => {
    const modelNames = collectModelTesterModelNames(
      {
        models: [
          { name: 'gpt-4o-mini' },
          { name: 'bge-large-en-v1.5' },
        ],
      },
      [
        { modelPattern: 'BAAI/bge-large-en-v1.5', enabled: true },
        { modelPattern: 'claude-*', enabled: true },
        { modelPattern: 'gemini-2.5-pro', enabled: false },
      ],
    );

    expect(modelNames).toEqual([
      'gpt-4o-mini',
      'bge-large-en-v1.5',
      'BAAI/bge-large-en-v1.5',
    ]);
  });

  it('filters models by keyword and keeps best matches first', () => {
    const filtered = filterModelTesterModelNames(
      [
        'BAAI/bge-large-en-v1.5',
        'text-embedding-3-large',
        'bge-m3',
      ],
      'bge',
    );

    expect(filtered).toEqual([
      'bge-m3',
      'BAAI/bge-large-en-v1.5',
    ]);
  });
});
