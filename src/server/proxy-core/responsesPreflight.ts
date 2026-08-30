export type ResponsesPreflightResult =
  | { ok: true }
  | {
    ok: false;
    statusCode: 400;
    payload: {
      error: {
        message: string;
        type: 'invalid_request_error';
      };
    };
  };

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function invalidRequest(message: string): Extract<ResponsesPreflightResult, { ok: false }> {
  return {
    ok: false,
    statusCode: 400,
    payload: {
      error: {
        message,
        type: 'invalid_request_error',
      },
    },
  };
}

function walkRecords(value: unknown, visitor: (item: Record<string, unknown>) => void): void {
  if (Array.isArray(value)) {
    for (const item of value) walkRecords(item, visitor);
    return;
  }
  if (!isRecord(value)) return;
  visitor(value);
  for (const item of Object.values(value)) {
    if (Array.isArray(item) || isRecord(item)) walkRecords(item, visitor);
  }
}

function validateExternalPreviousResponseId(body: Record<string, unknown>): ResponsesPreflightResult {
  const previousResponseId = asTrimmedString(body.previous_response_id);
  if (!previousResponseId) return { ok: true };

  const message = previousResponseId.startsWith('msg_')
    ? 'previous_response_id must be a response id beginning with resp_; message ids like msg_* are not valid, and HTTP /v1/responses does not support continuation chaining. Use Responses WebSocket v2 for function-call follow-up turns.'
    : 'HTTP /v1/responses does not support user-supplied previous_response_id continuation chaining. Use Responses WebSocket v2 for follow-up turns.';
  return invalidRequest(message);
}

function validateFunctionCallOutputs(
  body: Record<string, unknown>,
  options: { allowContinuationToolOutput?: boolean } = {},
): ResponsesPreflightResult {
  const input = body.input;
  if (!Array.isArray(input)) return { ok: true };

  const knownCallIds = new Set<string>();
  const knownReferenceIds = new Set<string>();
  const outputs: Record<string, unknown>[] = [];

  for (const item of input) {
    if (!isRecord(item)) continue;
    const itemType = asTrimmedString(item.type).toLowerCase();
    if (itemType === 'function_call' || itemType === 'custom_tool_call' || itemType === 'tool_call') {
      const callId = asTrimmedString(item.call_id ?? item.id);
      if (callId) knownCallIds.add(callId);
      const id = asTrimmedString(item.id);
      if (id) knownReferenceIds.add(id);
      continue;
    }
    if (itemType === 'function_call_output' || itemType === 'custom_tool_call_output') {
      outputs.push(item);
    }
  }

  if (options.allowContinuationToolOutput) {
    return { ok: true };
  }

  for (const item of outputs) {
    const callId = asTrimmedString(item.call_id);
    if (!callId) {
      return invalidRequest('function_call_output requires call_id. Use Responses WebSocket v2 for incremental tool-output follow-up turns.');
    }
    const itemReference = asTrimmedString(
      item.item_reference
      ?? item.itemReference
      ?? (isRecord(item.reference) ? item.reference.id : undefined),
    );
    if (!knownCallIds.has(callId) && (!itemReference || !knownReferenceIds.has(itemReference))) {
      return invalidRequest('function_call_output must match a function_call/tool_call in the same HTTP request or include a matching item_reference. Use Responses WebSocket v2 for continuation turns.');
    }
  }

  return { ok: true };
}

export function validateExternalResponsesHttpRequest(
  body: Record<string, unknown>,
  options: { allowContinuationToolOutput?: boolean } = {},
): ResponsesPreflightResult {
  const previousResponseResult = validateExternalPreviousResponseId(body);
  if (!previousResponseResult.ok) return previousResponseResult;

  const functionCallOutputResult = validateFunctionCallOutputs(body, options);
  if (!functionCallOutputResult.ok) return functionCallOutputResult;

  return { ok: true };
}

function isWebSearchToolRecord(tool: Record<string, unknown>): boolean {
  const type = asTrimmedString(tool.type).toLowerCase();
  const name = asTrimmedString(tool.name).toLowerCase();
  return type === 'web_search'
    || type === 'web_search_preview'
    || type === 'web_search_preview_2025_03_11'
    || type === 'web_search_20250305'
    || type === 'google_search'
    || name === 'web_search'
    || name === 'google_search';
}

export function hasResponsesWebSearchOnlyRequest(body: Record<string, unknown>): boolean {
  let hasWebSearchTool = false;
  let hasOtherTools = false;

  const tools = Array.isArray(body.tools) ? body.tools : [];
  for (const tool of tools) {
    if (!isRecord(tool)) continue;
    if (isWebSearchToolRecord(tool)) {
      hasWebSearchTool = true;
    } else {
      hasOtherTools = true;
    }
  }

  return hasWebSearchTool && !hasOtherTools;
}

export function extractResponsesWebSearchQuery(body: Record<string, unknown>): string {
  if (typeof body.input === 'string') {
    const query = body.input.trim();
    if (query) return query;
  }

  const queryCandidates: string[] = [];
  walkRecords(body.input, (item) => {
    const type = asTrimmedString(item.type).toLowerCase();
    if (type === 'input_text' || type === 'text') {
      const text = asTrimmedString(item.text);
      if (text) queryCandidates.push(text);
      return;
    }
    if (type === 'message') {
      const text = asTrimmedString(item.content);
      if (text) queryCandidates.push(text);
    }
  });
  return queryCandidates[queryCandidates.length - 1] || '';
}
