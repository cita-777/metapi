export const MESSAGE_STATUS = {
  LOADING: 'loading',
  INCOMPLETE: 'incomplete',
  COMPLETE: 'complete',
  ERROR: 'error',
} as const;

export const DEBUG_TABS = {
  PREVIEW: 'preview',
  REQUEST: 'request',
  RESPONSE: 'response',
} as const;

type MessageStatus = typeof MESSAGE_STATUS[keyof typeof MESSAGE_STATUS];
export type DebugTab = typeof DEBUG_TABS[keyof typeof DEBUG_TABS];

export type PlaygroundMode =
  | 'conversation'
  | 'embeddings'
  | 'search'
  | 'images.generate'
  | 'images.edit'
  | 'videos.create'
  | 'videos.inspect';

export type PlaygroundProtocol = 'openai' | 'responses' | 'claude' | 'gemini';
export type TestTargetFormat = PlaygroundProtocol;
export type ProxyRequestKind = 'json' | 'multipart' | 'empty';
export type ProxyRequestMethod = 'POST' | 'GET' | 'DELETE';
export type VideoInspectAction = 'get' | 'delete';
export type ChatRole = 'user' | 'assistant' | 'system' | 'developer' | 'tool';

export type ConversationContentPart =
  | { type: 'text'; text: string }
  | { type: 'image_url'; url: string }
  | { type: 'image_inline'; dataUrl: string; mimeType?: string | null }
  | { type: 'input_audio'; dataUrl: string; mimeType?: string | null }
  | { type: 'input_file'; fileId?: string | null; filename?: string | null; mimeType?: string | null; data?: string | null }
  | { type: 'output_audio'; dataUrl: string; mimeType?: string | null }
  | { type: 'tool_call'; name?: string; argumentsText?: string }
  | { type: 'tool_result'; name?: string; outputText?: string }
  | { type: 'function_response'; name?: string; outputText?: string }
  | { type: 'reasoning'; text: string }
  | { type: 'redacted_reasoning'; text: string };

export type ChatMessage = {
  id: string;
  role: ChatRole;
  content: string;
  createAt: number;
  status?: MessageStatus;
  reasoningContent?: string | null;
  isReasoningExpanded?: boolean;
  isThinkingComplete?: boolean;
  hasAutoCollapsed?: boolean;
  parts?: ConversationContentPart[] | null;
};

type ApiChatMessage = {
  role: ChatRole;
  content: string;
  parts?: ConversationContentPart[] | null;
};

export type PlaygroundMultipartFile = {
  field: string;
  name: string;
  mimeType: string;
  dataUrl: string;
};

export type ConversationUploadedFile = {
  fileId: string;
  filename?: string | null;
  mimeType?: string | null;
};

export type TesterProxyEnvelope = {
  method: ProxyRequestMethod;
  path: string;
  requestKind: ProxyRequestKind;
  stream: boolean;
  jobMode: boolean;
  rawMode: boolean;
  jsonBody?: unknown;
  rawJsonText?: string;
  multipartFields?: Record<string, string>;
  multipartFiles?: PlaygroundMultipartFile[];
};

export type ModelTesterInputs = {
  mode: PlaygroundMode;
  protocol: PlaygroundProtocol;
  targetFormat: PlaygroundProtocol;
  model: string;
  systemPrompt: string;
  temperature: number;
  top_p: number;
  max_tokens: number;
  frequency_penalty: number;
  presence_penalty: number;
  seed: number | null;
  stream: boolean;
  searchMaxResults: number;
  videoInspectAction: VideoInspectAction;
};

export type ParameterEnabled = {
  temperature: boolean;
  top_p: boolean;
  max_tokens: boolean;
  frequency_penalty: boolean;
  presence_penalty: boolean;
  seed: boolean;
};

export type ModelTesterModeState = {
  embeddingsInput: string;
  searchQuery: string;
  searchAllowedDomains: string;
  searchBlockedDomains: string;
  imagesPrompt: string;
  imagesMaskDataUrl: string;
  videosPrompt: string;
  videosInspectId: string;
  extraJson: string;
};

export type ModelTesterSessionState = {
  version?: number;
  input: string;
  inputs: ModelTesterInputs;
  parameterEnabled: ParameterEnabled;
  messages: ChatMessage[];
  pendingPayload: TesterProxyEnvelope | null;
  pendingJobId?: string | null;
  customRequestMode: boolean;
  customRequestBody: string;
  showDebugPanel: boolean;
  activeDebugTab: DebugTab;
  modeState: ModelTesterModeState;
};

export type TestChatPayload = TesterProxyEnvelope;
export type ProxyTestEnvelope = TesterProxyEnvelope;

export const MODEL_TESTER_SESSION_VERSION = 5;
export const MODEL_TESTER_STORAGE_KEY = 'metapi:model-tester:session:v5';

export const DEFAULT_INPUTS: ModelTesterInputs = {
  mode: 'conversation',
  protocol: 'openai',
  targetFormat: 'openai',
  model: '',
  systemPrompt: '',
  temperature: 0.7,
  top_p: 1,
  max_tokens: 4096,
  frequency_penalty: 0,
  presence_penalty: 0,
  seed: null,
  stream: false,
  searchMaxResults: 10,
  videoInspectAction: 'get',
};

export const DEFAULT_PARAMETER_ENABLED: ParameterEnabled = {
  temperature: true,
  top_p: false,
  max_tokens: false,
  frequency_penalty: true,
  presence_penalty: true,
  seed: false,
};

export const DEFAULT_MODE_STATE: ModelTesterModeState = {
  embeddingsInput: '',
  searchQuery: '',
  searchAllowedDomains: '',
  searchBlockedDomains: '',
  imagesPrompt: '',
  imagesMaskDataUrl: '',
  videosPrompt: '',
  videosInspectId: '',
  extraJson: '',
};

const THINK_TAG_REGEX = /<think>([\s\S]*?)<\/think>/g;
const VALID_ROLES: ReadonlySet<string> = new Set(['user', 'assistant', 'system', 'developer', 'tool']);
const VALID_STATUS: ReadonlySet<string> = new Set(Object.values(MESSAGE_STATUS));
const VALID_DEBUG_TABS: ReadonlySet<string> = new Set(Object.values(DEBUG_TABS));
const VALID_MODES: ReadonlySet<string> = new Set([
  'conversation',
  'embeddings',
  'search',
  'images.generate',
  'images.edit',
  'videos.create',
  'videos.inspect',
]);
const VALID_PROTOCOLS: ReadonlySet<string> = new Set(['openai', 'responses', 'claude', 'gemini']);
const VALID_PROXY_METHODS: ReadonlySet<string> = new Set(['POST', 'GET', 'DELETE']);
const VALID_REQUEST_KINDS: ReadonlySet<string> = new Set(['json', 'multipart', 'empty']);

let messageCounter = 0;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

const toFiniteNumber = (value: unknown, fallback: number): number =>
  typeof value === 'number' && Number.isFinite(value) ? value : fallback;

const toBoolean = (value: unknown, fallback: boolean): boolean =>
  typeof value === 'boolean' ? value : fallback;

const toNullableFiniteNumber = (value: unknown): number | null => {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  return null;
};

const sanitizeString = (value: unknown, fallback = ''): string =>
  typeof value === 'string' ? value : fallback;

const isExactModelPattern = (modelPattern: string): boolean => {
  const normalized = modelPattern.trim();
  if (!normalized) return false;
  if (normalized.toLowerCase().startsWith('re:')) return false;
  return !/[\*\?]/.test(normalized);
};

const splitCommaSeparated = (value: string): string[] =>
  value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

const createMessageId = (): string => {
  messageCounter += 1;
  return `msg-${Date.now()}-${messageCounter}`;
};

const getConversationPath = (protocol: PlaygroundProtocol, model: string): string => {
  if (protocol === 'claude') return '/v1/messages';
  if (protocol === 'responses') return '/v1/responses';
  if (protocol === 'gemini') {
    const encodedModel = encodeURIComponent(model);
    return `/v1beta/models/${encodedModel}:generateContent`;
  }
  return '/v1/chat/completions';
};

const appendOptionalNumber = (target: Record<string, unknown>, key: string, enabled: boolean, value: number | null | undefined) => {
  if (!enabled) return;
  if (typeof value === 'number' && Number.isFinite(value)) {
    target[key] = value;
  }
};

const parseDataUrl = (dataUrl: string): { mimeType: string; data: string } | null => {
  const match = /^data:([^;,]+)?;base64,(.+)$/i.exec((dataUrl || '').trim());
  if (!match) return null;
  return {
    mimeType: match[1] || 'application/octet-stream',
    data: match[2],
  };
};

const toOpenAiContentPart = (part: ConversationContentPart): Record<string, unknown> | null => {
  if (part.type === 'image_url') {
    return {
      type: 'image_url',
      image_url: part.url,
    };
  }

  if (part.type === 'image_inline') {
    return {
      type: 'image_url',
      image_url: part.dataUrl,
    };
  }

  if (part.type === 'input_audio') {
    const parsed = parseDataUrl(part.dataUrl);
    if (!parsed) return null;
    return {
      type: 'input_audio',
      input_audio: {
        data: parsed.data,
        format: (part.mimeType || parsed.mimeType || 'audio/wav').split('/').pop() || 'wav',
      },
    };
  }

  if (part.type === 'input_file') {
    const filePayload: Record<string, unknown> = {};
    if (typeof part.fileId === 'string' && part.fileId.trim()) filePayload.file_id = part.fileId.trim();
    if (typeof part.filename === 'string' && part.filename.trim()) filePayload.filename = part.filename.trim();
    if (typeof part.data === 'string' && part.data.trim()) filePayload.file_data = part.data.trim();
    if (typeof part.mimeType === 'string' && part.mimeType.trim()) filePayload.mime_type = part.mimeType.trim();
    if (Object.keys(filePayload).length === 0) return null;
    return {
      type: 'file',
      file: filePayload,
    };
  }

  return null;
};

const toResponsesContentPart = (part: ConversationContentPart): Record<string, unknown> | null => {
  if (part.type === 'image_url') {
    return {
      type: 'input_image',
      image_url: part.url,
    };
  }

  if (part.type === 'image_inline') {
    return {
      type: 'input_image',
      image_url: part.dataUrl,
    };
  }

  if (part.type === 'input_audio') {
    const parsed = parseDataUrl(part.dataUrl);
    if (!parsed) return null;
    return {
      type: 'input_audio',
      input_audio: {
        data: parsed.data,
        format: (part.mimeType || parsed.mimeType || 'audio/wav').split('/').pop() || 'wav',
      },
    };
  }

  if (part.type === 'input_file') {
    const fileBlock: Record<string, unknown> = {
      type: 'input_file',
    };
    if (typeof part.fileId === 'string' && part.fileId.trim()) fileBlock.file_id = part.fileId.trim();
    if (typeof part.filename === 'string' && part.filename.trim()) fileBlock.filename = part.filename.trim();
    if (typeof part.data === 'string' && part.data.trim()) fileBlock.file_data = part.data.trim();
    if (Object.keys(fileBlock).length === 1) return null;
    return fileBlock;
  }

  return null;
};

const toGeminiContents = (messages: ApiChatMessage[]) =>
  messages.map((message) => ({
    role: message.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: message.content }],
  }));

const toOpenAiMessageContent = (message: ApiChatMessage): unknown => {
  const parts = Array.isArray(message.parts)
    ? message.parts
      .map((part) => toOpenAiContentPart(part))
      .filter((item): item is Record<string, unknown> => !!item)
    : [];

  if (parts.length <= 0) {
    return message.content;
  }

  if (message.content.trim()) {
    return [
      { type: 'text', text: message.content },
      ...parts,
    ];
  }

  return parts;
};

const toResponsesInput = (messages: ApiChatMessage[]) => {
  const hasStructuredParts = messages.some((message) => Array.isArray(message.parts) && message.parts.length > 0);
  if (!hasStructuredParts && messages.length === 1 && messages[0].role === 'user') {
    return messages[0].content;
  }
  const toResponsesTextType = (role: ApiChatMessage['role']) =>
    role === 'assistant' ? 'output_text' : 'input_text';
  return messages.map((message) => ({
    role: message.role === 'assistant' ? 'assistant' : 'user',
    content: [
      ...(message.content.trim() ? [{ type: toResponsesTextType(message.role), text: message.content }] : []),
      ...((Array.isArray(message.parts)
        ? message.parts
          .map((part) => toResponsesContentPart(part))
          .filter((item): item is Record<string, unknown> => !!item)
        : [])),
    ].length > 0
      ? [
        ...(message.content.trim() ? [{ type: toResponsesTextType(message.role), text: message.content }] : []),
        ...((Array.isArray(message.parts)
          ? message.parts
            .map((part) => toResponsesContentPart(part))
            .filter((item): item is Record<string, unknown> => !!item)
          : [])),
      ]
      : message.content,
  }));
};

const toClaudeMessages = (messages: ApiChatMessage[]) =>
  messages
    .filter((message) => message.role !== 'system' && message.role !== 'developer')
    .map((message) => ({
      role: message.role === 'assistant' ? 'assistant' : 'user',
      content: message.content,
    }));

const buildConversationJsonBody = (
  messages: ChatMessage[],
  inputs: ModelTesterInputs,
  parameterEnabled: ParameterEnabled,
): Record<string, unknown> => {
  const apiMessages = toApiMessages(messages);
  const systemPrompt = inputs.systemPrompt.trim();

  if (inputs.protocol === 'responses') {
    const body: Record<string, unknown> = {
      model: inputs.model,
      input: toResponsesInput(apiMessages.filter((message) => message.role !== 'system' && message.role !== 'developer')),
      stream: inputs.stream,
    };
    if (systemPrompt) body.instructions = systemPrompt;
    appendOptionalNumber(body, 'temperature', parameterEnabled.temperature, inputs.temperature);
    appendOptionalNumber(body, 'top_p', parameterEnabled.top_p, inputs.top_p);
    appendOptionalNumber(body, 'max_output_tokens', parameterEnabled.max_tokens, inputs.max_tokens);
    if (parameterEnabled.seed && typeof inputs.seed === 'number') body.seed = inputs.seed;
    return body;
  }

  if (inputs.protocol === 'claude') {
    const body: Record<string, unknown> = {
      model: inputs.model,
      stream: inputs.stream,
      messages: toClaudeMessages(apiMessages),
      max_tokens: parameterEnabled.max_tokens ? inputs.max_tokens : DEFAULT_INPUTS.max_tokens,
    };
    if (systemPrompt) body.system = systemPrompt;
    appendOptionalNumber(body, 'temperature', parameterEnabled.temperature, inputs.temperature);
    appendOptionalNumber(body, 'top_p', parameterEnabled.top_p, inputs.top_p);
    return body;
  }

  if (inputs.protocol === 'gemini') {
    const body: Record<string, unknown> = {
      contents: toGeminiContents(apiMessages.filter((message) => message.role !== 'system' && message.role !== 'developer')),
    };
    if (systemPrompt) {
      body.systemInstruction = {
        parts: [{ text: systemPrompt }],
      };
    }
    const generationConfig: Record<string, unknown> = {};
    appendOptionalNumber(generationConfig, 'temperature', parameterEnabled.temperature, inputs.temperature);
    appendOptionalNumber(generationConfig, 'topP', parameterEnabled.top_p, inputs.top_p);
    appendOptionalNumber(generationConfig, 'maxOutputTokens', parameterEnabled.max_tokens, inputs.max_tokens);
    if (parameterEnabled.seed && typeof inputs.seed === 'number') generationConfig.seed = inputs.seed;
    if (Object.keys(generationConfig).length > 0) {
      body.generationConfig = generationConfig;
    }
    return body;
  }

  const openAiMessages = [
    ...(systemPrompt ? [{ role: 'system', content: systemPrompt }] : []),
    ...apiMessages.map((message) => ({
      role: message.role === 'developer' ? 'system' : message.role,
      content: toOpenAiMessageContent(message),
    })),
  ];

  const body: Record<string, unknown> = {
    model: inputs.model,
    messages: openAiMessages,
    stream: inputs.stream,
  };
  appendOptionalNumber(body, 'temperature', parameterEnabled.temperature, inputs.temperature);
  appendOptionalNumber(body, 'top_p', parameterEnabled.top_p, inputs.top_p);
  appendOptionalNumber(body, 'max_tokens', parameterEnabled.max_tokens, inputs.max_tokens);
  appendOptionalNumber(body, 'frequency_penalty', parameterEnabled.frequency_penalty, inputs.frequency_penalty);
  appendOptionalNumber(body, 'presence_penalty', parameterEnabled.presence_penalty, inputs.presence_penalty);
  if (parameterEnabled.seed && typeof inputs.seed === 'number') body.seed = inputs.seed;
  return body;
};

const parseMessage = (value: unknown, index: number): ChatMessage | null => {
  if (!isRecord(value)) return null;
  if (typeof value.role !== 'string' || !VALID_ROLES.has(value.role)) return null;
  if (typeof value.content !== 'string') return null;

  const parsed: ChatMessage = {
    id: typeof value.id === 'string' && value.id.trim().length > 0
      ? value.id
      : `legacy-${index}-${Date.now()}`,
    role: value.role as ChatRole,
    content: value.content,
    createAt: typeof value.createAt === 'number' && Number.isFinite(value.createAt)
      ? value.createAt
      : Date.now(),
  };

  if (typeof value.status === 'string' && VALID_STATUS.has(value.status)) {
    parsed.status = value.status as MessageStatus;
  }
  if (typeof value.reasoningContent === 'string') {
    parsed.reasoningContent = value.reasoningContent;
  } else if (value.reasoningContent === null) {
    parsed.reasoningContent = null;
  }
  if (typeof value.isReasoningExpanded === 'boolean') {
    parsed.isReasoningExpanded = value.isReasoningExpanded;
  }
  if (typeof value.isThinkingComplete === 'boolean') {
    parsed.isThinkingComplete = value.isThinkingComplete;
  }
  if (typeof value.hasAutoCollapsed === 'boolean') {
    parsed.hasAutoCollapsed = value.hasAutoCollapsed;
  }
  if (Array.isArray(value.parts)) {
    parsed.parts = value.parts as ConversationContentPart[];
  }

  return parsed;
};

const sanitizeMessages = (value: unknown): ChatMessage[] => {
  if (!Array.isArray(value)) return [];
  return value
    .map((item, index) => parseMessage(item, index))
    .filter((item): item is ChatMessage => item !== null);
};

const parseInputs = (value: unknown, fallbackModel = ''): ModelTesterInputs => {
  if (!isRecord(value)) {
    return {
      ...DEFAULT_INPUTS,
      model: fallbackModel,
    };
  }

  const model = typeof value.model === 'string' && value.model.trim().length > 0
    ? value.model
    : fallbackModel;

  const protocol = typeof value.protocol === 'string' && VALID_PROTOCOLS.has(value.protocol)
    ? value.protocol as PlaygroundProtocol
    : value.targetFormat === 'claude'
      ? 'claude'
      : value.targetFormat === 'responses'
        ? 'responses'
        : value.targetFormat === 'gemini'
          ? 'gemini'
          : DEFAULT_INPUTS.protocol;

  return {
    model,
    mode: typeof value.mode === 'string' && VALID_MODES.has(value.mode)
      ? value.mode as PlaygroundMode
      : DEFAULT_INPUTS.mode,
    protocol,
    targetFormat: protocol,
    systemPrompt: sanitizeString(value.systemPrompt),
    temperature: toFiniteNumber(value.temperature, DEFAULT_INPUTS.temperature),
    top_p: toFiniteNumber(value.top_p, DEFAULT_INPUTS.top_p),
    max_tokens: toFiniteNumber(value.max_tokens, DEFAULT_INPUTS.max_tokens),
    frequency_penalty: toFiniteNumber(value.frequency_penalty, DEFAULT_INPUTS.frequency_penalty),
    presence_penalty: toFiniteNumber(value.presence_penalty, DEFAULT_INPUTS.presence_penalty),
    seed: toNullableFiniteNumber(value.seed),
    stream: toBoolean(value.stream, DEFAULT_INPUTS.stream),
    searchMaxResults: Math.max(1, Math.min(20, Math.trunc(toFiniteNumber(value.searchMaxResults, DEFAULT_INPUTS.searchMaxResults)))),
    videoInspectAction: value.videoInspectAction === 'delete' ? 'delete' : 'get',
  };
};

const parseParameterEnabled = (value: unknown): ParameterEnabled => {
  if (!isRecord(value)) {
    return { ...DEFAULT_PARAMETER_ENABLED };
  }

  return {
    temperature: toBoolean(value.temperature, DEFAULT_PARAMETER_ENABLED.temperature),
    top_p: toBoolean(value.top_p, DEFAULT_PARAMETER_ENABLED.top_p),
    max_tokens: toBoolean(value.max_tokens, DEFAULT_PARAMETER_ENABLED.max_tokens),
    frequency_penalty: toBoolean(value.frequency_penalty, DEFAULT_PARAMETER_ENABLED.frequency_penalty),
    presence_penalty: toBoolean(value.presence_penalty, DEFAULT_PARAMETER_ENABLED.presence_penalty),
    seed: toBoolean(value.seed, DEFAULT_PARAMETER_ENABLED.seed),
  };
};

const parseModeState = (value: unknown): ModelTesterModeState => {
  if (!isRecord(value)) return { ...DEFAULT_MODE_STATE };
  return {
    embeddingsInput: sanitizeString(value.embeddingsInput),
    searchQuery: sanitizeString(value.searchQuery),
    searchAllowedDomains: sanitizeString(value.searchAllowedDomains),
    searchBlockedDomains: sanitizeString(value.searchBlockedDomains),
    imagesPrompt: sanitizeString(value.imagesPrompt),
    imagesMaskDataUrl: sanitizeString(value.imagesMaskDataUrl),
    videosPrompt: sanitizeString(value.videosPrompt),
    videosInspectId: sanitizeString(value.videosInspectId),
    extraJson: sanitizeString(value.extraJson),
  };
};

const parseMultipartFiles = (value: unknown): PlaygroundMultipartFile[] => {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!isRecord(item)) return [];
    if (
      typeof item.field !== 'string'
      || typeof item.name !== 'string'
      || typeof item.mimeType !== 'string'
      || typeof item.dataUrl !== 'string'
    ) {
      return [];
    }
    return [{
      field: item.field,
      name: item.name,
      mimeType: item.mimeType,
      dataUrl: item.dataUrl,
    }];
  });
};

const buildFallbackInputsFromLegacy = (value: Record<string, unknown>): ModelTesterInputs => {
  const legacyModel = typeof value.model === 'string' ? value.model : '';
  const inputs = parseInputs(value.inputs, legacyModel);

  if (!value.inputs) {
    inputs.protocol = value.targetFormat === 'claude'
      ? 'claude'
      : value.targetFormat === 'responses'
        ? 'responses'
        : value.targetFormat === 'gemini'
          ? 'gemini'
          : inputs.protocol;
    inputs.temperature = toFiniteNumber(value.temperature, inputs.temperature);
  }

  return inputs;
};

const parsePendingPayload = (
  value: unknown,
  inputs: ModelTesterInputs,
  parameterEnabled: ParameterEnabled,
): TesterProxyEnvelope | null => {
  if (!isRecord(value)) return null;

  if (typeof value.path === 'string' && typeof value.method === 'string' && VALID_PROXY_METHODS.has(value.method)) {
    const requestKind = typeof value.requestKind === 'string' && VALID_REQUEST_KINDS.has(value.requestKind)
      ? value.requestKind as ProxyRequestKind
      : 'json';

    const pending: TesterProxyEnvelope = {
      method: value.method as ProxyRequestMethod,
      path: value.path,
      requestKind,
      stream: toBoolean(value.stream, false),
      jobMode: toBoolean(value.jobMode, false),
      rawMode: toBoolean(value.rawMode, false),
    };

    if ('jsonBody' in value) pending.jsonBody = value.jsonBody;
    if (typeof value.rawJsonText === 'string') pending.rawJsonText = value.rawJsonText;
    if (isRecord(value.multipartFields)) {
      pending.multipartFields = Object.fromEntries(
        Object.entries(value.multipartFields)
          .filter(([, item]) => typeof item === 'string')
          .map(([key, item]) => [key, item as string]),
      );
    }
    const multipartFiles = parseMultipartFiles(value.multipartFiles);
    if (multipartFiles.length > 0) pending.multipartFiles = multipartFiles;
    return pending;
  }

  if (typeof value.model === 'string') {
    const legacyMessages = sanitizeMessages(value.messages);
    if (legacyMessages.length === 0) return null;
    const legacyInputs: ModelTesterInputs = {
      ...inputs,
      model: value.model,
      protocol: value.targetFormat === 'claude'
        ? 'claude'
        : value.targetFormat === 'responses'
          ? 'responses'
          : value.targetFormat === 'gemini'
            ? 'gemini'
            : inputs.protocol,
      targetFormat: value.targetFormat === 'claude'
        ? 'claude'
        : value.targetFormat === 'responses'
          ? 'responses'
          : value.targetFormat === 'gemini'
            ? 'gemini'
            : inputs.targetFormat,
      stream: toBoolean(value.stream, inputs.stream),
      temperature: toFiniteNumber(value.temperature, inputs.temperature),
      top_p: toFiniteNumber(value.top_p, inputs.top_p),
      max_tokens: toFiniteNumber(value.max_tokens, inputs.max_tokens),
      frequency_penalty: toFiniteNumber(value.frequency_penalty, inputs.frequency_penalty),
      presence_penalty: toFiniteNumber(value.presence_penalty, inputs.presence_penalty),
      seed: toNullableFiniteNumber(value.seed),
    };
    return buildConversationRequestEnvelope(legacyMessages, legacyInputs, parameterEnabled);
  }

  return null;
};

export const collectModelTesterModelNames = (
  marketplace: { models?: Array<{ name?: unknown }>; } | null | undefined,
  routes: Array<{ modelPattern?: unknown; enabled?: unknown; }> | null | undefined,
): string[] => {
  const result: string[] = [];
  const seen = new Set<string>();

  const appendModel = (rawName: unknown) => {
    if (typeof rawName !== 'string') return;
    const name = rawName.trim();
    if (!name || seen.has(name)) return;
    seen.add(name);
    result.push(name);
  };

  for (const item of marketplace?.models || []) {
    appendModel(item?.name);
  }

  for (const route of routes || []) {
    if (!route || route.enabled === false) continue;
    if (typeof route.modelPattern !== 'string') continue;
    const modelPattern = route.modelPattern.trim();
    if (!modelPattern || !isExactModelPattern(modelPattern)) continue;
    appendModel(modelPattern);
  }

  return result;
};

export const filterModelTesterModelNames = (models: string[], query: string): string[] => {
  const keyword = query.trim().toLowerCase();
  if (!keyword) return [...models];

  return models
    .map((name, index) => {
      const matchIndex = name.toLowerCase().indexOf(keyword);
      if (matchIndex === -1) return null;
      return { name, matchIndex, index };
    })
    .filter((item): item is { name: string; matchIndex: number; index: number } => item !== null)
    .sort((a, b) => {
      if (a.matchIndex !== b.matchIndex) return a.matchIndex - b.matchIndex;
      if (a.name.length !== b.name.length) return a.name.length - b.name.length;
      return a.index - b.index;
    })
    .map((item) => item.name);
};

export const createMessage = (role: ChatRole, content: string, extra: Partial<ChatMessage> = {}): ChatMessage => ({
  id: createMessageId(),
  role,
  content,
  createAt: Date.now(),
  ...extra,
});

export const createConversationInputFilePart = (
  file: ConversationUploadedFile,
): ConversationContentPart => ({
  type: 'input_file',
  fileId: file.fileId,
  filename: file.filename ?? null,
  mimeType: file.mimeType ?? null,
});

export const createConversationUserMessage = (
  content: string,
  files: ConversationUploadedFile[] = [],
  extra: Partial<ChatMessage> = {},
): ChatMessage => {
  const parts = files.map((file) => createConversationInputFilePart(file));
  return createMessage('user', content, {
    ...extra,
    ...(parts.length > 0 ? { parts } : {}),
  });
};

export const createLoadingAssistantMessage = (): ChatMessage =>
  createMessage('assistant', '', {
    status: MESSAGE_STATUS.LOADING,
    reasoningContent: '',
    isReasoningExpanded: true,
    isThinkingComplete: false,
    hasAutoCollapsed: false,
  });

export const serializeModelTesterSession = (state: ModelTesterSessionState): string =>
  JSON.stringify({
    ...state,
    version: MODEL_TESTER_SESSION_VERSION,
  });

export const processThinkTags = (content: string, reasoningContent = ''): { content: string; reasoningContent: string } => {
  if (!content || !content.includes('<think>')) {
    return { content, reasoningContent };
  }

  const thoughts: string[] = [];
  const replyParts: string[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  THINK_TAG_REGEX.lastIndex = 0;
  while ((match = THINK_TAG_REGEX.exec(content)) !== null) {
    replyParts.push(content.substring(lastIndex, match.index));
    thoughts.push(match[1]);
    lastIndex = match.index + match[0].length;
  }
  replyParts.push(content.substring(lastIndex));

  const processedContent = replyParts.join('').replace(/<\/?think>/g, '').trim();
  const thoughtsCombined = thoughts.join('\n\n---\n\n');

  return {
    content: processedContent,
    reasoningContent: reasoningContent && thoughtsCombined
      ? `${reasoningContent}\n\n---\n\n${thoughtsCombined}`
      : (reasoningContent || thoughtsCombined),
  };
};

const processIncompleteThinkTags = (content: string, reasoningContent = ''): { content: string; reasoningContent: string } => {
  if (!content) return { content: '', reasoningContent };

  const lastOpenThinkIndex = content.lastIndexOf('<think>');
  if (lastOpenThinkIndex === -1) {
    return processThinkTags(content, reasoningContent);
  }

  const fragmentAfterLastOpen = content.substring(lastOpenThinkIndex);
  if (!fragmentAfterLastOpen.includes('</think>')) {
    const unclosedThought = fragmentAfterLastOpen.substring('<think>'.length).trim();
    const cleanContent = content.substring(0, lastOpenThinkIndex);
    const mergedReasoning = unclosedThought
      ? (reasoningContent ? `${reasoningContent}\n\n---\n\n${unclosedThought}` : unclosedThought)
      : reasoningContent;
    return processThinkTags(cleanContent, mergedReasoning);
  }

  return processThinkTags(content, reasoningContent);
};

export const finalizeIncompleteMessage = (message: ChatMessage): ChatMessage => {
  if (message.status !== MESSAGE_STATUS.LOADING && message.status !== MESSAGE_STATUS.INCOMPLETE) {
    return message;
  }

  const processed = processIncompleteThinkTags(message.content || '', message.reasoningContent || '');
  return {
    ...message,
    content: processed.content || message.content,
    reasoningContent: processed.reasoningContent || null,
    status: MESSAGE_STATUS.COMPLETE,
    isThinkingComplete: true,
  };
};

export const parseModelTesterSession = (raw: string | null): ModelTesterSessionState | null => {
  if (typeof raw !== 'string' || raw.trim().length === 0) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (!isRecord(parsed)) return null;

  const inputs = buildFallbackInputsFromLegacy(parsed);
  if (!inputs.model) return null;

  const parameterEnabled = parseParameterEnabled(parsed.parameterEnabled);
  const state: ModelTesterSessionState = {
    version: typeof parsed.version === 'number' && Number.isFinite(parsed.version)
      ? Math.trunc(parsed.version)
      : MODEL_TESTER_SESSION_VERSION,
    input: typeof parsed.input === 'string' ? parsed.input : '',
    inputs,
    parameterEnabled,
    messages: sanitizeMessages(parsed.messages),
    pendingPayload: parsePendingPayload(parsed.pendingPayload, inputs, parameterEnabled),
    customRequestMode: toBoolean(parsed.customRequestMode, false),
    customRequestBody: typeof parsed.customRequestBody === 'string' ? parsed.customRequestBody : '',
    showDebugPanel: toBoolean(parsed.showDebugPanel, false),
    activeDebugTab: typeof parsed.activeDebugTab === 'string' && VALID_DEBUG_TABS.has(parsed.activeDebugTab)
      ? parsed.activeDebugTab as DebugTab
      : DEBUG_TABS.PREVIEW,
    modeState: parseModeState(parsed.modeState),
  };

  if (typeof parsed.pendingJobId === 'string' && parsed.pendingJobId.trim().length > 0) {
    state.pendingJobId = parsed.pendingJobId;
  } else if (parsed.pendingJobId === null) {
    state.pendingJobId = null;
  }

  if (!state.pendingJobId && state.messages.length > 0) {
    state.messages = state.messages.map((message) => finalizeIncompleteMessage(message));
  }

  return state;
};

export const toApiMessages = (messages: ChatMessage[]): ApiChatMessage[] =>
  messages
    .filter((message) => {
      if (message.role !== 'assistant') return true;
      return message.status !== MESSAGE_STATUS.LOADING && message.status !== MESSAGE_STATUS.INCOMPLETE;
    })
    .map((message) => ({
      role: message.role,
      content: message.content,
      parts: message.parts,
    }));

export const buildConversationRequestEnvelope = (
  messages: ChatMessage[],
  inputs: ModelTesterInputs,
  parameterEnabled: ParameterEnabled,
): TesterProxyEnvelope => ({
  method: 'POST',
  path: getConversationPath(inputs.protocol, inputs.model),
  requestKind: 'json',
  stream: inputs.stream,
  jobMode: !inputs.stream,
  rawMode: false,
  jsonBody: buildConversationJsonBody(messages, inputs, parameterEnabled),
});

export const buildGeminiNativeConversationProxyEnvelope = (
  messages: ChatMessage[],
  inputs: ModelTesterInputs,
  parameterEnabled: ParameterEnabled,
): TesterProxyEnvelope => {
  const envelope = buildConversationRequestEnvelope(messages, { ...inputs, protocol: 'gemini' }, parameterEnabled);
  return {
    ...envelope,
    path: `/gemini${envelope.path}${inputs.stream ? '?alt=sse' : ''}`,
    jobMode: false,
  };
};

export const buildEmbeddingsRequestEnvelope = (
  inputText: string,
  inputs: ModelTesterInputs,
): TesterProxyEnvelope => ({
  method: 'POST',
  path: '/v1/embeddings',
  requestKind: 'json',
  stream: false,
  jobMode: false,
  rawMode: false,
  jsonBody: {
    model: inputs.model,
    input: inputText,
  },
});

export const buildSearchRequestEnvelope = (
  inputs: ModelTesterInputs,
  modeState: ModelTesterModeState,
): TesterProxyEnvelope => {
  const jsonBody: Record<string, unknown> = {
    model: inputs.model || '__search',
    query: modeState.searchQuery,
    max_results: inputs.searchMaxResults,
  };
  const allowedDomains = splitCommaSeparated(modeState.searchAllowedDomains);
  const blockedDomains = splitCommaSeparated(modeState.searchBlockedDomains);
  if (allowedDomains.length > 0) jsonBody.allowed_domains = allowedDomains;
  if (blockedDomains.length > 0) jsonBody.blocked_domains = blockedDomains;
  return {
    method: 'POST',
    path: '/v1/search',
    requestKind: 'json',
    stream: false,
    jobMode: false,
    rawMode: false,
    jsonBody,
  };
};

export const buildImagesGenerationsRequestEnvelope = (
  inputs: ModelTesterInputs,
  modeState: ModelTesterModeState,
): TesterProxyEnvelope => ({
  method: 'POST',
  path: '/v1/images/generations',
  requestKind: 'json',
  stream: false,
  jobMode: false,
  rawMode: false,
  jsonBody: {
    model: inputs.model,
    prompt: modeState.imagesPrompt,
  },
});

export const buildFileUploadRequestEnvelope = (
  file: Omit<PlaygroundMultipartFile, 'field'> & { field?: string },
  purpose = 'assistants',
): TesterProxyEnvelope => ({
  method: 'POST',
  path: '/v1/files',
  requestKind: 'multipart',
  stream: false,
  jobMode: false,
  rawMode: false,
  multipartFields: {
    purpose,
  },
  multipartFiles: [{
    field: file.field || 'file',
    name: file.name,
    mimeType: file.mimeType,
    dataUrl: file.dataUrl,
  }],
});

export const buildImagesEditRequestEnvelope = (
  inputs: ModelTesterInputs,
  modeState: ModelTesterModeState,
  files: PlaygroundMultipartFile[],
): TesterProxyEnvelope => ({
  method: 'POST',
  path: '/v1/images/edits',
  requestKind: 'multipart',
  stream: false,
  jobMode: false,
  rawMode: false,
  multipartFields: {
    model: inputs.model,
    prompt: modeState.imagesPrompt,
  },
  multipartFiles: files,
});

export const buildVideoCreateRequestEnvelope = (
  inputs: ModelTesterInputs,
  modeState: ModelTesterModeState,
  files: PlaygroundMultipartFile[],
): TesterProxyEnvelope => ({
  method: 'POST',
  path: '/v1/videos',
  requestKind: files.length > 0 ? 'multipart' : 'json',
  stream: false,
  jobMode: false,
  rawMode: false,
  jsonBody: files.length > 0 ? undefined : { model: inputs.model, prompt: modeState.videosPrompt },
  multipartFields: files.length > 0 ? { model: inputs.model, prompt: modeState.videosPrompt } : undefined,
  multipartFiles: files.length > 0 ? files : undefined,
});

export const buildVideoInspectRequestEnvelope = (
  inputs: ModelTesterInputs,
  modeState: ModelTesterModeState,
): TesterProxyEnvelope => ({
  method: inputs.videoInspectAction === 'delete' ? 'DELETE' : 'GET',
  path: `/v1/videos/${encodeURIComponent(modeState.videosInspectId.trim())}`,
  requestKind: 'empty',
  stream: false,
  jobMode: false,
  rawMode: false,
});

export const buildApiPayload = (
  messages: ChatMessage[],
  inputs: ModelTesterInputs,
  parameterEnabled: ParameterEnabled,
): TesterProxyEnvelope =>
  buildConversationRequestEnvelope(messages, inputs, parameterEnabled);

export const parseCustomRequestBody = (raw: string): Record<string, unknown> | null => {
  if (!raw.trim()) return null;
  try {
    const parsed = JSON.parse(raw);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

export const syncMessagesToCustomRequestBody = (
  currentBody: string,
  messages: ChatMessage[],
  inputs: ModelTesterInputs,
): string => {
  let payload: Record<string, unknown>;
  try {
    const parsed = JSON.parse(currentBody || '{}');
    payload = isRecord(parsed) ? parsed : {};
  } catch {
    payload = {};
  }

  const apiMessages = toApiMessages(messages);
  const systemPrompt = inputs.systemPrompt.trim();
  const conversationBody: Record<string, unknown> = {
    model: inputs.model,
    stream: payload.stream !== undefined ? payload.stream : inputs.stream,
  };
  if (typeof inputs.temperature === 'number' && Number.isFinite(inputs.temperature)) {
    conversationBody.temperature = inputs.temperature;
  }

  if (inputs.protocol === 'responses') {
    conversationBody.input = toResponsesInput(apiMessages.filter((message) => message.role !== 'system' && message.role !== 'developer'));
    if (!('instructions' in payload) && systemPrompt) {
      conversationBody.instructions = systemPrompt;
    }
  } else if (inputs.protocol === 'claude') {
    conversationBody.messages = toClaudeMessages(apiMessages);
    if (!('system' in payload) && systemPrompt) {
      conversationBody.system = systemPrompt;
    }
  } else if (inputs.protocol === 'gemini') {
    conversationBody.contents = toGeminiContents(apiMessages.filter((message) => message.role !== 'system' && message.role !== 'developer'));
    if (!('systemInstruction' in payload) && systemPrompt) {
      conversationBody.systemInstruction = { parts: [{ text: systemPrompt }] };
    }
  } else {
    conversationBody.messages = [
      ...((!('system' in payload) && systemPrompt) ? [{ role: 'system', content: systemPrompt }] : []),
      ...apiMessages.map((message) => ({
        role: message.role === 'developer' ? 'system' : message.role,
        content: toOpenAiMessageContent(message),
      })),
    ];
  }

  return JSON.stringify({ ...payload, ...conversationBody }, null, 2);
};

export const syncCustomRequestBodyToMessages = (raw: string): ChatMessage[] | null => {
  const parsed = parseCustomRequestBody(raw);
  if (!parsed) return null;

  const restored: Array<{ role: ChatRole; content: string }> = [];
  const appendMessage = (role: ChatRole, content: string) => {
    if (!content.trim()) return;
    restored.push({ role, content });
  };

  if (typeof parsed.system === 'string') appendMessage('system', parsed.system);
  if (typeof parsed.instructions === 'string') appendMessage('system', parsed.instructions);
  if (isRecord(parsed.systemInstruction) && Array.isArray(parsed.systemInstruction.parts)) {
    const systemText = parsed.systemInstruction.parts
      .map((part) => (isRecord(part) && typeof part.text === 'string' ? part.text : ''))
      .join('\n');
    appendMessage('system', systemText);
  }

  if (Array.isArray(parsed.messages)) {
    for (const item of parsed.messages) {
      if (!isRecord(item) || typeof item.role !== 'string') continue;
      if (typeof item.content === 'string') {
        appendMessage(VALID_ROLES.has(item.role) ? item.role as ChatRole : 'user', item.content);
        continue;
      }
      if (Array.isArray(item.content)) {
        const text = item.content
          .map((block) => {
            if (isRecord(block) && typeof block.text === 'string') return block.text;
            if (isRecord(block) && typeof block.content === 'string') return block.content;
            return '';
          })
          .join('\n');
        appendMessage(VALID_ROLES.has(item.role) ? item.role as ChatRole : 'user', text);
      }
    }
  } else if (Array.isArray(parsed.input)) {
    for (const item of parsed.input) {
      if (!isRecord(item) || typeof item.role !== 'string') continue;
      appendMessage(item.role === 'assistant' ? 'assistant' : 'user', sanitizeString(item.content));
    }
  } else if (typeof parsed.input === 'string') {
    appendMessage('user', parsed.input);
  } else if (Array.isArray(parsed.contents)) {
    for (const item of parsed.contents) {
      if (!isRecord(item)) continue;
      const role = item.role === 'model' ? 'assistant' : 'user';
      const text = Array.isArray(item.parts)
        ? item.parts
          .map((part) => (isRecord(part) && typeof part.text === 'string' ? part.text : ''))
          .join('\n')
        : '';
      appendMessage(role, text);
    }
  }

  if (restored.length === 0) return null;
  return restored.map((item, index) => createMessage(item.role, item.content, {
    id: `custom-${index}-${Date.now()}`,
  }));
};

export const buildRawProxyRequestEnvelope = (
  method: ProxyRequestMethod,
  path: string,
  requestKind: ProxyRequestKind,
  rawJsonText: string,
  options?: Partial<Pick<TesterProxyEnvelope, 'stream' | 'jobMode'>>,
): TesterProxyEnvelope => ({
  method,
  path,
  requestKind,
  stream: options?.stream ?? false,
  jobMode: options?.jobMode ?? false,
  rawMode: true,
  rawJsonText,
});

export const findLastLoadingAssistantIndex = (messages: ChatMessage[]): number => {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (
      message.role === 'assistant' &&
      (message.status === MESSAGE_STATUS.LOADING || message.status === MESSAGE_STATUS.INCOMPLETE)
    ) {
      return index;
    }
  }
  return -1;
};

export const countConversationTurns = (messages: ChatMessage[]): number =>
  messages.reduce((turns, message) => turns + (message.role === 'user' ? 1 : 0), 0);

