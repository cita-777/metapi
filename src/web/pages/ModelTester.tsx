import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api.js';
import { clearAuthSession, getAuthToken } from '../authSession.js';
import {
  DEBUG_TABS,
  DEFAULT_INPUTS,
  DEFAULT_MODE_STATE,
  DEFAULT_PARAMETER_ENABLED,
  MODEL_TESTER_STORAGE_KEY,
  MESSAGE_STATUS,
  buildApiPayload,
  buildEmbeddingsRequestEnvelope,
  buildFileUploadRequestEnvelope,
  buildGeminiNativeConversationProxyEnvelope,
  buildImagesEditRequestEnvelope,
  buildImagesGenerationsRequestEnvelope,
  buildRawProxyRequestEnvelope,
  buildSearchRequestEnvelope,
  buildVideoCreateRequestEnvelope,
  buildVideoInspectRequestEnvelope,
  countConversationTurns,
  collectModelTesterModelNames,
  createLoadingAssistantMessage,
  createMessage,
  createConversationUserMessage,
  filterModelTesterModelNames,
  finalizeIncompleteMessage,
  findLastLoadingAssistantIndex,
  parseCustomRequestBody,
  parseModelTesterSession,
  processThinkTags,
  serializeModelTesterSession,
  syncCustomRequestBodyToMessages,
  syncMessagesToCustomRequestBody,
  type ChatMessage,
  type ConversationContentPart,
  type ConversationUploadedFile,
  type DebugTab,
  type ModelTesterInputs,
  type ModelTesterModeState,
  type ParameterEnabled,
  type PlaygroundMode,
  type PlaygroundMultipartFile,
  type TestTargetFormat,
  type TestChatPayload,
} from './helpers/modelTesterSession.js';
import ModernSelect from '../components/ModernSelect.js';
import { useAnimatedVisibility } from '../components/useAnimatedVisibility.js';
import { tr } from '../i18n.js';

type ChatJobResponse = {
  jobId: string;
  status: 'pending' | 'succeeded' | 'failed' | 'cancelled';
  result?: unknown;
  error?: unknown;
};

type DebugTimelineEntry = {
  at: string;
  level: 'info' | 'warn' | 'error';
  text: string;
};

type UploadState = {
  name: string;
  mimeType: string;
  dataUrl: string;
};

type ConversationFileState = UploadState & {
  localId: string;
  fileId?: string | null;
  status: 'pending' | 'uploading' | 'uploaded' | 'error';
  errorMessage?: string | null;
};

const POLL_INTERVAL_MS = 1200;
const CONVERSATION_FILE_ACCEPT = '.pdf,.txt,.md,.markdown,.json,image/*,audio/*';
const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const createConversationFileLocalId = () =>
  `draft-file-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

const summarizeModeRequest = (
  mode: PlaygroundMode,
  input: string,
  modeState: ModelTesterModeState,
  videoAction: 'get' | 'delete',
): string => {
  if (mode === 'embeddings') return input.trim() || modeState.embeddingsInput.trim() || 'Embedding request';
  if (mode === 'search') return input.trim() || modeState.searchQuery.trim() || 'Search request';
  if (mode === 'images.generate' || mode === 'images.edit') return input.trim() || modeState.imagesPrompt.trim() || 'Image request';
  if (mode === 'videos.create') return input.trim() || modeState.videosPrompt.trim() || 'Video request';
  if (mode === 'videos.inspect') {
    const id = input.trim() || modeState.videosInspectId.trim();
    return `${videoAction.toUpperCase()} ${id || 'video'}`;
  }
  return input.trim();
};

const readFileAsDataUrl = (file: File): Promise<string> => new Promise((resolve, reject) => {
  const reader = new FileReader();
  reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '');
  reader.onerror = () => reject(reader.error || new Error('读取文件失败'));
  reader.readAsDataURL(file);
});

const formatJson = (value: unknown): string => {
  if (typeof value === 'string') {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
};

const extractErrorMessage = (error: unknown): string => {
  const data = error as any;
  return data?.error?.message || data?.message || 'request failed';
};

const extractClaudeMessageContent = (result: any): { content: string; reasoningContent: string } => {
  const blocks = Array.isArray(result?.content) ? result.content : [];
  const contentParts: string[] = [];
  const reasoningParts: string[] = [];

  for (const block of blocks) {
    if (!block || typeof block !== 'object') continue;
    if (block.type === 'text' && typeof block.text === 'string') {
      contentParts.push(block.text);
      continue;
    }
    if (block.type === 'thinking' && typeof block.thinking === 'string') {
      reasoningParts.push(block.thinking);
      continue;
    }
    if (typeof block.text === 'string') {
      contentParts.push(block.text);
    }
  }

  return {
    content: contentParts.join(''),
    reasoningContent: reasoningParts.join('\n\n'),
  };
};

const extractResponsesContent = (result: any): { content: string; reasoningContent: string } => {
  const contentParts: string[] = [];
  const reasoningParts: string[] = [];

  const pushContent = (value: unknown) => {
    if (typeof value === 'string' && value.length > 0) contentParts.push(value);
  };
  const pushReasoning = (value: unknown) => {
    if (typeof value === 'string' && value.length > 0) reasoningParts.push(value);
  };

  const directOutputText = result?.output_text;
  if (typeof directOutputText === 'string') {
    pushContent(directOutputText);
  } else if (Array.isArray(directOutputText)) {
    for (const item of directOutputText) {
      if (typeof item === 'string') {
        pushContent(item);
        continue;
      }
      if (item && typeof item === 'object' && typeof (item as any).text === 'string') {
        pushContent((item as any).text);
      }
    }
  }

  const outputs = Array.isArray(result?.output)
    ? result.output
    : (result && typeof result === 'object' && (Array.isArray(result?.content) || typeof result?.type === 'string'))
      ? [result]
      : [];
  for (const item of outputs) {
    if (!item || typeof item !== 'object') continue;
    const itemType = typeof item.type === 'string' ? item.type : '';

    if (itemType === 'output_text') {
      pushContent(item.text);
      continue;
    }

    if (itemType === 'reasoning') {
      if (typeof item.summary_text === 'string') pushReasoning(item.summary_text);
      if (typeof item.reasoning === 'string') pushReasoning(item.reasoning);
      if (Array.isArray(item.summary)) {
        for (const summaryItem of item.summary) {
          if (summaryItem && typeof summaryItem === 'object' && typeof (summaryItem as any).text === 'string') {
            pushReasoning((summaryItem as any).text);
          }
        }
      }
    }

    const content = Array.isArray((item as any).content) ? (item as any).content : [];
    for (const block of content) {
      if (!block || typeof block !== 'object') continue;
      const blockType = typeof (block as any).type === 'string' ? (block as any).type : '';
      if (blockType === 'output_text' || blockType === 'text') {
        pushContent((block as any).text);
        continue;
      }
      if (blockType.includes('reasoning')) {
        pushReasoning((block as any).text);
      }
    }
  }

  return {
    content: contentParts.join(''),
    reasoningContent: reasoningParts.join('\n\n'),
  };
};

const extractAssistantResult = (result: unknown): { content: string; reasoningContent: string } => {
  const data = result as any;
  let content = '';
  let reasoning = '';

  if (Array.isArray(data?.choices)) {
    const choice = data.choices[0];
    const maybeContent = choice?.message?.content ?? choice?.text ?? '';
    content = typeof maybeContent === 'string'
      ? maybeContent
      : Array.isArray(maybeContent)
        ? maybeContent
          .map((item) => item?.text ?? '')
          .join('')
        : '';
    reasoning = choice?.message?.reasoning_content || choice?.message?.reasoning || '';
  } else if (data?.type === 'message' && Array.isArray(data?.content)) {
    const parsedClaude = extractClaudeMessageContent(data);
    content = parsedClaude.content;
    reasoning = parsedClaude.reasoningContent;
  } else if (data?.object === 'response' || Array.isArray(data?.output) || typeof data?.output_text === 'string') {
    const parsedResponses = extractResponsesContent(data);
    content = parsedResponses.content;
    reasoning = parsedResponses.reasoningContent;
  } else if (Array.isArray(data?.candidates)) {
    const parts = data?.candidates?.[0]?.content?.parts;
    if (Array.isArray(parts)) {
      content = parts
        .filter((item: any) => !(item?.thought === true))
        .map((item: any) => (typeof item?.text === 'string' ? item.text : ''))
        .join('');
      reasoning = parts
        .filter((item: any) => item?.thought === true)
        .map((item: any) => (typeof item?.text === 'string' ? item.text : ''))
        .join('');
    }
  }

  const processed = processThinkTags(content, reasoning);

  if (!processed.content && processed.reasoningContent) {
    return {
      content: '[Only reasoning returned]',
      reasoningContent: processed.reasoningContent,
    };
  }
  if (!processed.content && !processed.reasoningContent) {
    return {
      content: formatJson(result),
      reasoningContent: '',
    };
  }

  return processed;
};

const replaceMessageAt = (messages: ChatMessage[], index: number, nextMessage: ChatMessage): ChatMessage[] => [
  ...messages.slice(0, index),
  nextMessage,
  ...messages.slice(index + 1),
];

const applyAssistantSuccess = (messages: ChatMessage[], result: unknown): ChatMessage[] => {
  const { content, reasoningContent } = extractAssistantResult(result);
  const targetIndex = findLastLoadingAssistantIndex(messages);

  if (targetIndex === -1) {
    return [...messages, createMessage('assistant', content, {
      status: MESSAGE_STATUS.COMPLETE,
      reasoningContent: reasoningContent || null,
      isThinkingComplete: true,
      isReasoningExpanded: false,
      hasAutoCollapsed: true,
    })];
  }

  const current = messages[targetIndex];
  return replaceMessageAt(messages, targetIndex, {
    ...current,
    content,
    reasoningContent: reasoningContent || null,
    status: MESSAGE_STATUS.COMPLETE,
    isThinkingComplete: true,
    isReasoningExpanded: false,
    hasAutoCollapsed: true,
  });
};

const applyAssistantError = (messages: ChatMessage[], errorMessage: string): ChatMessage[] => {
  const targetIndex = findLastLoadingAssistantIndex(messages);
  if (targetIndex === -1) {
    return [...messages, createMessage('assistant', errorMessage, {
      status: MESSAGE_STATUS.ERROR,
      isThinkingComplete: true,
    })];
  }

  const current = messages[targetIndex];
  return replaceMessageAt(messages, targetIndex, {
    ...current,
    content: errorMessage,
    status: MESSAGE_STATUS.ERROR,
    isThinkingComplete: true,
  });
};

const applyAssistantStopped = (messages: ChatMessage[]): ChatMessage[] => {
  const targetIndex = findLastLoadingAssistantIndex(messages);
  if (targetIndex === -1) return messages;

  const current = messages[targetIndex];
  return replaceMessageAt(messages, targetIndex, finalizeIncompleteMessage({
    ...current,
    content: current.content || 'Generation stopped.',
  }));
};

const applyAssistantDelta = (
  messages: ChatMessage[],
  delta: { contentDelta?: string; reasoningDelta?: string },
): ChatMessage[] => {
  const targetIndex = findLastLoadingAssistantIndex(messages);
  if (targetIndex === -1) return messages;

  const current = messages[targetIndex];
  let next: ChatMessage = {
    ...current,
    status: MESSAGE_STATUS.INCOMPLETE,
  };

  const toIncrementalText = (existingText: string, incomingText?: string): string => {
    if (!incomingText) return '';
    if (!existingText) return incomingText;

    if (incomingText === existingText) return '';
    if (incomingText.startsWith(existingText)) {
      return incomingText.slice(existingText.length);
    }
    if (existingText.endsWith(incomingText)) return '';

    const maxOverlap = Math.min(existingText.length, incomingText.length);
    const MIN_OVERLAP = 8;
    for (let overlap = maxOverlap; overlap >= MIN_OVERLAP; overlap -= 1) {
      if (existingText.slice(-overlap) === incomingText.slice(0, overlap)) {
        return incomingText.slice(overlap);
      }
    }

    return incomingText;
  };

  if (delta.reasoningDelta) {
    const existingReasoning = next.reasoningContent || '';
    const reasoningAppend = toIncrementalText(existingReasoning, delta.reasoningDelta);
    if (reasoningAppend) {
      next = {
        ...next,
        reasoningContent: existingReasoning + reasoningAppend,
        isThinkingComplete: false,
      };
    }
  }

  if (delta.contentDelta) {
    const existingContent = next.content || '';
    const contentAppend = toIncrementalText(existingContent, delta.contentDelta);
    if (!contentAppend) {
      return replaceMessageAt(messages, targetIndex, next);
    }

    const hasReasoning = Boolean(next.reasoningContent);
    const shouldAutoCollapse = hasReasoning && !next.hasAutoCollapsed;
    next = {
      ...next,
      content: existingContent + contentAppend,
      isReasoningExpanded: shouldAutoCollapse ? false : next.isReasoningExpanded,
      hasAutoCollapsed: shouldAutoCollapse || next.hasAutoCollapsed,
    };
  }

  return replaceMessageAt(messages, targetIndex, next);
};

const parseStreamErrorText = async (response: Response): Promise<string> => {
  try {
    const text = await response.text();
    if (!text) return `HTTP ${response.status}`;
    try {
      const parsed = JSON.parse(text);
      return extractErrorMessage(parsed);
    } catch {
      return text;
    }
  } catch {
    return `HTTP ${response.status}`;
  }
};

const parseSseBlock = (block: string): { event: string; data: string | null } => {
  const lines = block.split(/\r?\n/);
  let event = 'message';
  const dataLines: string[] = [];

  for (const line of lines) {
    if (line.startsWith('event:')) {
      event = line.slice(6).trim();
      continue;
    }
    if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trimStart());
    }
  }

  return {
    event,
    data: dataLines.length > 0 ? dataLines.join('\n') : null,
  };
};

const parseAnyStreamDelta = (eventPayload: any): {
  contentDelta?: string;
  reasoningDelta?: string;
  done?: boolean;
} => {
  if (!eventPayload || typeof eventPayload !== 'object') return {};

  if (Array.isArray(eventPayload.choices)) {
    const choice = eventPayload.choices[0];
    const delta = choice?.delta || {};
    const reasoningDelta = typeof delta.reasoning_content === 'string'
      ? delta.reasoning_content
      : typeof delta.reasoning === 'string'
        ? delta.reasoning
        : '';
    const contentDelta = typeof delta.content === 'string'
      ? delta.content
      : typeof choice?.message?.content === 'string'
        ? choice.message.content
        : '';

    return {
      contentDelta: contentDelta || undefined,
      reasoningDelta: reasoningDelta || undefined,
      done: Boolean(choice?.finish_reason),
    };
  }

  if (typeof eventPayload.type === 'string') {
    // Responses stream emits a full-text summary again in several "done" events
    // (output_text.done/content_part.done/output_item.done/response.completed).
    // Treat those as structural events only; otherwise UI appends duplicate text.
    if (eventPayload.type === 'response.output_item.added' || eventPayload.type === 'response.output_item.done') {
      return {};
    }

    if (eventPayload.type === 'response.content_part.added' || eventPayload.type === 'response.content_part.done') {
      return {};
    }

    if (eventPayload.type === 'response.content_part.delta') {
      const delta = eventPayload.delta;
      if (typeof delta === 'string') return { contentDelta: delta || undefined };
      if (delta && typeof delta === 'object') {
        const parsed = extractResponsesContent(delta);
        if (parsed.content || parsed.reasoningContent) {
          return {
            contentDelta: parsed.content || undefined,
            reasoningDelta: parsed.reasoningContent || undefined,
          };
        }
        const text = typeof (delta as any).text === 'string' ? (delta as any).text : '';
        return { contentDelta: text || undefined };
      }
    }

    if (eventPayload.type === 'response.output_text.delta') {
      const text = typeof eventPayload.delta === 'string'
        ? eventPayload.delta
        : typeof eventPayload.text === 'string'
          ? eventPayload.text
          : '';
      return { contentDelta: text || undefined };
    }

    if (eventPayload.type === 'response.reasoning_summary_text.delta' || eventPayload.type === 'response.reasoning.delta') {
      const text = typeof eventPayload.delta === 'string'
        ? eventPayload.delta
        : typeof eventPayload.text === 'string'
          ? eventPayload.text
          : '';
      return { reasoningDelta: text || undefined };
    }

    if (eventPayload.type === 'response.output_text.done') return {};

    if (eventPayload.type === 'response.completed' || eventPayload.type === 'response.failed') {
      return { done: true };
    }

    if (eventPayload.type === 'content_block_delta') {
      const delta = eventPayload.delta || {};
      const deltaType = typeof delta.type === 'string' ? delta.type : '';
      const text = typeof delta.text === 'string' ? delta.text : '';
      if (deltaType === 'thinking_delta') {
        return { reasoningDelta: text || undefined };
      }
      return { contentDelta: text || undefined };
    }

    if (eventPayload.type === 'content_block_start') {
      const block = eventPayload.content_block || {};
      const text = typeof block.text === 'string' ? block.text : '';
      return { contentDelta: text || undefined };
    }

    if (eventPayload.type === 'message_delta') {
      const stopReason = eventPayload?.delta?.stop_reason || eventPayload?.stop_reason;
      return { done: Boolean(stopReason) };
    }

    if (eventPayload.type === 'message_stop') {
      return { done: true };
    }
  }

  if (Array.isArray(eventPayload.candidates)) {
    const parts = eventPayload?.candidates?.[0]?.content?.parts;
    if (Array.isArray(parts)) {
      const reasoningDelta = parts
        .filter((item: any) => item?.thought === true)
        .map((item: any) => (typeof item?.text === 'string' ? item.text : ''))
        .join('');
      const contentDelta = parts
        .filter((item: any) => !(item?.thought === true))
        .map((item: any) => (typeof item?.text === 'string' ? item.text : ''))
        .join('');
      return {
        contentDelta: contentDelta || undefined,
        reasoningDelta: reasoningDelta || undefined,
        done: Boolean(eventPayload?.candidates?.[0]?.finishReason),
      };
    }
  }

  return {};
};

const toNumber = (value: string, fallback: number): number => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const splitCsvOrLines = (value: string): string[] =>
  value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);

const CONVERSATION_MODE_OPTIONS: Array<{ value: PlaygroundMode; label: string }> = [
  { value: 'conversation', label: '对话' },
  { value: 'embeddings', label: 'Embeddings' },
  { value: 'search', label: 'Search' },
  { value: 'images.generate', label: '图片生成' },
  { value: 'images.edit', label: '图片编辑' },
  { value: 'videos.create', label: '视频创建' },
  { value: 'videos.inspect', label: '视频查询/删除' },
];

const PROTOCOL_OPTIONS: Array<{ value: PlaygroundProtocol; label: string }> = [
  { value: 'openai', label: 'OpenAI (/v1/chat/completions)' },
  { value: 'responses', label: 'OpenAI Responses (/v1/responses)' },
  { value: 'claude', label: 'Claude (/v1/messages)' },
  { value: 'gemini', label: 'Gemini Native (/gemini/v1beta/models/*)' },
];

const inputBaseStyle: React.CSSProperties = {
  width: '100%',
  padding: '10px 14px',
  border: '1px solid var(--color-border)',
  borderRadius: 'var(--radius-sm)',
  fontSize: 13,
  outline: 'none',
  background: 'var(--color-bg)',
  color: 'var(--color-text-primary)',
  transition: 'border-color 0.2s',
};

function ParameterRow(props: {
  title: string;
  valueText?: string;
  enabled: boolean;
  onToggle: () => void;
  disabled?: boolean;
  children: React.ReactNode;
}) {
  const {
    title,
    valueText,
    enabled,
    onToggle,
    disabled,
    children,
  } = props;
  return (
    <div style={{ marginBottom: 12, opacity: enabled ? 1 : 0.55 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <div style={{ fontSize: 13, fontWeight: 600 }}>
          {title}
          {valueText && <span style={{ marginLeft: 6, color: 'var(--color-primary)' }}>{valueText}</span>}
        </div>
        <label style={{ fontSize: 12 }}>
          <input type="checkbox" checked={enabled} onChange={onToggle} disabled={disabled} /> 启用
        </label>
      </div>
      {children}
    </div>
  );
}

export default function ModelTester() {
  const [models, setModels] = useState<string[]>([]);
  const [modelSearch, setModelSearch] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [inputs, setInputs] = useState<ModelTesterInputs>(DEFAULT_INPUTS);
  const [modeState, setModeState] = useState<ModelTesterModeState>(DEFAULT_MODE_STATE);
  const [parameterEnabled, setParameterEnabled] = useState<ParameterEnabled>(DEFAULT_PARAMETER_ENABLED);

  const [sending, setSending] = useState(false);
  const [loadingModels, setLoadingModels] = useState(true);
  const [error, setError] = useState('');
  const [pendingPayload, setPendingPayload] = useState<TestChatPayload | null>(null);
  const [pendingJobId, setPendingJobId] = useState<string | null>(null);

  const [customRequestMode, setCustomRequestMode] = useState(false);
  const [customRequestBody, setCustomRequestBody] = useState('');
  const [showDebugPanel, setShowDebugPanel] = useState(false);
  const debugPanelPresence = useAnimatedVisibility(showDebugPanel, 220);
  const [activeDebugTab, setActiveDebugTab] = useState<DebugTab>(DEBUG_TABS.PREVIEW);
  const [debugRequest, setDebugRequest] = useState('');
  const [debugResponse, setDebugResponse] = useState('');
  const [debugPreview, setDebugPreview] = useState('');
  const [debugTimeline, setDebugTimeline] = useState<DebugTimelineEntry[]>([]);
  const [debugTimestamp, setDebugTimestamp] = useState('');
  const [nonConversationResult, setNonConversationResult] = useState<unknown>(null);

  const [searchQueryValue, setSearchQueryValue] = useState('');
  const [searchAllowedDomains, setSearchAllowedDomains] = useState('');
  const [searchBlockedDomains, setSearchBlockedDomains] = useState('');
  const [searchMaxResults, setSearchMaxResults] = useState(10);
  const [embeddingInputText, setEmbeddingInputText] = useState('');
  const [assetPrompt, setAssetPrompt] = useState('');
  const [videoInspectId, setVideoInspectId] = useState('');
  const [videoInspectAction, setVideoInspectAction] = useState<'GET' | 'DELETE'>('GET');
  const [imageSourceFile, setImageSourceFile] = useState<UploadState | null>(null);
  const [imageMaskFile, setImageMaskFile] = useState<UploadState | null>(null);
  const [conversationFiles, setConversationFiles] = useState<ConversationFileState[]>([]);

  const [editingMessageId, setEditingMessageId] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const chatEndRef = useRef<HTMLDivElement>(null);
  const conversationFileInputRef = useRef<HTMLInputElement>(null);
  const restoredSessionRef = useRef<ReturnType<typeof parseModelTesterSession>>(null);
  const streamAbortRef = useRef<AbortController | null>(null);
  const streamStopRequestedRef = useRef(false);

  const pushDebug = useCallback((level: DebugTimelineEntry['level'], text: string) => {
    const now = new Date().toISOString();
    setDebugTimeline((prev) => {
      const next = [...prev, { at: now, level, text }];
      return next.length > 200 ? next.slice(next.length - 200) : next;
    });
    setDebugTimestamp(now);
  }, []);

  const updateInput = useCallback(<K extends keyof ModelTesterInputs>(key: K, value: ModelTesterInputs[K]) => {
    setInputs((prev) => {
      if (key === 'protocol') {
        return {
          ...prev,
          protocol: value as ModelTesterInputs['protocol'],
        };
      }
      return { ...prev, [key]: value };
    });
  }, []);

  const updateModeState = useCallback(<K extends keyof ModelTesterModeState>(key: K, value: ModelTesterModeState[K]) => {
    setModeState((prev) => ({ ...prev, [key]: value }));
  }, []);

  const updateProtocol = useCallback((protocol: PlaygroundProtocol) => {
    setInputs((prev) => ({
      ...prev,
      protocol,
    }));
  }, []);

  const toggleParameter = useCallback((key: keyof ParameterEnabled) => {
    setParameterEnabled((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);

  useEffect(() => {
    const restored = parseModelTesterSession(localStorage.getItem(MODEL_TESTER_STORAGE_KEY));
    restoredSessionRef.current = restored;
    if (!restored) return;

    setMessages(restored.messages);
    setInput(restored.input);
    setInputs(restored.inputs);
    setModeState(restored.modeState);
    setParameterEnabled(restored.parameterEnabled);
    setPendingPayload(restored.pendingPayload);
    setPendingJobId(restored.pendingJobId || null);
    setCustomRequestMode(restored.customRequestMode);
    setCustomRequestBody(restored.customRequestBody);
    setShowDebugPanel(restored.showDebugPanel);
    setActiveDebugTab(restored.activeDebugTab);
    setEmbeddingInputText(restored.modeState.embeddingsInput);
    setSearchQueryValue(restored.modeState.searchQuery);
    setSearchAllowedDomains(restored.modeState.searchAllowedDomains);
    setSearchBlockedDomains(restored.modeState.searchBlockedDomains);
    setAssetPrompt(restored.modeState.imagesPrompt || restored.modeState.videosPrompt);
    setVideoInspectId(restored.modeState.videosInspectId);
    setVideoInspectAction(restored.inputs.videoInspectAction === 'delete' ? 'DELETE' : 'GET');

    if (restored.pendingJobId) {
      setSending(true);
      setError('发现未完成的任务，正在重新连接...');
      pushDebug('info', `恢复任务 ${restored.pendingJobId}。`);
    } else if (restored.pendingPayload) {
      setError('发现未完成的请求快照，点击重试继续。');
      pushDebug('warn', '恢复待处理的请求快照。');
    }
  }, [pushDebug]);

  useEffect(() => {
    const fetchModels = async () => {
      setLoadingModels(true);
      try {
        const [marketResult, routesResult] = await Promise.allSettled([
          api.getModelsMarketplace({ includePricing: false }),
          api.getRoutes(),
        ]);

        if (marketResult.status === 'rejected' && routesResult.status === 'rejected') {
          throw marketResult.reason || routesResult.reason || new Error('failed to fetch models');
        }

        const names = collectModelTesterModelNames(
          marketResult.status === 'fulfilled' ? marketResult.value : null,
          routesResult.status === 'fulfilled' ? routesResult.value : null,
        );
        setModels(names);

        const restoredModel = restoredSessionRef.current?.inputs.model || '';
        const currentModel = inputs.model || '';
        const nextModel = restoredModel && names.includes(restoredModel)
          ? restoredModel
          : currentModel && names.includes(currentModel)
            ? currentModel
            : names[0] || '';

        if (nextModel) {
          setInputs((prev) => ({ ...prev, model: nextModel }));
        }
      } catch {
        setError('加载模型列表失败。');
        pushDebug('error', '获取模型列表失败。');
      } finally {
        setLoadingModels(false);
      }
    };

    void fetchModels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!inputs.model) return;
    localStorage.setItem(MODEL_TESTER_STORAGE_KEY, serializeModelTesterSession({
      input,
      inputs,
      parameterEnabled,
      messages,
      modeState: {
        embeddingsInput: embeddingInputText,
        searchQuery: searchQueryValue,
        searchAllowedDomains,
        searchBlockedDomains,
        imagesPrompt: inputs.mode === 'images.generate' || inputs.mode === 'images.edit' ? assetPrompt : '',
        imagesMaskDataUrl: imageMaskFile?.dataUrl || '',
        videosPrompt: inputs.mode === 'videos.create' ? assetPrompt : '',
        videosInspectId: videoInspectId,
        extraJson: customRequestBody,
      },
      pendingPayload,
      pendingJobId,
      customRequestMode,
      customRequestBody,
      showDebugPanel,
      activeDebugTab,
    }));
  }, [
    activeDebugTab,
    customRequestBody,
    customRequestMode,
    input,
    inputs,
    messages,
    assetPrompt,
    customRequestBody,
    embeddingInputText,
    imageMaskFile?.dataUrl,
    parameterEnabled,
    pendingJobId,
    pendingPayload,
    searchAllowedDomains,
    searchBlockedDomains,
    searchQueryValue,
    showDebugPanel,
    videoInspectId,
  ]);

  const handleUploadChange = useCallback(async (
    fileList: FileList | null,
    setter: React.Dispatch<React.SetStateAction<UploadState | null>>,
  ) => {
    const file = fileList?.[0];
    if (!file) {
      setter(null);
      return;
    }

    try {
      const dataUrl = await readFileAsDataUrl(file);
      setter({
        name: file.name,
        mimeType: file.type || 'application/octet-stream',
        dataUrl,
      });
    } catch (readError: any) {
      setError(readError?.message || '读取文件失败');
    }
  }, []);

  const handleConversationFilesChange = useCallback(async (fileList: FileList | null) => {
    const files = Array.from(fileList || []);
    if (files.length <= 0) return;

    try {
      const nextFiles = await Promise.all(files.map(async (file) => ({
        localId: createConversationFileLocalId(),
        name: file.name,
        mimeType: file.type || 'application/octet-stream',
        dataUrl: await readFileAsDataUrl(file),
        fileId: null,
        status: 'pending' as const,
        errorMessage: null,
      })));
      setConversationFiles((prev) => [...prev, ...nextFiles]);
      pushDebug('info', `已添加 ${nextFiles.length} 个会话附件。`);
    } catch (readError: any) {
      const message = readError?.message || '读取附件失败';
      setError(message);
      pushDebug('error', message);
    }
  }, [pushDebug]);

  const removeConversationFile = useCallback((localId: string) => {
    if (sending) return;
    setConversationFiles((prev) => prev.filter((item) => item.localId !== localId));
  }, [sending]);

  const extractUploadedFilesFromMessage = useCallback((message: ChatMessage): ConversationUploadedFile[] => {
    const parts = Array.isArray(message.parts) ? message.parts : [];
    return parts.flatMap((part) => {
      if (part.type !== 'input_file') return [];
      const fileId = typeof part.fileId === 'string' ? part.fileId.trim() : '';
      if (!fileId) return [];
      return [{
        fileId,
        filename: typeof part.filename === 'string' && part.filename.trim() ? part.filename.trim() : null,
        mimeType: typeof part.mimeType === 'string' && part.mimeType.trim() ? part.mimeType.trim() : null,
      }];
    });
  }, []);

  const uploadConversationFiles = useCallback(async (): Promise<ConversationUploadedFile[]> => {
    if (conversationFiles.length <= 0) return [];

    const uploaded: ConversationUploadedFile[] = [];
    for (const item of conversationFiles) {
      if (item.fileId) {
        uploaded.push({
          fileId: item.fileId,
          filename: item.name,
          mimeType: item.mimeType,
        });
        continue;
      }

      setConversationFiles((prev) => prev.map((entry) => (
        entry.localId === item.localId
          ? { ...entry, status: 'uploading', errorMessage: null }
          : entry
      )));
      pushDebug('info', `正在上传附件：${item.name}`);

      try {
        const result = await api.proxyTest(buildFileUploadRequestEnvelope({
          name: item.name,
          mimeType: item.mimeType,
          dataUrl: item.dataUrl,
        })) as { id?: unknown; filename?: unknown; mime_type?: unknown };
        const fileId = typeof result?.id === 'string' ? result.id.trim() : '';
        if (!fileId) {
          throw new Error('上传成功但未返回 file_id');
        }
        const filename = typeof result?.filename === 'string' && result.filename.trim()
          ? result.filename.trim()
          : item.name;
        const mimeType = typeof result?.mime_type === 'string' && result.mime_type.trim()
          ? result.mime_type.trim()
          : item.mimeType;

        setConversationFiles((prev) => prev.map((entry) => (
          entry.localId === item.localId
            ? { ...entry, fileId, name: filename, mimeType, status: 'uploaded', errorMessage: null }
            : entry
        )));
        uploaded.push({ fileId, filename, mimeType });
        pushDebug('info', `附件上传完成：${filename} -> ${fileId}`);
      } catch (uploadError: any) {
        const message = uploadError?.message || '附件上传失败';
        setConversationFiles((prev) => prev.map((entry) => (
          entry.localId === item.localId
            ? { ...entry, status: 'error', errorMessage: message }
            : entry
        )));
        throw new Error(`${item.name}: ${message}`);
      }
    }

    return uploaded;
  }, [conversationFiles, pushDebug]);

  const buildConversationMessagesWithSystem = useCallback((baseMessages: ChatMessage[]) => {
    if (!inputs.systemPrompt.trim()) return baseMessages;
    return [
      createMessage('system', inputs.systemPrompt.trim()),
      ...baseMessages,
    ];
  }, [inputs.systemPrompt]);

  const buildClaudeBodyFromMessages = useCallback((baseMessages: ChatMessage[]) => {
    const effectiveMessages = buildConversationMessagesWithSystem(baseMessages);
    const systemContents = effectiveMessages
      .filter((message) => message.role === 'system' || message.role === 'developer')
      .map((message) => message.content.trim())
      .filter(Boolean);
    const downstreamMessages = effectiveMessages
      .filter((message) => message.role !== 'system' && message.role !== 'developer')
      .map((message) => ({
        role: message.role === 'assistant' ? 'assistant' : 'user',
        content: message.content,
      }));

    return {
      model: inputs.model,
      stream: inputs.stream,
      max_tokens: parameterEnabled.max_tokens ? inputs.max_tokens : DEFAULT_INPUTS.max_tokens,
      ...(systemContents.length > 0 ? { system: systemContents.join('\n\n') } : {}),
      ...(parameterEnabled.temperature ? { temperature: inputs.temperature } : {}),
      ...(parameterEnabled.top_p ? { top_p: inputs.top_p } : {}),
      messages: downstreamMessages,
    };
  }, [buildConversationMessagesWithSystem, inputs.max_tokens, inputs.model, inputs.stream, inputs.temperature, inputs.top_p, parameterEnabled.max_tokens, parameterEnabled.temperature, parameterEnabled.top_p]);

  const buildResponsesBodyFromMessages = useCallback((baseMessages: ChatMessage[]) => {
    const effectiveMessages = buildConversationMessagesWithSystem(baseMessages);
    const systemContents = effectiveMessages
      .filter((message) => message.role === 'system' || message.role === 'developer')
      .map((message) => message.content.trim())
      .filter(Boolean);
    const downstreamMessages = effectiveMessages
      .filter((message) => message.role !== 'system' && message.role !== 'developer')
      .map((message) => ({
        role: message.role === 'assistant' ? 'assistant' : 'user',
        content: message.content,
      }));

    return {
      model: inputs.model,
      stream: inputs.stream,
      ...(parameterEnabled.temperature ? { temperature: inputs.temperature } : {}),
      ...(parameterEnabled.top_p ? { top_p: inputs.top_p } : {}),
      ...(parameterEnabled.max_tokens ? { max_output_tokens: inputs.max_tokens } : {}),
      ...(systemContents.length > 0 ? { instructions: systemContents.join('\n\n') } : {}),
      input: downstreamMessages.length === 1 && downstreamMessages[0].role === 'user' && systemContents.length === 0
        ? downstreamMessages[0].content
        : downstreamMessages,
    };
  }, [buildConversationMessagesWithSystem, inputs.max_tokens, inputs.model, inputs.stream, inputs.temperature, inputs.top_p, parameterEnabled.max_tokens, parameterEnabled.temperature, parameterEnabled.top_p]);

  const buildConversationProxyEnvelope = useCallback((baseMessages: ChatMessage[]): ProxyTestEnvelope => {
    const normalizedMessages = buildConversationMessagesWithSystem(baseMessages);

    if (customRequestMode) {
      const path = inputs.protocol === 'gemini'
        ? `/gemini/v1beta/models/${encodeURIComponent(inputs.model)}:generateContent${inputs.stream ? '?alt=sse' : ''}`
        : inputs.protocol === 'claude'
          ? '/v1/messages'
          : inputs.protocol === 'responses'
            ? '/v1/responses'
            : '/v1/chat/completions';

      return {
        method: 'POST',
        path,
        requestKind: 'json',
        stream: inputs.stream,
        jobMode: false,
        rawMode: true,
        rawJsonText: customRequestBody,
      };
    }

    if (inputs.protocol === 'claude') {
      return {
        method: 'POST',
        path: '/v1/messages',
        requestKind: 'json',
        stream: inputs.stream,
        jobMode: false,
        rawMode: false,
        jsonBody: buildClaudeBodyFromMessages(baseMessages),
      };
    }

    if (inputs.protocol === 'responses') {
      return {
        method: 'POST',
        path: '/v1/responses',
        requestKind: 'json',
        stream: inputs.stream,
        jobMode: false,
        rawMode: false,
        jsonBody: buildResponsesBodyFromMessages(baseMessages),
      };
    }

    if (inputs.protocol === 'gemini') {
      return buildGeminiNativeConversationProxyEnvelope(baseMessages, inputs, parameterEnabled);
    }

    const openAiEnvelope = buildApiPayload(normalizedMessages, { ...inputs, protocol: 'openai' }, parameterEnabled);
    const openAiPayload = (openAiEnvelope.jsonBody && typeof openAiEnvelope.jsonBody === 'object')
      ? { ...(openAiEnvelope.jsonBody as Record<string, unknown>) }
      : {};

    return {
      method: 'POST',
      path: '/v1/chat/completions',
      requestKind: 'json',
      stream: inputs.stream,
      jobMode: false,
      rawMode: false,
      jsonBody: openAiPayload,
    };
  }, [buildApiPayload, buildClaudeBodyFromMessages, buildConversationMessagesWithSystem, buildResponsesBodyFromMessages, customRequestBody, customRequestMode, inputs, parameterEnabled]);

  const buildModeProxyEnvelope = useCallback((): ProxyTestEnvelope | null => {
    if (inputs.mode === 'embeddings') {
      const trimmed = embeddingInputText.trim();
      if (!trimmed) return null;
      return {
        method: 'POST',
        path: '/v1/embeddings',
        requestKind: 'json',
        stream: false,
        jobMode: false,
        rawMode: customRequestMode,
        ...(customRequestMode
          ? { rawJsonText: customRequestBody }
          : { jsonBody: { model: inputs.model, input: trimmed } }),
      };
    }

    if (inputs.mode === 'search') {
      if (!searchQueryValue.trim()) return null;
      return {
        method: 'POST',
        path: '/v1/search',
        requestKind: 'json',
        stream: false,
        jobMode: false,
        rawMode: customRequestMode,
        ...(customRequestMode
          ? { rawJsonText: customRequestBody }
          : {
            jsonBody: {
              model: inputs.model || '__search',
              query: searchQueryValue.trim(),
              max_results: Math.max(1, Math.min(20, Math.trunc(searchMaxResults || 10))),
              ...(splitCsvOrLines(searchAllowedDomains).length > 0 ? { allowed_domains: splitCsvOrLines(searchAllowedDomains) } : {}),
              ...(splitCsvOrLines(searchBlockedDomains).length > 0 ? { blocked_domains: splitCsvOrLines(searchBlockedDomains) } : {}),
            },
          }),
      };
    }

    if (inputs.mode === 'images.generate') {
      if (!assetPrompt.trim()) return null;
      return {
        method: 'POST',
        path: '/v1/images/generations',
        requestKind: 'json',
        stream: false,
        jobMode: false,
        rawMode: customRequestMode,
        ...(customRequestMode
          ? { rawJsonText: customRequestBody }
          : { jsonBody: { model: inputs.model, prompt: assetPrompt.trim() } }),
      };
    }

    if (inputs.mode === 'images.edit') {
      if (!assetPrompt.trim() || !imageSourceFile) return null;
      return {
        method: 'POST',
        path: '/v1/images/edits',
        requestKind: 'multipart',
        stream: false,
        jobMode: false,
        rawMode: false,
        multipartFields: {
          model: inputs.model,
          prompt: assetPrompt.trim(),
        },
        multipartFiles: [
          {
            field: 'image',
            name: imageSourceFile.name,
            mimeType: imageSourceFile.mimeType,
            dataUrl: imageSourceFile.dataUrl,
          },
          ...(imageMaskFile ? [{
            field: 'mask',
            name: imageMaskFile.name,
            mimeType: imageMaskFile.mimeType,
            dataUrl: imageMaskFile.dataUrl,
          }] : []),
        ],
      };
    }

    if (inputs.mode === 'videos.create') {
      if (!assetPrompt.trim()) return null;
      if (imageSourceFile) {
        return {
          method: 'POST',
          path: '/v1/videos',
          requestKind: 'multipart',
          stream: false,
          jobMode: false,
          rawMode: false,
          multipartFields: {
            model: inputs.model,
            prompt: assetPrompt.trim(),
          },
          multipartFiles: [
            {
              field: 'input_reference',
              name: imageSourceFile.name,
              mimeType: imageSourceFile.mimeType,
              dataUrl: imageSourceFile.dataUrl,
            },
          ],
        };
      }

      return {
        method: 'POST',
        path: '/v1/videos',
        requestKind: 'json',
        stream: false,
        jobMode: false,
        rawMode: customRequestMode,
        ...(customRequestMode
          ? { rawJsonText: customRequestBody }
          : { jsonBody: { model: inputs.model, prompt: assetPrompt.trim() } }),
      };
    }

    if (inputs.mode === 'videos.inspect') {
      if (!videoInspectId.trim()) return null;
      return {
        method: videoInspectAction,
        path: `/v1/videos/${encodeURIComponent(videoInspectId.trim())}`,
        requestKind: 'empty',
        stream: false,
        jobMode: false,
        rawMode: false,
      };
    }

    return null;
  }, [assetPrompt, customRequestBody, customRequestMode, embeddingInputText, imageMaskFile, imageSourceFile, inputs.mode, inputs.model, searchAllowedDomains, searchBlockedDomains, searchMaxResults, searchQueryValue, videoInspectAction, videoInspectId]);

  const previewPayload = useMemo(() => {
    if (inputs.mode !== 'conversation') {
      return buildModeProxyEnvelope();
    }
    if (customRequestMode) {
      const raw = customRequestBody.trim();
      if (!raw) return null;
      try {
        return JSON.parse(raw);
      } catch {
        return { _error: '自定义请求体中的 JSON 无效', raw };
      }
    }
    if (inputs.protocol === 'gemini') {
      return buildConversationProxyEnvelope(messages);
    }
    return buildApiPayload(buildConversationMessagesWithSystem(messages), inputs, parameterEnabled);
  }, [buildConversationMessagesWithSystem, buildConversationProxyEnvelope, buildModeProxyEnvelope, customRequestBody, customRequestMode, inputs, messages, parameterEnabled]);

  useEffect(() => {
    setDebugPreview(formatJson(previewPayload));
  }, [previewPayload]);

  const finalizeJob = useCallback((jobId: string) => {
    void api.deleteProxyTestJob(jobId).catch(() => { });
  }, []);

  useEffect(() => {
    if (!pendingJobId) return;

    let active = true;
    setSending(true);

    const pollTask = async () => {
      while (active) {
        try {
          const status = await api.getProxyTestJob(pendingJobId) as ChatJobResponse;
          if (!active) return;

          if (status.status === 'pending') {
            await wait(POLL_INTERVAL_MS);
            continue;
          }

          if (status.status === 'succeeded') {
            setMessages((prev) => applyAssistantSuccess(prev, status.result));
            setError('');
            setDebugResponse(formatJson(status.result));
            setActiveDebugTab(DEBUG_TABS.RESPONSE);
            pushDebug('info', `任务 ${pendingJobId} 已成功。`);
          } else if (status.status === 'cancelled') {
            setMessages((prev) => applyAssistantStopped(prev));
            setError('生成已取消。');
            setDebugResponse(formatJson(status.error));
            setActiveDebugTab(DEBUG_TABS.RESPONSE);
            pushDebug('warn', `任务 ${pendingJobId} 已取消。`);
          } else {
            const message = extractErrorMessage(status.error);
            setMessages((prev) => applyAssistantError(prev, message));
            setError(message);
            setDebugResponse(formatJson(status.error));
            setActiveDebugTab(DEBUG_TABS.RESPONSE);
            pushDebug('error', `任务 ${pendingJobId} 失败：${message}`);
          }

          setPendingJobId(null);
          setPendingPayload(null);
          setSending(false);
          finalizeJob(pendingJobId);
          return;
        } catch (pollError) {
          const message = (pollError as any)?.message || '未知轮询错误';
          pushDebug('warn', `轮询 ${pendingJobId} 失败一次：${message}`);
          await wait(POLL_INTERVAL_MS);
        }
      }
    };

    void pollTask();
    return () => {
      active = false;
    };
  }, [finalizeJob, pendingJobId, pushDebug]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const turnCount = useMemo(() => countConversationTurns(messages), [messages]);
  const filteredModels = useMemo(
    () => filterModelTesterModelNames(models, modelSearch),
    [modelSearch, models],
  );
  const currentModelVisible = useMemo(
    () => filteredModels.includes(inputs.model),
    [filteredModels, inputs.model],
  );
  const modelCountText = useMemo(() => {
    if (!modelSearch.trim()) return `共 ${models.length} 个模型`;
    return `匹配 ${filteredModels.length} / ${models.length}`;
  }, [filteredModels.length, modelSearch, models.length]);

  const modelSelectOptions = useMemo(
    () => filteredModels.map((item) => ({ value: item, label: item })),
    [filteredModels],
  );
  const conversationFileSupported = inputs.protocol === 'openai' || inputs.protocol === 'responses';
  const canSend = useMemo(() => {
    if (sending || pendingJobId || !inputs.model) return false;
    if (inputs.mode !== 'conversation') {
      if (inputs.mode === 'embeddings') return Boolean(embeddingInputText.trim());
      if (inputs.mode === 'search') return Boolean(searchQueryValue.trim());
      if (inputs.mode === 'images.generate') return Boolean(assetPrompt.trim());
      if (inputs.mode === 'images.edit') return Boolean(assetPrompt.trim()) && Boolean(imageSourceFile);
      if (inputs.mode === 'videos.create') return Boolean(assetPrompt.trim());
      if (inputs.mode === 'videos.inspect') return Boolean(videoInspectId.trim());
      return false;
    }
    const hasPrompt = input.trim().length > 0;
    if (!customRequestMode) return hasPrompt || (conversationFileSupported && conversationFiles.length > 0);
    return hasPrompt || customRequestBody.trim().length > 0;
  }, [assetPrompt, conversationFileSupported, conversationFiles.length, customRequestBody, customRequestMode, embeddingInputText, imageSourceFile, input, inputs.mode, inputs.model, pendingJobId, searchQueryValue, sending, videoInspectId]);

  const startChatJob = useCallback(async (payload: TestChatPayload) => {
    try {
      setError('');
      setPendingPayload(payload);
      const created = await api.startProxyTestJob(payload) as { jobId: string };
      setPendingJobId(created.jobId);
      setSending(true);
      pushDebug('info', `已创建任务 ${created.jobId}。`);
    } catch (e: any) {
      const message = e?.message || '请求失败';
      setMessages((prev) => applyAssistantError(prev, message));
      setError(message);
      setSending(false);
      setDebugResponse(formatJson({ error: { message } }));
      setActiveDebugTab(DEBUG_TABS.RESPONSE);
      pushDebug('error', `创建任务失败：${message}`);
    }
  }, [pushDebug]);

  const startStream = useCallback(async (payload: TestChatPayload) => {
    const controller = new AbortController();
    streamAbortRef.current = controller;
    streamStopRequestedRef.current = false;
    setSending(true);
    setPendingJobId(null);
    setPendingPayload(payload);
    pushDebug('info', '已开始流式请求。');

    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    const rawEvents: string[] = [];
    const appendRawEvent = (raw: string) => {
      rawEvents.push(raw);
      if (rawEvents.length > 500) {
        rawEvents.splice(0, rawEvents.length - 500);
      }
      setDebugResponse(rawEvents.join('\n'));
    };

    try {
      const response = await api.proxyTestStream(payload, controller.signal);
      if (response.status === 401 || response.status === 403) {
        const hadToken = Boolean(getAuthToken(localStorage));
        clearAuthSession(localStorage);
        if (hadToken) window.location.reload();
        throw new Error('会话已过期');
      }
      if (!response.ok) {
        throw new Error(await parseStreamErrorText(response));
      }
      if (!response.body) {
        throw new Error('流式响应体为空');
      }

      setActiveDebugTab(DEBUG_TABS.RESPONSE);
      const reader = response.body.getReader();
      let doneReceived = false;
      let hasAnyContent = false;
      let hasAnyReasoning = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;

        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split(/\r?\n\r?\n/);
        buffer = chunks.pop() || '';

        for (const chunk of chunks) {
          const parsed = parseSseBlock(chunk);
          if (!parsed.data) continue;
          appendRawEvent(parsed.data);

          if (parsed.data === '[DONE]') {
            doneReceived = true;
            pushDebug('info', '收到流式 [DONE] 信号。');
            continue;
          }

          let eventPayload: any;
          try {
            eventPayload = JSON.parse(parsed.data);
          } catch {
            pushDebug('warn', `忽略非 JSON 的 SSE 数据块 (event=${parsed.event})。`);
            continue;
          }

          if (eventPayload?.error) {
            throw new Error(extractErrorMessage(eventPayload));
          }

          const delta = parseAnyStreamDelta(eventPayload);
          if (typeof delta.reasoningDelta === 'string' && delta.reasoningDelta.trim().length > 0) {
            hasAnyReasoning = true;
          }
          if (typeof delta.contentDelta === 'string' && delta.contentDelta.trim().length > 0) {
            hasAnyContent = true;
          }
          if (delta.reasoningDelta || delta.contentDelta) {
            setMessages((prev) => applyAssistantDelta(prev, {
              reasoningDelta: delta.reasoningDelta,
              contentDelta: delta.contentDelta,
            }));
          }
          if (delta.done) doneReceived = true;
        }
      }

      const emptyOutput = !hasAnyContent && !hasAnyReasoning;

      setMessages((prev) => {
        const idx = findLastLoadingAssistantIndex(prev);
        if (idx === -1) return prev;
        const finalized = finalizeIncompleteMessage(prev[idx]);
        if (emptyOutput && !(finalized.content || '').trim() && !(finalized.reasoningContent || '').trim()) {
          return replaceMessageAt(prev, idx, {
            ...finalized,
            content: '空回复（上游未返回任何内容）',
            status: MESSAGE_STATUS.ERROR,
            isThinkingComplete: true,
          });
        }
        return replaceMessageAt(prev, idx, {
          ...finalized,
          status: MESSAGE_STATUS.COMPLETE,
          isThinkingComplete: true,
        });
      });

      setPendingPayload(null);
      if (emptyOutput) {
        const message = '上游返回空内容';
        setError(message);
        pushDebug('error', '流式传输完成但内容为空。');
      } else {
        setError('');
        pushDebug(doneReceived ? 'info' : 'warn', doneReceived
          ? '流式传输已成功完成。'
          : '流式传输未收到 [DONE] 信号，已在本地完成。');
      }
    } catch (streamError: any) {
      const abortedByUser = controller.signal.aborted && streamStopRequestedRef.current;
      const abortedUnexpectedly = controller.signal.aborted
        || streamError?.name === 'AbortError'
        || streamError?.message === 'This operation was aborted'
        || streamError?.message === 'The user aborted a request.';

      if (abortedByUser) {
        setMessages((prev) => applyAssistantStopped(prev));
        setError('生成已停止。');
        pushDebug('warn', '流式传输被用户中止。');
      } else if (abortedUnexpectedly) {
        const message = '流式连接中断，请重试。';
        setMessages((prev) => applyAssistantError(prev, message));
        setError(message);
        pushDebug('error', `流式传输异常中断：${streamError?.message || 'AbortError'}`);
      } else {
        const rawMsg = streamError?.message || '流式请求失败';
        const message = rawMsg === 'This operation was aborted' ? '操作已中止' : rawMsg;
        setMessages((prev) => applyAssistantError(prev, message));
        setError(message);
        pushDebug('error', `流式传输失败：${message}`);
      }
    } finally {
      if (streamAbortRef.current === controller) streamAbortRef.current = null;
      streamStopRequestedRef.current = false;
      setSending(false);
    }
  }, [pushDebug]);

  const startProxyStream = useCallback(async (
    envelope: ProxyTestEnvelope,
    nextMessages: ChatMessage[],
  ) => {
    const controller = new AbortController();
    streamAbortRef.current = controller;
    streamStopRequestedRef.current = false;
    setSending(true);
    setPendingJobId(null);
    setPendingPayload(null);
    setMessages(nextMessages);
    setError('');
    setActiveDebugTab(DEBUG_TABS.RESPONSE);
    pushDebug('info', `已开始代理流式请求：${envelope.path}`);

    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    const rawEvents: string[] = [];
    const appendRawEvent = (raw: string) => {
      rawEvents.push(raw);
      if (rawEvents.length > 500) {
        rawEvents.splice(0, rawEvents.length - 500);
      }
      setDebugResponse(rawEvents.join('\n'));
    };

    try {
      const response = await api.proxyTestStream(envelope, controller.signal);
      if (!response.ok) {
        throw new Error(await parseStreamErrorText(response));
      }
      if (!response.body) {
        throw new Error('流式响应体为空');
      }

      const reader = response.body.getReader();
      let doneReceived = false;
      let hasAnyContent = false;
      let hasAnyReasoning = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;

        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split(/\r?\n\r?\n/);
        buffer = chunks.pop() || '';

        for (const chunk of chunks) {
          const parsed = parseSseBlock(chunk);
          if (!parsed.data) continue;
          appendRawEvent(parsed.data);

          if (parsed.data === '[DONE]') {
            doneReceived = true;
            continue;
          }

          let eventPayload: any;
          try {
            eventPayload = JSON.parse(parsed.data);
          } catch {
            continue;
          }

          if (eventPayload?.error) {
            throw new Error(extractErrorMessage(eventPayload));
          }

          const delta = parseAnyStreamDelta(eventPayload);
          if (typeof delta.reasoningDelta === 'string' && delta.reasoningDelta.trim().length > 0) {
            hasAnyReasoning = true;
          }
          if (typeof delta.contentDelta === 'string' && delta.contentDelta.trim().length > 0) {
            hasAnyContent = true;
          }
          if (delta.reasoningDelta || delta.contentDelta) {
            setMessages((prev) => applyAssistantDelta(prev, {
              reasoningDelta: delta.reasoningDelta,
              contentDelta: delta.contentDelta,
            }));
          }
          if (delta.done) doneReceived = true;
        }
      }

      const emptyOutput = !hasAnyContent && !hasAnyReasoning;

      setMessages((prev) => {
        const idx = findLastLoadingAssistantIndex(prev);
        if (idx === -1) return prev;
        const finalized = finalizeIncompleteMessage(prev[idx]);
        if (emptyOutput && !(finalized.content || '').trim() && !(finalized.reasoningContent || '').trim()) {
          return replaceMessageAt(prev, idx, {
            ...finalized,
            content: '空回复（上游未返回任何内容）',
            status: MESSAGE_STATUS.ERROR,
            isThinkingComplete: true,
          });
        }
        return replaceMessageAt(prev, idx, {
          ...finalized,
          status: MESSAGE_STATUS.COMPLETE,
          isThinkingComplete: true,
        });
      });

      if (emptyOutput) {
        const message = '上游返回空内容';
        setError(message);
        pushDebug('error', '代理流式传输完成但内容为空。');
      } else {
        setError('');
        pushDebug(doneReceived ? 'info' : 'warn', doneReceived
          ? '代理流式传输已成功完成。'
          : '代理流式传输未收到 [DONE] 信号，已在本地完成。');
      }
    } catch (streamError: any) {
      const abortedByUser = controller.signal.aborted && streamStopRequestedRef.current;
      const abortedUnexpectedly = controller.signal.aborted
        || streamError?.name === 'AbortError'
        || streamError?.message === 'This operation was aborted'
        || streamError?.message === 'The user aborted a request.';

      if (abortedByUser) {
        setMessages((prev) => applyAssistantStopped(prev));
        setError('生成已停止。');
      } else if (abortedUnexpectedly) {
        setMessages((prev) => applyAssistantError(prev, '流式连接中断，请重试。'));
        setError('流式连接中断，请重试。');
      } else {
        const message = streamError?.message || '流式请求失败';
        setMessages((prev) => applyAssistantError(prev, message));
        setError(message);
      }
    } finally {
      if (streamAbortRef.current === controller) streamAbortRef.current = null;
      streamStopRequestedRef.current = false;
      setSending(false);
    }
  }, [pushDebug]);

  const dispatchPayload = useCallback(async (
    nextMessages: ChatMessage[],
    payload: TestChatPayload,
    options?: { syncedCustomBody?: string },
  ) => {
    setMessages(nextMessages);
    if (options?.syncedCustomBody !== undefined) {
      setCustomRequestBody(options.syncedCustomBody);
    }
    setError('');
    setPendingPayload(payload);
    setDebugRequest(formatJson(payload));
    setDebugResponse('');
    setActiveDebugTab(DEBUG_TABS.REQUEST);
    setDebugTimestamp(new Date().toISOString());

    if (payload.stream) {
      await startStream(payload);
    } else {
      await startChatJob(payload);
    }
  }, [startChatJob, startStream]);

  const dispatchProxyEnvelope = useCallback(async (envelope: ProxyTestEnvelope, nextMessages?: ChatMessage[]) => {
    setError('');
    setDebugRequest(formatJson(envelope.rawMode ? { path: envelope.path, rawJsonText: envelope.rawJsonText } : envelope));
    setDebugResponse('');
    setActiveDebugTab(DEBUG_TABS.REQUEST);
    setDebugTimestamp(new Date().toISOString());

    if (envelope.stream && nextMessages) {
      await startProxyStream(envelope, nextMessages);
      return;
    }

    setSending(true);
    try {
      const result = await api.proxyTest(envelope);
      setDebugResponse(formatJson(result));
      setActiveDebugTab(DEBUG_TABS.RESPONSE);
      setNonConversationResult(result);

      if (nextMessages) {
        setMessages((prev) => applyAssistantSuccess(nextMessages, result));
      }

      setError('');
      pushDebug('info', `代理请求成功：${envelope.path}`);
    } catch (requestError: any) {
      const message = requestError?.message || '请求失败';
      if (nextMessages) {
        setMessages((prev) => applyAssistantError(nextMessages, message));
      }
      setError(message);
      setDebugResponse(formatJson({ error: { message } }));
      setActiveDebugTab(DEBUG_TABS.RESPONSE);
      pushDebug('error', `代理请求失败：${message}`);
    } finally {
      setSending(false);
    }
  }, [pushDebug, startProxyStream]);

  const buildPayloadWithMessages = useCallback((nextMessages: ChatMessage[]): {
    payload: TestChatPayload | null;
    syncedCustomBody?: string;
  } => {
    const effectiveMessages = buildConversationMessagesWithSystem(nextMessages);
    return {
      payload: customRequestMode
        ? buildRawProxyRequestEnvelope(
          'POST',
          buildConversationProxyEnvelope(effectiveMessages).path,
          'json',
          customRequestBody,
          { stream: inputs.stream, jobMode: !inputs.stream },
        )
        : buildApiPayload(
          effectiveMessages,
          { ...inputs, protocol: inputs.protocol as TestTargetFormat },
          parameterEnabled,
        ),
      syncedCustomBody: customRequestMode
        ? customRequestBody
        : syncMessagesToCustomRequestBody(customRequestBody, effectiveMessages, inputs),
    };
  }, [buildConversationMessagesWithSystem, buildConversationProxyEnvelope, customRequestBody, customRequestMode, inputs, parameterEnabled]);

  const sendWithPrompt = useCallback(async (
    prompt: string,
    baseMessages: ChatMessage[],
    files: ConversationUploadedFile[] = [],
  ) => {
    const userMessage = createConversationUserMessage(prompt, files);
    const loadingAssistant = createLoadingAssistantMessage();
    const nextMessages = [...baseMessages, userMessage, loadingAssistant];
    const useProxyTransport = inputs.protocol === 'gemini' || customRequestMode;
    if (useProxyTransport) {
      await dispatchProxyEnvelope(buildConversationProxyEnvelope(nextMessages), nextMessages);
      return;
    }

    const { payload, syncedCustomBody } = buildPayloadWithMessages(nextMessages);

    if (!payload) {
      setError('自定义请求体无效或不包含消息。');
      pushDebug('error', '从自定义请求体构建请求失败。');
      return;
    }

    await dispatchPayload(nextMessages, payload, { syncedCustomBody });
  }, [buildConversationProxyEnvelope, buildPayloadWithMessages, createConversationUserMessage, customRequestMode, dispatchPayload, dispatchProxyEnvelope, inputs.protocol, pushDebug]);

  const sendModeRequest = useCallback(async () => {
    const envelope = buildModeProxyEnvelope();
    if (!envelope) {
      setError('请先补全当前模式所需的输入。');
      return;
    }
    await dispatchProxyEnvelope(envelope);
  }, [buildModeProxyEnvelope, dispatchProxyEnvelope]);

  const send = useCallback(async () => {
    if (!canSend) return;

    if (inputs.mode !== 'conversation') {
      await sendModeRequest();
      return;
    }

    const trimmed = input.trim();
    if (conversationFiles.length > 0 && customRequestMode) {
      const message = '自定义请求模式不会自动注入会话附件，请先关闭自定义请求模式或移除附件。';
      setError(message);
      pushDebug('warn', message);
      return;
    }

    if (conversationFiles.length > 0 && !conversationFileSupported) {
      const message = '当前协议的会话附件仅支持 OpenAI / Responses；请切换协议或移除附件。';
      setError(message);
      pushDebug('warn', message);
      return;
    }

    if (!customRequestMode && conversationFileSupported && conversationFiles.length > 0) {
      setSending(true);
      try {
        const uploadedFiles = await uploadConversationFiles();
        setInput('');
        setConversationFiles([]);
        await sendWithPrompt(trimmed, messages, uploadedFiles);
      } catch (uploadError: any) {
        const message = uploadError?.message || '附件上传失败';
        setError(message);
        pushDebug('error', message);
        setSending(false);
      }
      return;
    }

    if (trimmed.length > 0) {
      setInput('');
      await sendWithPrompt(trimmed, messages);
      return;
    }

    if (!customRequestMode) return;
    const payload = parseCustomRequestBody(customRequestBody);
    if (!payload) {
      setError('自定义请求体必须是有效的 JSON 且包含非空消息。');
      pushDebug('error', '发送被阻止：无效的自定义请求体。');
      return;
    }

    const nextMessages = [...messages, createLoadingAssistantMessage()];
    await dispatchPayload(
      nextMessages,
      buildRawProxyRequestEnvelope(
        'POST',
        buildConversationProxyEnvelope(nextMessages).path,
        'json',
        customRequestBody,
        { stream: inputs.stream, jobMode: !inputs.stream },
      ),
    );
  }, [canSend, conversationFileSupported, conversationFiles.length, customRequestBody, customRequestMode, dispatchPayload, input, inputs.mode, messages, pushDebug, sendModeRequest, sendWithPrompt, uploadConversationFiles]);

  const retryPending = useCallback(async () => {
    if (sending || pendingJobId || !pendingPayload) return;

    const nextMessages = (() => {
      const copied = [...messages];
      const last = copied[copied.length - 1];
      if (last?.role === 'assistant' && (last.status === MESSAGE_STATUS.ERROR || last.status === MESSAGE_STATUS.COMPLETE)) {
        copied.pop();
      }
      copied.push(createLoadingAssistantMessage());
      return copied;
    })();

    pushDebug('info', '正在重试待处理的请求。');
    await dispatchPayload(nextMessages, pendingPayload);
  }, [dispatchPayload, messages, pendingJobId, pendingPayload, pushDebug, sending]);

  const stopGenerating = useCallback(async () => {
    let hadWork = false;

    if (streamAbortRef.current) {
      hadWork = true;
      streamStopRequestedRef.current = true;
      try {
        streamAbortRef.current.abort();
      } catch {
        // no-op
      }
      streamAbortRef.current = null;
    }

    if (pendingJobId) {
      hadWork = true;
      const jobId = pendingJobId;
      setPendingJobId(null);
      try {
        await api.deleteProxyTestJob(jobId);
      } catch {
        // no-op
      }
    }

    if (!hadWork) return;
    setSending(false);
    setMessages((prev) => applyAssistantStopped(prev));
    setError('生成已停止。');
    pushDebug('warn', '生成已被用户停止。');
  }, [pendingJobId, pushDebug]);

  const clearChat = useCallback(() => {
    if (pendingJobId) {
      void api.deleteProxyTestJob(pendingJobId).catch(() => { });
    }
    if (streamAbortRef.current) {
      streamStopRequestedRef.current = true;
      try {
        streamAbortRef.current.abort();
      } catch {
        // no-op
      }
      streamAbortRef.current = null;
    }

    setMessages([]);
    setPendingPayload(null);
    setPendingJobId(null);
    setInput('');
    setError('');
    setSending(false);
    setEditingMessageId(null);
    setEditValue('');
    setDebugRequest('');
    setDebugResponse('');
    setDebugPreview('');
    setDebugTimeline([]);
    setDebugTimestamp('');
    setNonConversationResult(null);
    setSearchQueryValue('');
    setSearchAllowedDomains('');
    setSearchBlockedDomains('');
    setSearchMaxResults(10);
    setEmbeddingInputText('');
    setAssetPrompt('');
    setVideoInspectId('');
    setVideoInspectAction('GET');
    setImageSourceFile(null);
    setImageMaskFile(null);
    setConversationFiles([]);
    localStorage.removeItem(MODEL_TESTER_STORAGE_KEY);
    pushDebug('info', '对话已清除。');
  }, [pendingJobId, pushDebug]);

  const toggleReasoning = useCallback((messageId: string) => {
    setMessages((prev) => prev.map((message) => {
      if (message.id !== messageId || message.role !== 'assistant') return message;
      return { ...message, isReasoningExpanded: !message.isReasoningExpanded };
    }));
  }, []);

  const copyMessage = useCallback(async (message: ChatMessage) => {
    const text = [
      message.reasoningContent ? `[reasoning]\n${message.reasoningContent}` : '',
      message.content,
    ].filter(Boolean).join('\n\n').trim();

    if (!text) {
      setError('没有可复制的文本内容。');
      return;
    }

    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement('textarea');
        area.value = text;
        document.body.appendChild(area);
        area.select();
        document.execCommand('copy');
        document.body.removeChild(area);
      }
      pushDebug('info', `已复制消息 ${message.id}。`);
    } catch {
      setError('复制失败，请手动复制。');
    }
  }, [pushDebug]);

  const deleteMessage = useCallback((target: ChatMessage) => {
    if (sending) return;
    setMessages((prev) => {
      const index = prev.findIndex((msg) => msg.id === target.id);
      if (index === -1) return prev;
      if (target.role === 'user' && prev[index + 1]?.role === 'assistant') {
        return prev.filter((_, idx) => idx !== index && idx !== index + 1);
      }
      return prev.filter((msg) => msg.id !== target.id);
    });
    setEditingMessageId(null);
    setEditValue('');
    pushDebug('info', `已删除消息 ${target.id}。`);
  }, [pushDebug, sending]);

  const toggleAssistantRole = useCallback((target: ChatMessage) => {
    if (!(target.role === 'assistant' || target.role === 'system')) return;
    if (sending) return;
    setMessages((prev) => prev.map((msg) => {
      if (msg.id !== target.id) return msg;
      return { ...msg, role: msg.role === 'assistant' ? 'system' : 'assistant' };
    }));
  }, [sending]);

  const resetFromMessage = useCallback((target: ChatMessage) => {
    if (sending || pendingJobId) return;
    const index = messages.findIndex((msg) => msg.id === target.id);
    if (index === -1) return;

    let userIndex = -1;
    if (target.role === 'user') {
      userIndex = index;
    } else {
      for (let i = index - 1; i >= 0; i -= 1) {
        if (messages[i].role === 'user') {
          userIndex = i;
          break;
        }
      }
    }

    if (userIndex === -1) {
      setError('未找到可重试的用户消息。');
      return;
    }

    const base = messages.slice(0, userIndex);
    const prompt = messages[userIndex].content;
    const files = extractUploadedFilesFromMessage(messages[userIndex]);
    setEditingMessageId(null);
    setEditValue('');
    void sendWithPrompt(prompt, base, files);
  }, [extractUploadedFilesFromMessage, messages, pendingJobId, sendWithPrompt, sending]);

  const startEditMessage = useCallback((target: ChatMessage) => {
    if (sending) return;
    setEditingMessageId(target.id);
    setEditValue(target.content);
  }, [sending]);

  const cancelEditMessage = useCallback(() => {
    setEditingMessageId(null);
    setEditValue('');
  }, []);

  const saveEditMessage = useCallback((retry = false) => {
    if (!editingMessageId) return;

    const targetIndex = messages.findIndex((message) => message.id === editingMessageId);
    if (targetIndex === -1) {
      cancelEditMessage();
      return;
    }

    const nextContent = editValue;
    const target = messages[targetIndex];
    const updated = messages.map((message, index) => (index === targetIndex
      ? { ...message, content: nextContent }
      : message));

    setMessages(updated);
    setEditingMessageId(null);
    setEditValue('');

    if (retry && target.role === 'user') {
      const base = updated.slice(0, targetIndex);
      void sendWithPrompt(nextContent, base, extractUploadedFilesFromMessage(target));
    }
  }, [cancelEditMessage, editValue, editingMessageId, extractUploadedFilesFromMessage, messages, sendWithPrompt]);

  const syncMessageToBody = useCallback(() => {
    const nextBody = syncMessagesToCustomRequestBody(customRequestBody, messages, inputs);
    setCustomRequestBody(nextBody);
    pushDebug('info', '已将消息同步到自定义请求体。');
  }, [customRequestBody, inputs, messages, pushDebug]);

  const syncBodyToMessage = useCallback(() => {
    const nextMessages = syncCustomRequestBodyToMessages(customRequestBody);
    if (!nextMessages) {
      setError('自定义请求体中没有有效的消息。');
      return;
    }
    setMessages(nextMessages);
    pushDebug('info', '已将自定义请求体同步到消息。');
  }, [customRequestBody, pushDebug]);

  const formatCustomBody = useCallback(() => {
    try {
      const parsed = JSON.parse(customRequestBody);
      setCustomRequestBody(JSON.stringify(parsed, null, 2));
      setError('');
    } catch (formatError: any) {
      setError(`JSON 解析错误：${formatError?.message || '无效的 JSON'}`);
    }
  }, [customRequestBody]);

  const debugTabContent = useMemo(() => {
    if (activeDebugTab === DEBUG_TABS.PREVIEW) return debugPreview;
    if (activeDebugTab === DEBUG_TABS.REQUEST) return debugRequest;
    return debugResponse;
  }, [activeDebugTab, debugPreview, debugRequest, debugResponse]);

  const layoutColumns = debugPanelPresence.shouldRender
    ? '340px minmax(0, 1fr) 360px'
    : '340px minmax(0, 1fr)';

  if (loadingModels) {
    return (
      <div className="animate-fade-in">
        <div className="skeleton" style={{ width: 200, height: 28, marginBottom: 20 }} />
        <div className="skeleton" style={{ height: 120, marginBottom: 12, borderRadius: 'var(--radius-md)' }} />
        <div className="skeleton" style={{ height: 520, borderRadius: 'var(--radius-md)' }} />
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <div>
          <h2 className="page-title">{tr('模型测试')}</h2>
          <p style={{ fontSize: 13, color: 'var(--color-text-muted)', margin: '4px 0 0' }}>
            支持流式输出、任务模式、自定义请求体和调试面板。
          </p>
        </div>
        <div className="page-actions">
          <button
            onClick={() => setShowDebugPanel((prev) => !prev)}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
          >
            {showDebugPanel ? '隐藏调试' : '显示调试'}
          </button>
          <button
            onClick={() => { void retryPending(); }}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
            disabled={sending || !!pendingJobId || !pendingPayload}
          >
            重试
          </button>
          <button
            onClick={() => { void stopGenerating(); }}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
            disabled={!pendingJobId && !streamAbortRef.current}
          >
            停止
          </button>
          <button
            onClick={clearChat}
            className="btn btn-ghost"
            style={{ border: '1px solid var(--color-border)', padding: '8px 14px' }}
            disabled={messages.length === 0 && !pendingPayload && !pendingJobId}
          >
            清除
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }} className="animate-slide-up stagger-1">
        <div className="stat-summary-card stat-summary-purple">
          <div className="stat-summary-card-label">模型数量</div>
          <div className="stat-summary-card-value">{models.length}</div>
        </div>
        <div className="stat-summary-card stat-summary-blue">
          <div className="stat-summary-card-label">当前模型</div>
          <div className="stat-summary-card-value" style={{ fontSize: 14, wordBreak: 'break-all' }}>{inputs.model || '未选择'}</div>
        </div>
        <div className="stat-summary-card stat-summary-green">
          <div className="stat-summary-card-label">对话轮数</div>
          <div className="stat-summary-card-value">{turnCount}</div>
        </div>
        <div className="stat-summary-card stat-summary-orange">
          <div className="stat-summary-card-label">模式</div>
          <div className="stat-summary-card-value" style={{ fontSize: 14 }}>
            {inputs.mode === 'conversation'
              ? (customRequestMode ? '自定义请求' : (inputs.stream ? '流式' : '任务模式'))
              : inputs.mode}
            {' / '}
            {inputs.protocol === 'claude'
              ? 'Claude'
              : inputs.protocol === 'responses'
                ? 'OpenAI Responses'
                : inputs.protocol === 'gemini'
                  ? 'Gemini'
                  : 'OpenAI'}
          </div>
        </div>
      </div>

      <div
        className="animate-slide-up stagger-2"
        style={{
          display: 'grid',
          gridTemplateColumns: layoutColumns,
          gap: 16,
          alignItems: 'stretch',
        }}
      >
        <div className="card" style={{ padding: 16, minHeight: 680, maxHeight: 740, overflowY: 'auto' }}>
          <h3 style={{ margin: '0 0 12px', fontSize: 15 }}>设置</h3>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6, fontWeight: 600 }}>
              测试模式
            </div>
            <ModernSelect
              value={inputs.mode}
              onChange={(next) => {
                if (!next) return;
                updateInput('mode', next as PlaygroundMode);
              }}
              options={CONVERSATION_MODE_OPTIONS}
              placeholder="请选择测试模式"
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6, fontWeight: 600 }}>模型</div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
              <input
                value={modelSearch}
                onChange={(event) => setModelSearch(event.target.value)}
                placeholder="搜索模型（支持名称片段）"
                style={{
                  ...inputBaseStyle,
                  flex: 1,
                  marginBottom: 0,
                }}
                disabled={models.length === 0}
              />
              <button
                type="button"
                className="btn btn-ghost"
                style={{ border: '1px solid var(--color-border)', whiteSpace: 'nowrap' }}
                onClick={() => setModelSearch('')}
                disabled={!modelSearch}
              >
                清空
              </button>
            </div>
            <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginBottom: 6 }}>
              {modelCountText}
            </div>
            <ModernSelect
              value={currentModelVisible ? inputs.model : ''}
              onChange={(next) => {
                if (!next) return;
                updateInput('model', next);
              }}
              options={modelSelectOptions}
              placeholder={
                !currentModelVisible && !!inputs.model
                  ? `当前模型已被筛选：${inputs.model}`
                  : (models.length === 0
                    ? '暂无模型'
                    : (filteredModels.length === 0 ? '未找到匹配模型' : '请选择模型'))
              }
              disabled={models.length === 0 || customRequestMode || filteredModels.length === 0}
              emptyLabel="未找到匹配模型"
              menuMaxHeight={300}
            />
            {!currentModelVisible && !!inputs.model && (
              <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 4 }}>
                当前模型已被筛选：{inputs.model}
              </div>
            )}
            {customRequestMode && (
              <div style={{ fontSize: 11, color: 'var(--color-warning)', marginTop: 4 }}>
                自定义请求模式下模型选择将被忽略。
              </div>
            )}
          </div>

          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6, fontWeight: 600 }}>
              协议 / 输出格式
            </div>
            <ModernSelect
              value={inputs.protocol}
              onChange={(next) => {
                if (!next) return;
                updateProtocol(next as PlaygroundProtocol);
              }}
              options={PROTOCOL_OPTIONS}
              placeholder="请选择协议"
            />
            <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 4 }}>
              对话模式下可模拟 OpenAI / Responses / Claude / Gemini Native。
            </div>
          </div>

          {inputs.mode === 'conversation' && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 6, fontWeight: 600 }}>
                System Prompt
              </div>
              <textarea
                value={inputs.systemPrompt}
                onChange={(event) => updateInput('systemPrompt', event.target.value)}
                rows={4}
                placeholder="可选的系统提示词，会在发送时独立注入请求。"
                style={{
                  ...inputBaseStyle,
                  resize: 'vertical',
                  fontFamily: 'inherit',
                  lineHeight: 1.5,
                }}
              />
            </div>
          )}

          <div style={{ marginBottom: 14, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ fontSize: 13, fontWeight: 600 }}>流式输出</div>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--color-text-secondary)' }}>
              <input
                type="checkbox"
                checked={inputs.stream}
                onChange={(event) => updateInput('stream', event.target.checked)}
                disabled={customRequestMode || inputs.mode !== 'conversation'}
              />
              启用
            </label>
          </div>

          {inputs.mode !== 'conversation' && (
            <div style={{ fontSize: 11, color: 'var(--color-text-muted)', marginBottom: 14 }}>
              当前模式默认走同步请求；Search / Embeddings / Images / Videos 会通过通用 proxy tester 直达对应接口。
            </div>
          )}

          <div style={{ marginBottom: 14, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ fontSize: 13, fontWeight: 600 }}>自定义请求体</div>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--color-text-secondary)' }}>
              <input
                type="checkbox"
                checked={customRequestMode}
                onChange={(event) => setCustomRequestMode(event.target.checked)}
              />
              启用
            </label>
          </div>

          <div className={`anim-collapse ${customRequestMode ? 'is-open' : ''}`.trim()} style={{ marginBottom: 14 }}>
            <div className="anim-collapse-inner">
              <textarea
                value={customRequestBody}
                onChange={(event) => setCustomRequestBody(event.target.value)}
                rows={11}
                placeholder='{"model":"gpt-4o-mini","targetFormat":"claude","messages":[{"role":"user","content":"hello"}],"stream":true}'
                style={{
                  ...inputBaseStyle,
                  resize: 'vertical',
                  fontFamily: 'var(--font-mono)',
                  lineHeight: 1.5,
                }}
              />
              <div style={{ marginTop: 8, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={formatCustomBody}>
                  格式化 JSON
                </button>
                {inputs.mode === 'conversation' && (
                  <>
                    <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={syncMessageToBody}>
                      消息 -&gt; 请求体
                    </button>
                    <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={syncBodyToMessage}>
                      请求体 -&gt; 消息
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

            <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 8, fontWeight: 600 }}>
              采样参数
            </div>

          <ParameterRow
            title="温度"
            valueText={inputs.temperature.toFixed(2)}
            enabled={parameterEnabled.temperature}
            onToggle={() => toggleParameter('temperature')}
            disabled={customRequestMode}
          >
            <input
              type="range"
              min={0}
              max={2}
              step={0.1}
              value={inputs.temperature}
              onChange={(event) => updateInput('temperature', toNumber(event.target.value, inputs.temperature))}
              style={{ width: '100%', accentColor: 'var(--color-primary)' }}
              disabled={!parameterEnabled.temperature || customRequestMode}
            />
          </ParameterRow>

          <ParameterRow
            title="Top P"
            valueText={inputs.top_p.toFixed(2)}
            enabled={parameterEnabled.top_p}
            onToggle={() => toggleParameter('top_p')}
            disabled={customRequestMode}
          >
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={inputs.top_p}
              onChange={(event) => updateInput('top_p', toNumber(event.target.value, inputs.top_p))}
              style={{ width: '100%', accentColor: 'var(--color-primary)' }}
              disabled={!parameterEnabled.top_p || customRequestMode}
            />
          </ParameterRow>

          <ParameterRow
            title="频率惩罚"
            valueText={inputs.frequency_penalty.toFixed(2)}
            enabled={parameterEnabled.frequency_penalty}
            onToggle={() => toggleParameter('frequency_penalty')}
            disabled={customRequestMode}
          >
            <input
              type="range"
              min={-2}
              max={2}
              step={0.1}
              value={inputs.frequency_penalty}
              onChange={(event) => updateInput('frequency_penalty', toNumber(event.target.value, inputs.frequency_penalty))}
              style={{ width: '100%', accentColor: 'var(--color-primary)' }}
              disabled={!parameterEnabled.frequency_penalty || customRequestMode}
            />
          </ParameterRow>

          <ParameterRow
            title="存在惩罚"
            valueText={inputs.presence_penalty.toFixed(2)}
            enabled={parameterEnabled.presence_penalty}
            onToggle={() => toggleParameter('presence_penalty')}
            disabled={customRequestMode}
          >
            <input
              type="range"
              min={-2}
              max={2}
              step={0.1}
              value={inputs.presence_penalty}
              onChange={(event) => updateInput('presence_penalty', toNumber(event.target.value, inputs.presence_penalty))}
              style={{ width: '100%', accentColor: 'var(--color-primary)' }}
              disabled={!parameterEnabled.presence_penalty || customRequestMode}
            />
          </ParameterRow>

          <ParameterRow
            title="最大 Token 数"
            enabled={parameterEnabled.max_tokens}
            onToggle={() => toggleParameter('max_tokens')}
            disabled={customRequestMode}
          >
            <input
              type="number"
              value={inputs.max_tokens}
              min={1}
              step={1}
              onChange={(event) => updateInput('max_tokens', toNumber(event.target.value, inputs.max_tokens))}
              style={inputBaseStyle}
              disabled={!parameterEnabled.max_tokens || customRequestMode}
            />
          </ParameterRow>

          <ParameterRow
            title="随机种子"
            valueText={inputs.seed === null ? '自动' : String(inputs.seed)}
            enabled={parameterEnabled.seed}
            onToggle={() => toggleParameter('seed')}
            disabled={customRequestMode}
          >
            <input
              type="number"
              value={inputs.seed ?? ''}
              min={0}
              step={1}
              placeholder="可选种子值"
              onChange={(event) => {
                const raw = event.target.value.trim();
                updateInput('seed', raw.length === 0 ? null : toNumber(raw, 0));
              }}
              style={inputBaseStyle}
              disabled={!parameterEnabled.seed || customRequestMode}
            />
          </ParameterRow>
        </div>

        <div className="card" style={{ padding: 0, overflow: 'hidden', minHeight: 680, maxHeight: 740, display: 'flex', flexDirection: 'column' }}>
          <div style={{
            padding: '14px 16px',
            borderBottom: '1px solid var(--color-border-light)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--color-bg-card)',
          }}>
            <div style={{ fontSize: 14, fontWeight: 700 }}>对话</div>
            <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
              {sending ? '生成中...' : '就绪'}
            </div>
          </div>

          <div style={{ flex: 1, minHeight: 280, overflowY: 'auto', padding: 18, background: 'var(--color-bg)' }}>
            {inputs.mode !== 'conversation' ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div style={{
                  padding: 14,
                  border: '1px solid var(--color-border-light)',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--color-bg-card)',
                }}>
                  <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 6 }}>
                    {inputs.mode === 'embeddings' ? 'Embeddings 结果'
                      : inputs.mode === 'search' ? 'Search 结果'
                        : inputs.mode.startsWith('images') ? '图片结果'
                          : '视频任务结果'}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
                    新模式走通用 proxy tester；结果同时会写入右侧调试面板。
                  </div>
                </div>

                {Array.isArray((nonConversationResult as any)?.data) && (nonConversationResult as any).data.some((item: any) => item?.url || item?.b64_json) && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
                    {(nonConversationResult as any).data.map((item: any, index: number) => {
                      const imageSrc = typeof item?.url === 'string'
                        ? item.url
                        : (typeof item?.b64_json === 'string' ? `data:image/png;base64,${item.b64_json}` : '');
                      if (!imageSrc) return null;
                      return (
                        <div key={`image-${index}`} style={{
                          border: '1px solid var(--color-border-light)',
                          borderRadius: 'var(--radius-md)',
                          overflow: 'hidden',
                          background: 'var(--color-bg-card)',
                        }}>
                          <img src={imageSrc} alt={`generated-${index}`} style={{ width: '100%', display: 'block' }} />
                        </div>
                      );
                    })}
                  </div>
                )}

                <pre style={{
                  margin: 0,
                  padding: 14,
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--color-border-light)',
                  background: 'var(--color-bg-card)',
                  fontSize: 12,
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  fontFamily: 'var(--font-mono)',
                }}>
                  {nonConversationResult ? formatJson(nonConversationResult) : '// 暂无结果'}
                </pre>
              </div>
            ) : messages.length === 0 ? (
              <div className="empty-state" style={{ padding: '40px 0' }}>
                <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M8 10h.01M12 14h.01M16 10h.01M9 16h6M12 3C7.03 3 3 6.582 3 11c0 2.2 1.003 4.193 2.63 5.64V21l3.376-1.847A10.76 10.76 0 0012 19c4.97 0 9-3.582 9-8s-4.03-8-9-8z" />
                </svg>
                <div className="empty-state-title">开始对话测试</div>
                <div className="empty-state-desc">支持流式模式、自定义请求体模式和可恢复的任务。</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {messages.map((message) => {
                  const isUser = message.role === 'user';
                  const isSystem = message.role === 'system';
                  const isLoading = message.status === MESSAGE_STATUS.LOADING || message.status === MESSAGE_STATUS.INCOMPLETE;
                  const isError = message.status === MESSAGE_STATUS.ERROR;
                  const showReasoning = Boolean(message.reasoningContent);
                  const isEditing = editingMessageId === message.id;
                  const fileParts = Array.isArray(message.parts)
                    ? message.parts.filter((part): part is Extract<ConversationContentPart, { type: 'input_file' }> => part.type === 'input_file')
                    : [];

                  return (
                    <div
                      key={message.id}
                      className="animate-fade-in"
                      style={{
                        display: 'flex',
                        gap: 10,
                        flexDirection: isUser ? 'row-reverse' : 'row',
                      }}
                    >
                      <div style={{
                        width: 30,
                        height: 30,
                        borderRadius: 8,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 12,
                        fontWeight: 700,
                        flexShrink: 0,
                        background: isUser
                          ? 'linear-gradient(135deg, var(--color-primary), color-mix(in srgb, var(--color-primary) 58%, white))'
                          : (isSystem
                            ? 'linear-gradient(135deg, color-mix(in srgb, var(--color-text-secondary) 88%, black), color-mix(in srgb, var(--color-text-muted) 70%, white))'
                            : (isError
                              ? 'linear-gradient(135deg, var(--color-danger), color-mix(in srgb, var(--color-danger) 68%, white))'
                              : 'linear-gradient(135deg, var(--color-success), color-mix(in srgb, var(--color-success) 62%, white))')),
                        color: 'white',
                      }}>
                        {isUser ? 'U' : (isSystem ? 'SYS' : 'AI')}
                      </div>

                      <div style={{ maxWidth: '78%', display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {showReasoning && (
                          <div style={{
                            border: '1px solid color-mix(in srgb, var(--color-primary) 28%, transparent)',
                            background: 'color-mix(in srgb, var(--color-primary) 9%, var(--color-bg-card))',
                            borderRadius: '10px',
                            overflow: 'hidden',
                          }}>
                            <button
                              onClick={() => toggleReasoning(message.id)}
                              style={{
                                width: '100%',
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                border: 'none',
                                background: 'transparent',
                                cursor: 'pointer',
                                padding: '8px 10px',
                                fontSize: 12,
                                fontWeight: 600,
                                color: 'var(--color-primary)',
                              }}
                            >
                              <span>{isLoading ? '思考中...' : '推理过程'}</span>
                              <span>{message.isReasoningExpanded ? '▼' : '▶'}</span>
                            </button>
                            <div className={`anim-collapse ${message.isReasoningExpanded ? 'is-open' : ''}`.trim()}>
                              <div className="anim-collapse-inner">
                                <div style={{
                                  padding: '8px 10px',
                                  borderTop: '1px solid color-mix(in srgb, var(--color-primary) 20%, transparent)',
                                  fontSize: 12,
                                  lineHeight: 1.7,
                                  whiteSpace: 'pre-wrap',
                                  color: 'var(--color-text-secondary)',
                                }}>
                                  {message.reasoningContent}
                                </div>
                              </div>
                            </div>
                          </div>
                        )}

                        <div style={{
                          padding: '10px 12px',
                          borderRadius: isUser ? '12px 12px 3px 12px' : '12px 12px 12px 3px',
                          background: isUser ? 'var(--color-primary)' : (isError ? 'var(--color-danger-soft)' : 'var(--color-bg-card)'),
                          color: isUser ? 'white' : 'var(--color-text-primary)',
                          border: isUser ? 'none' : (isError ? '1px solid color-mix(in srgb, var(--color-danger) 32%, transparent)' : '1px solid var(--color-border-light)'),
                          fontSize: 13,
                          lineHeight: 1.65,
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                          boxShadow: 'var(--shadow-sm)',
                          minHeight: 24,
                        }}>
                          {isEditing ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                              <textarea
                                value={editValue}
                                onChange={(event) => setEditValue(event.target.value)}
                                rows={3}
                                style={{ ...inputBaseStyle, resize: 'vertical', background: 'var(--color-bg-card)', color: 'var(--color-text-primary)' }}
                              />
                              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                                {message.role === 'user' && (
                                  <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={() => saveEditMessage(true)}>
                                    保存并重试
                                  </button>
                                )}
                                <button className="btn btn-primary" onClick={() => saveEditMessage(false)}>保存</button>
                                <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)' }} onClick={cancelEditMessage}>取消</button>
                              </div>
                            </div>
                          ) : (
                            <>
                              {isLoading && <span className="spinner spinner-sm" style={{ marginRight: 6, verticalAlign: 'middle' }} />}
                              {message.content || (isLoading ? '思考中...' : '')}
                            </>
                          )}
                        </div>

                        {!isEditing && fileParts.length > 0 && (
                          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
                            {fileParts.map((part, index) => (
                              <span
                                key={`${message.id}-file-${part.fileId || part.filename || index}`}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 6,
                                  padding: '4px 8px',
                                  borderRadius: 999,
                                  border: '1px solid var(--color-border-light)',
                                  background: 'var(--color-bg-subtle)',
                                  color: 'var(--color-text-secondary)',
                                  fontSize: 11,
                                  maxWidth: '100%',
                                }}
                                title={part.fileId || part.filename || '附件'}
                              >
                                <span>📎</span>
                                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {part.filename || part.fileId || '附件'}
                                </span>
                              </span>
                            ))}
                          </div>
                        )}

                        {!isEditing && (
                          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                            {!isLoading && (
                              <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)', padding: '4px 8px', fontSize: 11 }} onClick={() => resetFromMessage(message)} disabled={sending || Boolean(pendingJobId)}>
                                重试
                              </button>
                            )}
                            <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)', padding: '4px 8px', fontSize: 11 }} onClick={() => { void copyMessage(message); }}>
                              复制
                            </button>
                            {!isLoading && (
                              <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)', padding: '4px 8px', fontSize: 11 }} onClick={() => startEditMessage(message)} disabled={sending}>
                                编辑
                              </button>
                            )}
                            {!isLoading && (
                              <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)', padding: '4px 8px', fontSize: 11 }} onClick={() => deleteMessage(message)} disabled={sending}>
                                删除
                              </button>
                            )}
                            {(message.role === 'assistant' || message.role === 'system') && !isLoading && (
                              <button className="btn btn-ghost" style={{ border: '1px solid var(--color-border)', padding: '4px 8px', fontSize: 11 }} onClick={() => toggleAssistantRole(message)} disabled={sending}>
                                {message.role === 'assistant' ? '转为系统' : '转为助手'}
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
                <div ref={chatEndRef} />
              </div>
            )}
          </div>

          <div style={{ borderTop: '1px solid var(--color-border-light)', padding: 14, background: 'var(--color-bg-card)' }}>
            {error && (
              <div className="alert alert-error animate-scale-in" style={{ marginBottom: 10 }}>
                {error}
              </div>
            )}

            {inputs.mode === 'conversation' ? (
              <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{
                    padding: '10px 12px',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--color-border-light)',
                    background: 'var(--color-bg-subtle)',
                  }}>
                    <input
                      ref={conversationFileInputRef}
                      type="file"
                      multiple
                      accept={CONVERSATION_FILE_ACCEPT}
                      style={{ display: 'none' }}
                      onChange={(event) => {
                        void handleConversationFilesChange(event.target.files);
                        event.target.value = '';
                      }}
                    />
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        className="btn btn-ghost"
                        style={{ border: '1px solid var(--color-border)', padding: '6px 10px' }}
                        disabled={sending || customRequestMode || !conversationFileSupported}
                        onClick={() => conversationFileInputRef.current?.click()}
                      >
                        添加文件
                      </button>
                      <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                        {customRequestMode
                          ? '自定义请求模式不会自动上传这些附件；关闭自定义模式后可走标准 /v1/files 链路。'
                          : !conversationFileSupported
                            ? '当前协议暂不支持会话附件注入；请切换到 OpenAI 或 Responses。'
                            : '支持 PDF / TXT / Markdown / JSON / 图片 / 音频；发送前会先上传到 /v1/files。'}
                      </span>
                    </div>
                    {conversationFiles.length > 0 && (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
                        {conversationFiles.map((file) => {
                          const statusText = file.status === 'uploading'
                            ? '上传中'
                            : file.status === 'uploaded'
                              ? '已上传'
                              : file.status === 'error'
                                ? '失败'
                                : '待上传';
                          const statusColor = file.status === 'error'
                            ? 'var(--color-danger)'
                            : file.status === 'uploaded'
                              ? 'var(--color-success)'
                              : file.status === 'uploading'
                                ? 'var(--color-warning)'
                                : 'var(--color-text-muted)';

                          return (
                            <span
                              key={file.localId}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 6,
                                maxWidth: '100%',
                                padding: '6px 10px',
                                borderRadius: 999,
                                border: '1px solid var(--color-border-light)',
                                background: 'var(--color-bg-card)',
                                fontSize: 11,
                              }}
                              title={file.errorMessage || file.fileId || file.name}
                            >
                              <span>📎</span>
                              <span style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {file.name}
                              </span>
                              <span style={{ color: statusColor }}>· {statusText}</span>
                              {!sending && (
                                <button
                                  type="button"
                                  onClick={() => removeConversationFile(file.localId)}
                                  style={{
                                    border: 'none',
                                    background: 'transparent',
                                    color: 'var(--color-text-muted)',
                                    cursor: 'pointer',
                                    padding: 0,
                                  }}
                                >
                                  ×
                                </button>
                              )}
                            </span>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  <textarea
                    value={input}
                    onChange={(event) => setInput(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' && !event.shiftKey) {
                        event.preventDefault();
                        if (sending) {
                          void stopGenerating();
                          return;
                        }
                        void send();
                      }
                    }}
                    placeholder={customRequestMode
                      ? '自定义模式下输入可选。回车发送时将优先使用右侧自定义请求体。'
                      : '输入提示词，或只上传文件后直接发送…（回车发送，Shift+回车换行）'}
                    rows={3}
                    style={{ ...inputBaseStyle, resize: 'none', flex: 1 }}
                  />
                </div>
                <button
                  onClick={() => {
                    if (sending) {
                      void stopGenerating();
                      return;
                    }
                    void send();
                  }}
                  disabled={sending ? false : !canSend}
                  className="btn btn-primary"
                  style={{
                    height: 78,
                    padding: '0 20px',
                    fontSize: 14,
                    fontWeight: 600,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 4,
                    minWidth: 88,
                  }}
                >
                  {sending ? (
                    <>
                      <span style={{ fontSize: 18, lineHeight: 1 }}>■</span>
                      <span style={{ fontSize: 11 }}>停止</span>
                    </>
                  ) : (
                    <>
                      <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                      </svg>
                      <span style={{ fontSize: 11 }}>发送</span>
                    </>
                  )}
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {inputs.mode === 'embeddings' && (
                  <textarea
                    value={embeddingInputText}
                    onChange={(event) => setEmbeddingInputText(event.target.value)}
                    rows={4}
                    placeholder="输入 embeddings 测试文本，支持单条或多行。"
                    style={{ ...inputBaseStyle, resize: 'vertical' }}
                  />
                )}
                {inputs.mode === 'search' && (
                  <>
                    <textarea
                      value={searchQueryValue}
                      onChange={(event) => setSearchQueryValue(event.target.value)}
                      rows={3}
                      placeholder="输入搜索查询"
                      style={{ ...inputBaseStyle, resize: 'vertical' }}
                    />
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 120px', gap: 10 }}>
                      <input value={searchAllowedDomains} onChange={(event) => setSearchAllowedDomains(event.target.value)} placeholder="allowed_domains (逗号分隔)" style={inputBaseStyle} />
                      <input value={searchBlockedDomains} onChange={(event) => setSearchBlockedDomains(event.target.value)} placeholder="blocked_domains (逗号分隔)" style={inputBaseStyle} />
                      <input value={searchMaxResults} onChange={(event) => setSearchMaxResults(toNumber(event.target.value, 10))} type="number" min={1} max={20} style={inputBaseStyle} />
                    </div>
                  </>
                )}
                {(inputs.mode === 'images.generate' || inputs.mode === 'images.edit' || inputs.mode === 'videos.create') && (
                  <>
                    <textarea
                      value={assetPrompt}
                      onChange={(event) => setAssetPrompt(event.target.value)}
                      rows={3}
                      placeholder={inputs.mode === 'videos.create' ? '输入视频生成提示词' : '输入图片提示词'}
                      style={{ ...inputBaseStyle, resize: 'vertical' }}
                    />
                    {(inputs.mode === 'images.edit' || inputs.mode === 'videos.create') && (
                      <div style={{ display: 'grid', gridTemplateColumns: inputs.mode === 'images.edit' ? '1fr 1fr' : '1fr', gap: 10 }}>
                        <label style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                          <div style={{ marginBottom: 6 }}>{inputs.mode === 'images.edit' ? '原图' : '参考图'}</div>
                          <input type="file" accept="image/*" onChange={(event) => { void handleUploadChange(event.target.files, setImageSourceFile); }} />
                        </label>
                        {inputs.mode === 'images.edit' && (
                          <label style={{ fontSize: 12, color: 'var(--color-text-secondary)' }}>
                            <div style={{ marginBottom: 6 }}>Mask</div>
                            <input type="file" accept="image/*" onChange={(event) => { void handleUploadChange(event.target.files, setImageMaskFile); }} />
                          </label>
                        )}
                      </div>
                    )}
                  </>
                )}
                {inputs.mode === 'videos.inspect' && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 160px', gap: 10 }}>
                    <input
                      value={videoInspectId}
                      onChange={(event) => setVideoInspectId(event.target.value)}
                      placeholder="输入 public video id"
                      style={inputBaseStyle}
                    />
                    <ModernSelect
                      value={videoInspectAction}
                      onChange={(next) => {
                        if (!next) return;
                        setVideoInspectAction(next as 'GET' | 'DELETE');
                      }}
                      options={[
                        { value: 'GET', label: 'GET' },
                        { value: 'DELETE', label: 'DELETE' },
                      ]}
                    />
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button
                    onClick={() => { void send(); }}
                    disabled={!canSend}
                    className="btn btn-primary"
                    style={{ minWidth: 120, height: 42 }}
                  >
                    发送请求
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {debugPanelPresence.shouldRender && (
          <div className={`card panel-presence ${debugPanelPresence.isVisible ? '' : 'is-closing'}`.trim()} style={{ padding: 14, minHeight: 680, maxHeight: 740, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <h3 style={{ margin: 0, fontSize: 15 }}>调试</h3>
              <div style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                {debugTimestamp ? new Date(debugTimestamp).toLocaleString() : '--'}
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
              <button
                className="btn btn-ghost"
                style={{
                  border: activeDebugTab === DEBUG_TABS.PREVIEW ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
                  color: activeDebugTab === DEBUG_TABS.PREVIEW ? 'var(--color-primary)' : 'var(--color-text-secondary)',
                }}
                onClick={() => setActiveDebugTab(DEBUG_TABS.PREVIEW)}
              >
                预览
              </button>
              <button
                className="btn btn-ghost"
                style={{
                  border: activeDebugTab === DEBUG_TABS.REQUEST ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
                  color: activeDebugTab === DEBUG_TABS.REQUEST ? 'var(--color-primary)' : 'var(--color-text-secondary)',
                }}
                onClick={() => setActiveDebugTab(DEBUG_TABS.REQUEST)}
              >
                请求
              </button>
              <button
                className="btn btn-ghost"
                style={{
                  border: activeDebugTab === DEBUG_TABS.RESPONSE ? '1px solid var(--color-primary)' : '1px solid var(--color-border)',
                  color: activeDebugTab === DEBUG_TABS.RESPONSE ? 'var(--color-primary)' : 'var(--color-text-secondary)',
                }}
                onClick={() => setActiveDebugTab(DEBUG_TABS.RESPONSE)}
              >
                响应
              </button>
            </div>

            <div style={{ flex: 1, overflow: 'hidden', border: '1px solid var(--color-border-light)', borderRadius: 'var(--radius-sm)', background: 'var(--color-bg)' }}>
              <pre style={{
                margin: 0,
                padding: 12,
                fontSize: 12,
                lineHeight: 1.55,
                fontFamily: 'var(--font-mono)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                overflow: 'auto',
                maxHeight: '100%',
              }}>
                {debugTabContent || '// 暂无数据'}
              </pre>
            </div>

            <div style={{ marginTop: 10, fontSize: 12, fontWeight: 600 }}>时间线</div>
            <div style={{
              marginTop: 6,
              border: '1px solid var(--color-border-light)',
              borderRadius: 'var(--radius-sm)',
              padding: 8,
              minHeight: 120,
              maxHeight: 170,
              overflowY: 'auto',
              background: 'var(--color-bg)',
            }}>
              {debugTimeline.length === 0 ? (
                <div style={{ color: 'var(--color-text-muted)', fontSize: 12 }}>暂无事件。</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {debugTimeline.map((item, index) => (
                    <div key={`${item.at}-${index}`} style={{ fontSize: 11, color: 'var(--color-text-secondary)', lineHeight: 1.45 }}>
                      <span style={{
                        display: 'inline-block',
                        minWidth: 40,
                        marginRight: 6,
                        color: item.level === 'error' ? 'var(--color-danger)' : item.level === 'warn' ? 'var(--color-warning)' : 'var(--color-primary)',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                      }}>
                        {item.level}
                      </span>
                      <span style={{ color: 'var(--color-text-muted)', marginRight: 6 }}>
                        {new Date(item.at).toLocaleTimeString()}
                      </span>
                      <span>{item.text}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
