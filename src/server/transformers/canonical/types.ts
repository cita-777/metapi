import type { CanonicalAttachment } from './attachments.js';
import type { CanonicalTool, CanonicalToolChoice } from './tools.js';

export type CanonicalOperation =
  | 'generate'
  | 'count_tokens';

export type CanonicalSurface =
  | 'openai-chat'
  | 'openai-responses'
  | 'anthropic-messages'
  | 'gemini-generate-content';

export type CanonicalCliProfile =
  | 'generic'
  | 'codex'
  | 'claude_code'
  | 'gemini_cli';

export type CanonicalMessageRole =
  | 'system'
  | 'developer'
  | 'user'
  | 'assistant'
  | 'tool';

export type CanonicalTextPart = {
  type: 'text';
  text: string;
  thought?: boolean;
};

export type CanonicalImagePart = {
  type: 'image';
  dataUrl?: string;
  url?: string;
  mimeType?: string | null;
};

export type CanonicalFilePart = {
  type: 'file';
  fileId?: string;
  fileUrl?: string;
  fileData?: string;
  mimeType?: string | null;
  filename?: string;
};

export type CanonicalToolCallPart = {
  type: 'tool_call';
  id: string;
  name: string;
  argumentsJson: string;
};

export type CanonicalToolResultPart = {
  type: 'tool_result';
  toolCallId: string;
  resultText?: string;
  resultJson?: unknown;
  resultContent?: string | Array<string | Record<string, unknown>>;
};

export type CanonicalContentPart =
  | CanonicalTextPart
  | CanonicalImagePart
  | CanonicalFilePart
  | CanonicalToolCallPart
  | CanonicalToolResultPart;

export type CanonicalMessage = {
  role: CanonicalMessageRole;
  parts: CanonicalContentPart[];
  phase?: string;
  reasoningSignature?: string;
};

export type CanonicalReasoningEffort =
  | 'none'
  | 'low'
  | 'medium'
  | 'high'
  | 'max';

export type CanonicalReasoningRequest = {
  effort?: CanonicalReasoningEffort;
  budgetTokens?: number;
  summary?: string;
  includeEncryptedContent?: boolean;
};

export type CanonicalContinuation = {
  sessionId?: string;
  previousResponseId?: string;
  promptCacheKey?: string;
  turnState?: string;
};

export type CanonicalRequestEnvelope = {
  operation: CanonicalOperation;
  surface: CanonicalSurface;
  cliProfile: CanonicalCliProfile;
  requestedModel: string;
  stream: boolean;
  messages: CanonicalMessage[];
  reasoning?: CanonicalReasoningRequest;
  tools?: CanonicalTool[];
  toolChoice?: CanonicalToolChoice;
  continuation?: CanonicalContinuation;
  metadata?: Record<string, unknown>;
  passthrough?: Record<string, unknown>;
  attachments?: CanonicalAttachment[];
};
