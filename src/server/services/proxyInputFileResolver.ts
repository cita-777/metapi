import type { ProxyResourceOwner } from '../middleware/auth.js';
import { getProxyFileByPublicIdForOwner, LOCAL_PROXY_FILE_ID_PREFIX } from './proxyFileStore.js';
import { ensureBase64DataUrl } from '../transformers/shared/inputFile.js';
import { summarizeConversationFileInputsInOpenAiBody } from '../proxy-core/capabilities/conversationFileCapabilities.js';
import {
  isSupportedConversationFileMimeType,
  resolveConversationFileMimeType,
} from '../../shared/conversationFileTypes.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function cloneJsonValue<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => cloneJsonValue(item)) as T;
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, cloneJsonValue(item)]),
    ) as T;
  }
  return value;
}

function isSupportedMimeType(mimeType: string): boolean {
  return isSupportedConversationFileMimeType(mimeType);
}

function audioFormatFromMimeType(mimeType: string, filename: string): string {
  const normalized = mimeType.toLowerCase();
  if (normalized === 'audio/mpeg') return 'mp3';
  if (normalized === 'audio/wav' || normalized === 'audio/x-wav') return 'wav';
  if (normalized === 'audio/mp4' || normalized === 'audio/x-m4a') return 'm4a';
  if (normalized === 'audio/ogg') return 'ogg';
  if (normalized === 'audio/webm') return 'webm';
  const extension = filename.split('.').pop()?.trim().toLowerCase();
  return extension || 'mp3';
}

function isLocalProxyFileId(fileId: string): boolean {
  return fileId.startsWith(LOCAL_PROXY_FILE_ID_PREFIX);
}

type InputFileLike = {
  fileId?: string;
  filename?: string;
  fileData?: string;
  mimeType?: string;
};

export class ProxyInputFileResolutionError extends Error {
  statusCode: number;
  payload: unknown;

  constructor(statusCode: number, message: string, type = 'invalid_request_error') {
    super(message);
    this.name = 'ProxyInputFileResolutionError';
    this.statusCode = statusCode;
    this.payload = {
      error: {
        message,
        type,
      },
    };
  }
}

function normalizeInputFileLike(item: Record<string, unknown>): InputFileLike | null {
  const type = asTrimmedString(item.type).toLowerCase();
  if (type !== 'file' && type !== 'input_file') return null;

  const source = type === 'file' && isRecord(item.file)
    ? item.file
    : item;

  const fileId = asTrimmedString(source.file_id ?? item.file_id);
  const filename = asTrimmedString(source.filename ?? item.filename);
  const fileData = asTrimmedString(source.file_data ?? item.file_data);
  const mimeType = asTrimmedString(source.mime_type ?? source.mimeType ?? item.mime_type ?? item.mimeType);
  if (!fileId && !fileData) return null;
  return {
    ...(fileId ? { fileId } : {}),
    ...(filename ? { filename } : {}),
    ...(fileData ? { fileData } : {}),
    ...(mimeType ? { mimeType } : {}),
  };
}

async function resolveInputFileLike(fileLike: InputFileLike, owner: ProxyResourceOwner): Promise<{
  fileId?: string;
  filename: string;
  fileData: string;
  mimeType: string;
}> {
  if (fileLike.fileData) {
    const filename = fileLike.filename || 'upload.bin';
    const mimeType = resolveConversationFileMimeType(fileLike.mimeType, filename);
    if (!isSupportedMimeType(mimeType)) {
      throw new ProxyInputFileResolutionError(400, `unsupported file mime type: ${mimeType}`);
    }
    return {
      ...(fileLike.fileId ? { fileId: fileLike.fileId } : {}),
      filename,
      fileData: fileLike.fileData,
      mimeType,
    };
  }

  if (fileLike.fileId) {
    const stored = await getProxyFileByPublicIdForOwner(fileLike.fileId, owner);
    if (!stored) {
      throw new ProxyInputFileResolutionError(404, `file not found: ${fileLike.fileId}`, 'not_found_error');
    }
    const mimeType = resolveConversationFileMimeType(
      fileLike.mimeType || stored.mimeType,
      stored.filename,
    );
    if (!isSupportedMimeType(mimeType)) {
      throw new ProxyInputFileResolutionError(400, `unsupported file mime type: ${mimeType}`);
    }
    return {
      filename: fileLike.filename || stored.filename,
      fileData: stored.contentBase64,
      mimeType,
    };
  }

  const filename = fileLike.filename || 'upload.bin';
  const mimeType = resolveConversationFileMimeType(fileLike.mimeType, filename);
  if (!fileLike.fileData) {
    throw new ProxyInputFileResolutionError(400, `file_data is required for inline file block: ${filename}`);
  }
  if (!isSupportedMimeType(mimeType)) {
    throw new ProxyInputFileResolutionError(400, `unsupported file mime type: ${mimeType}`);
  }
  return {
    filename,
    fileData: fileLike.fileData,
    mimeType,
  };
}

function shouldResolveInlineFileLike(fileLike: InputFileLike): boolean {
  if (fileLike.fileData) return true;
  if (!fileLike.fileId) return false;
  return isLocalProxyFileId(fileLike.fileId);
}

function toOpenAiResolvedBlock(file: { fileId?: string; filename: string; fileData: string; mimeType: string }): Record<string, unknown> {
  if (file.mimeType.startsWith('image/')) {
    return {
      type: 'image_url',
      image_url: `data:${file.mimeType};base64,${file.fileData}`,
    };
  }
  if (file.mimeType.startsWith('audio/')) {
    return {
      type: 'input_audio',
      input_audio: {
        data: file.fileData,
        format: audioFormatFromMimeType(file.mimeType, file.filename),
      },
    };
  }
  return {
    type: 'file',
    file: {
      ...(file.fileId ? { file_id: file.fileId } : {}),
      filename: file.filename,
      file_data: file.fileData,
      mime_type: file.mimeType,
    },
  };
}

function toResponsesResolvedBlock(file: { fileId?: string; filename: string; fileData: string; mimeType: string }): Record<string, unknown> {
  if (file.mimeType.startsWith('image/')) {
    return {
      type: 'input_image',
      image_url: `data:${file.mimeType};base64,${file.fileData}`,
    };
  }
  if (file.mimeType.startsWith('audio/')) {
    return {
      type: 'input_audio',
      input_audio: {
        data: file.fileData,
        format: audioFormatFromMimeType(file.mimeType, file.filename),
      },
    };
  }
  return {
    type: 'input_file',
    ...(!file.fileData && file.fileId ? { file_id: file.fileId } : {}),
    filename: file.filename,
    file_data: ensureBase64DataUrl(file.fileData, file.mimeType),
  };
}

async function resolveOpenAiMessageContent(content: unknown, owner: ProxyResourceOwner): Promise<unknown> {
  if (!Array.isArray(content)) return content;
  return Promise.all(content.map(async (item) => {
    if (!isRecord(item)) return cloneJsonValue(item);
    const fileLike = normalizeInputFileLike(item);
    if (!fileLike || !shouldResolveInlineFileLike(fileLike)) return cloneJsonValue(item);
    return toOpenAiResolvedBlock(await resolveInputFileLike(fileLike, owner));
  }));
}

async function resolveResponsesMessageContent(content: unknown, owner: ProxyResourceOwner): Promise<unknown> {
  if (!Array.isArray(content)) return content;
  return Promise.all(content.map(async (item) => {
    if (!isRecord(item)) return cloneJsonValue(item);
    const fileLike = normalizeInputFileLike(item);
    if (!fileLike || !shouldResolveInlineFileLike(fileLike)) return cloneJsonValue(item);
    return toResponsesResolvedBlock(await resolveInputFileLike(fileLike, owner));
  }));
}

export async function inlineLocalInputFileReferences(
  value: unknown,
  owner: ProxyResourceOwner,
): Promise<unknown> {
  if (Array.isArray(value)) {
    return Promise.all(value.map((item) => inlineLocalInputFileReferences(item, owner)));
  }

  if (!isRecord(value)) return cloneJsonValue(value);

  const fileLike = normalizeInputFileLike(value);
  if (fileLike && shouldResolveInlineFileLike(fileLike)) {
    const resolved = await resolveInputFileLike(fileLike, owner);
    const type = asTrimmedString(value.type).toLowerCase();
    if (type === 'file') {
      return toOpenAiResolvedBlock(resolved);
    }
    if (type === 'input_file') {
      return toResponsesResolvedBlock(resolved);
    }
  }

  const entries = await Promise.all(
    Object.entries(value).map(async ([key, entryValue]) => (
      [key, await inlineLocalInputFileReferences(entryValue, owner)] as const
    )),
  );
  return Object.fromEntries(entries);
}

export async function resolveOpenAiBodyInputFiles(
  body: Record<string, unknown>,
  owner: ProxyResourceOwner,
): Promise<Record<string, unknown>> {
  const next = cloneJsonValue(body);
  if (!Array.isArray(next.messages)) return next;
  next.messages = await Promise.all(next.messages.map(async (message) => {
    if (!isRecord(message)) return cloneJsonValue(message);
    if (Array.isArray(message.content)) {
      return {
        ...message,
        content: await resolveOpenAiMessageContent(message.content, owner),
      };
    }
    if (isRecord(message.content)) {
      const fileLike = normalizeInputFileLike(message.content);
      if (!fileLike) return cloneJsonValue(message);
      return {
        ...message,
        content: [toOpenAiResolvedBlock(await resolveInputFileLike(fileLike, owner))],
      };
    }
    return cloneJsonValue(message);
  }));
  return next;
}

export async function resolveResponsesBodyInputFiles(
  body: Record<string, unknown>,
  owner: ProxyResourceOwner,
): Promise<Record<string, unknown>> {
  const next = cloneJsonValue(body);
  const resolveResponsesInputItem = async (item: unknown): Promise<unknown> => {
    if (!isRecord(item)) return cloneJsonValue(item);
    const fileLike = normalizeInputFileLike(item);
    if (fileLike && shouldResolveInlineFileLike(fileLike)) {
      return toResponsesResolvedBlock(await resolveInputFileLike(fileLike, owner));
    }
    if (Array.isArray(item.content)) {
      return {
        ...item,
        content: await resolveResponsesMessageContent(item.content, owner),
      };
    }
    if (isRecord(item.content)) {
      const nestedFileLike = normalizeInputFileLike(item.content);
      if (!nestedFileLike) return cloneJsonValue(item);
      return {
        ...item,
        content: [toResponsesResolvedBlock(await resolveInputFileLike(nestedFileLike, owner))],
      };
    }
    return cloneJsonValue(item);
  };

  if (Array.isArray(next.input)) {
    next.input = await Promise.all(next.input.map((item) => resolveResponsesInputItem(item)));
    return next;
  }

  if (isRecord(next.input)) {
    next.input = await resolveResponsesInputItem(next.input);
  }

  return next;
}

export function hasNonImageFileInputInOpenAiBody(body: Record<string, unknown>): boolean {
  return summarizeConversationFileInputsInOpenAiBody(body).hasDocument;
}
