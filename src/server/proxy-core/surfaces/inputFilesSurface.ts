import type { ProxyResourceOwner } from '../../middleware/auth.js';
import { getProxyFileByPublicIdForOwner } from '../../services/proxyFileStore.js';
import {
  inferInputFileMimeType,
  normalizeInputFileBlock,
  toOpenAiChatFileBlock,
  toResponsesInputFileBlock,
  type NormalizedInputFile,
} from '../../transformers/shared/inputFile.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function isSupportedFileMimeType(mimeType: string): boolean {
  return mimeType === 'application/pdf'
    || mimeType === 'text/plain'
    || mimeType === 'text/markdown'
    || mimeType === 'application/json'
    || mimeType.startsWith('image/')
    || mimeType.startsWith('audio/');
}

export class ProxyInputFileResolutionError extends Error {
  statusCode: number;
  payload: unknown;

  constructor(statusCode: number, payload: unknown) {
    super(typeof payload === 'object' && payload && 'error' in (payload as Record<string, unknown>)
      ? String(((payload as { error?: { message?: unknown } }).error?.message) || 'input file resolution failed')
      : 'input file resolution failed');
    this.name = 'ProxyInputFileResolutionError';
    this.statusCode = statusCode;
    this.payload = payload;
  }
}

function buildInvalidRequest(message: string): ProxyInputFileResolutionError {
  return new ProxyInputFileResolutionError(400, {
    error: {
      message,
      type: 'invalid_request_error',
    },
  });
}

function buildNotFound(message: string): ProxyInputFileResolutionError {
  return new ProxyInputFileResolutionError(404, {
    error: {
      message,
      type: 'not_found_error',
    },
  });
}

async function resolveInputFileBlock(
  item: Record<string, unknown>,
  owner: ProxyResourceOwner,
): Promise<Record<string, unknown>> {
  const normalized = normalizeInputFileBlock(item);
  if (!normalized) return item;

  let resolved: NormalizedInputFile = { ...normalized };

  if (!resolved.fileData && resolved.fileId?.startsWith('file-metapi-')) {
    const stored = await getProxyFileByPublicIdForOwner(resolved.fileId, owner);
    if (!stored) {
      throw buildNotFound(`file not found: ${resolved.fileId}`);
    }
    resolved = {
      filename: stored.filename,
      mimeType: stored.mimeType,
      fileData: stored.contentBase64,
    };
  }

  const inferredMimeType = inferInputFileMimeType(resolved);
  if (resolved.fileData && (!inferredMimeType || !isSupportedFileMimeType(inferredMimeType))) {
    throw buildInvalidRequest(`unsupported file mime type: ${inferredMimeType || 'application/octet-stream'}`);
  }
  if (inferredMimeType) {
    resolved.mimeType = inferredMimeType;
  }

  const type = typeof item.type === 'string' ? item.type : '';
  if (type === 'input_file') {
    return toResponsesInputFileBlock(resolved);
  }
  if (type === 'file') {
    return toOpenAiChatFileBlock(resolved);
  }
  return item;
}

export async function inlineLocalInputFileReferences(
  value: unknown,
  owner: ProxyResourceOwner,
): Promise<unknown> {
  if (Array.isArray(value)) {
    return Promise.all(value.map((item) => inlineLocalInputFileReferences(item, owner)));
  }

  if (!isRecord(value)) return value;

  const type = typeof value.type === 'string' ? value.type : '';
  if (type === 'input_file' || type === 'file') {
    return resolveInputFileBlock(value, owner);
  }

  const entries = await Promise.all(
    Object.entries(value).map(async ([key, entryValue]) => [key, await inlineLocalInputFileReferences(entryValue, owner)] as const),
  );
  return Object.fromEntries(entries);
}
