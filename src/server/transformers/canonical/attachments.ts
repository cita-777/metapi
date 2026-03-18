import {
  normalizeInputFileBlock,
  type NormalizedInputFile,
} from '../shared/inputFile.js';

export type CanonicalAttachment = {
  kind: 'file';
  sourceType?: 'file' | 'input_file';
  fileId?: string;
  fileUrl?: string;
  fileData?: string;
  filename?: string;
  mimeType?: string | null;
};

function cloneOptionalString(value: string | null | undefined): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export function canonicalAttachmentFromNormalizedInputFile(
  file: NormalizedInputFile,
): CanonicalAttachment {
  return {
    kind: 'file',
    sourceType: file.sourceType,
    ...(cloneOptionalString(file.fileId) ? { fileId: file.fileId } : {}),
    ...(cloneOptionalString(file.fileUrl) ? { fileUrl: file.fileUrl } : {}),
    ...(cloneOptionalString(file.fileData) ? { fileData: file.fileData } : {}),
    ...(cloneOptionalString(file.filename) ? { filename: file.filename } : {}),
    ...(file.mimeType !== undefined ? { mimeType: file.mimeType } : {}),
  };
}

export function canonicalAttachmentFromInputFileBlock(
  item: Record<string, unknown>,
): CanonicalAttachment | null {
  const normalized = normalizeInputFileBlock(item);
  if (!normalized) return null;
  return canonicalAttachmentFromNormalizedInputFile(normalized);
}

export function canonicalAttachmentToNormalizedInputFile(
  attachment: CanonicalAttachment,
): NormalizedInputFile {
  const hadDataUrl = typeof attachment.fileData === 'string'
    ? /^data:[^;,]+;base64,/i.test(attachment.fileData)
    : undefined;
  return {
    ...(attachment.sourceType ? { sourceType: attachment.sourceType } : {}),
    ...(cloneOptionalString(attachment.fileId) ? { fileId: attachment.fileId } : {}),
    ...(cloneOptionalString(attachment.fileUrl) ? { fileUrl: attachment.fileUrl } : {}),
    ...(cloneOptionalString(attachment.fileData) ? { fileData: attachment.fileData } : {}),
    ...(cloneOptionalString(attachment.filename) ? { filename: attachment.filename } : {}),
    ...(attachment.mimeType !== undefined ? { mimeType: attachment.mimeType } : {}),
    ...(hadDataUrl !== undefined ? { hadDataUrl } : {}),
  };
}
