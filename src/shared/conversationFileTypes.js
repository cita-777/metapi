export const CONVERSATION_DOCUMENT_ACCEPT_PARTS = ['.pdf', '.txt', '.md', '.markdown', '.json'];
const GENERIC_MIME_TYPES = new Set([
  'application/octet-stream',
  'binary/octet-stream',
]);
const DOCUMENT_MIME_TYPES = new Set([
  'application/json',
  'application/pdf',
  'text/markdown',
  'text/plain',
]);
const DOCUMENT_EXTENSIONS = ['.json', '.md', '.markdown', '.pdf', '.txt'];
const IMAGE_EXTENSIONS = ['.avif', '.bmp', '.gif', '.jpeg', '.jpg', '.png', '.svg', '.webp'];
const AUDIO_EXTENSIONS = ['.aac', '.flac', '.m4a', '.mp3', '.ogg', '.wav', '.weba'];

function normalizeValue(value) {
  return (value || '').trim().toLowerCase();
}

function normalizeMimeType(value) {
  const normalized = normalizeValue(value);
  const [essence] = normalized.split(';');
  return (essence || '').trim();
}

export function inferConversationFileMimeType(filename) {
  const normalized = normalizeValue(filename);
  if (normalized.endsWith('.pdf')) return 'application/pdf';
  if (normalized.endsWith('.txt')) return 'text/plain';
  if (normalized.endsWith('.md') || normalized.endsWith('.markdown')) return 'text/markdown';
  if (normalized.endsWith('.json')) return 'application/json';
  if (normalized.endsWith('.png')) return 'image/png';
  if (normalized.endsWith('.jpg') || normalized.endsWith('.jpeg')) return 'image/jpeg';
  if (normalized.endsWith('.gif')) return 'image/gif';
  if (normalized.endsWith('.webp')) return 'image/webp';
  if (normalized.endsWith('.svg')) return 'image/svg+xml';
  if (normalized.endsWith('.avif')) return 'image/avif';
  if (normalized.endsWith('.bmp')) return 'image/bmp';
  if (normalized.endsWith('.wav')) return 'audio/wav';
  if (normalized.endsWith('.mp3')) return 'audio/mpeg';
  if (normalized.endsWith('.m4a')) return 'audio/mp4';
  if (normalized.endsWith('.ogg')) return 'audio/ogg';
  if (normalized.endsWith('.aac')) return 'audio/aac';
  if (normalized.endsWith('.flac')) return 'audio/flac';
  if (normalized.endsWith('.weba')) return 'audio/webm';
  return 'application/octet-stream';
}

export function resolveConversationFileMimeType(mimeType, filename) {
  const normalizedMimeType = normalizeMimeType(mimeType);
  if (normalizedMimeType && !GENERIC_MIME_TYPES.has(normalizedMimeType)) {
    return normalizedMimeType;
  }
  return inferConversationFileMimeType(filename);
}

export function classifyConversationFileMimeType(mimeType) {
  const normalized = normalizeMimeType(mimeType);
  if (normalized.startsWith('image/')) return 'image';
  if (normalized.startsWith('audio/')) return 'audio';
  return 'document';
}

export function detectConversationFileKind(file) {
  const mimeType = normalizeMimeType(file?.mimeType);
  if (mimeType) {
    if (mimeType.startsWith('image/')) return 'image';
    if (mimeType.startsWith('audio/')) return 'audio';
    if (DOCUMENT_MIME_TYPES.has(mimeType)) return 'document';
    if (!GENERIC_MIME_TYPES.has(mimeType)) return 'unknown';
  }

  const filename = normalizeValue(file?.filename);
  if (!filename) return 'unknown';
  if (DOCUMENT_EXTENSIONS.some((extension) => filename.endsWith(extension))) return 'document';
  if (IMAGE_EXTENSIONS.some((extension) => filename.endsWith(extension))) return 'image';
  if (AUDIO_EXTENSIONS.some((extension) => filename.endsWith(extension))) return 'audio';
  return 'unknown';
}

export function isSupportedConversationFileMimeType(mimeType) {
  const normalized = normalizeMimeType(mimeType);
  return DOCUMENT_MIME_TYPES.has(normalized)
    || normalized.startsWith('image/')
    || normalized.startsWith('audio/');
}

export function buildConversationAcceptList(input) {
  const parts = [];
  if (input.document) parts.push(...CONVERSATION_DOCUMENT_ACCEPT_PARTS);
  if (input.image) parts.push('image/*');
  if (input.audio) parts.push('audio/*');
  return parts.join(',');
}
