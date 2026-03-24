import type { PlaygroundProtocol } from './modelTesterSession.js';
import {
  buildConversationAcceptList,
  detectConversationFileKind,
} from '../../../shared/conversationFileTypes.js';

export type ConversationFileTransportMode = 'native' | 'inline_only' | 'unsupported';

export type ConversationFileCapability = {
  supported: boolean;
  imageMode: ConversationFileTransportMode;
  audioMode: ConversationFileTransportMode;
  documentMode: ConversationFileTransportMode;
  reason: string;
};

type ConversationFileDescriptor = {
  filename?: string | null;
  mimeType?: string | null;
};

const isSupportedMode = (mode: ConversationFileTransportMode): boolean => mode !== 'unsupported';

function buildSupportedTypeLabel(capability: ConversationFileCapability): string {
  const labels: string[] = [];
  if (isSupportedMode(capability.documentMode)) labels.push('PDF / TXT / Markdown / JSON');
  if (isSupportedMode(capability.imageMode)) labels.push('图片');
  if (isSupportedMode(capability.audioMode)) labels.push('音频');
  return labels.join(' / ');
}

function buildTransportNotes(capability: ConversationFileCapability): string[] {
  const notes: string[] = [];
  if (capability.documentMode === 'inline_only') notes.push('文档会以内联数据注入');
  if (capability.imageMode === 'native' && capability.documentMode === 'inline_only') {
    notes.push('图片会按图片部件发送');
  }
  if (capability.audioMode === 'native' && capability.documentMode === 'inline_only') {
    notes.push('音频会按音频部件发送');
  }
  return notes;
}

export function resolveConversationFileCapability(
  protocol: PlaygroundProtocol,
): ConversationFileCapability {
  if (protocol === 'openai' || protocol === 'responses') {
    return {
      supported: true,
      imageMode: 'native',
      audioMode: 'native',
      documentMode: 'native',
      reason: '',
    };
  }

  if (protocol === 'claude') {
    return {
      supported: true,
      imageMode: 'native',
      audioMode: 'unsupported',
      documentMode: 'inline_only',
      reason: '当前界面的会话附件会以内联文档方式发送。',
    };
  }

  if (protocol === 'gemini') {
    return {
      supported: true,
      imageMode: 'native',
      audioMode: 'native',
      documentMode: 'inline_only',
      reason: '当前界面的会话附件会以内联文档方式发送。',
    };
  }

  return {
    supported: false,
    imageMode: 'unsupported',
    audioMode: 'unsupported',
    documentMode: 'unsupported',
    reason: '当前协议暂不支持会话附件。',
  };
}

export function buildConversationFileAccept(capability: ConversationFileCapability): string {
  return buildConversationAcceptList({
    document: isSupportedMode(capability.documentMode),
    image: isSupportedMode(capability.imageMode),
    audio: isSupportedMode(capability.audioMode),
  });
}

export function buildConversationFileHint(capability: ConversationFileCapability): string {
  if (!capability.supported) {
    return capability.reason || '当前协议暂不支持会话附件。';
  }

  const typeLabel = buildSupportedTypeLabel(capability);
  if (!typeLabel) {
    return capability.reason || '当前协议暂不支持会话附件。';
  }

  if (
    capability.documentMode === 'native'
    && capability.imageMode === 'native'
    && capability.audioMode === 'native'
  ) {
    return `支持 ${typeLabel}；发送前会先上传到 /v1/files。`;
  }

  const notes = buildTransportNotes(capability);
  if (notes.length <= 0) {
    return `支持 ${typeLabel}。`;
  }
  return `支持 ${typeLabel}；${notes.join('，')}。`;
}

export function isConversationUploadedFileSupported(
  capability: ConversationFileCapability,
  file: ConversationFileDescriptor,
): boolean {
  const kind = detectConversationFileKind(file);
  if (kind === 'document') return isSupportedMode(capability.documentMode);
  if (kind === 'image') return isSupportedMode(capability.imageMode);
  if (kind === 'audio') return isSupportedMode(capability.audioMode);
  return false;
}
