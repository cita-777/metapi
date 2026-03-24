import { describe, expect, it } from 'vitest';

import {
  buildConversationAcceptList,
  classifyConversationFileMimeType,
  detectConversationFileKind,
  inferConversationFileMimeType,
  isSupportedConversationFileMimeType,
  resolveConversationFileMimeType,
} from './conversationFileTypes.js';

describe('conversationFileTypes', () => {
  it('classifies conversation file kinds from mime type and filename', () => {
    expect(classifyConversationFileMimeType('image/png')).toBe('image');
    expect(classifyConversationFileMimeType('audio/mpeg')).toBe('audio');
    expect(classifyConversationFileMimeType('application/pdf')).toBe('document');

    expect(detectConversationFileKind({ filename: 'paper.pdf', mimeType: null })).toBe('document');
    expect(detectConversationFileKind({ filename: 'photo.webp', mimeType: null })).toBe('image');
    expect(detectConversationFileKind({ filename: 'voice.mp3', mimeType: null })).toBe('audio');
    expect(detectConversationFileKind({ filename: 'unknown.bin', mimeType: null })).toBe('unknown');
  });

  it('keeps supported mime and accept list rules in one place', () => {
    expect(isSupportedConversationFileMimeType('application/pdf')).toBe(true);
    expect(isSupportedConversationFileMimeType('image/jpeg')).toBe(true);
    expect(isSupportedConversationFileMimeType('audio/wav')).toBe(true);
    expect(isSupportedConversationFileMimeType('application/octet-stream')).toBe(false);

    expect(buildConversationAcceptList({
      document: true,
      image: true,
      audio: false,
    })).toBe('.pdf,.txt,.md,.markdown,.json,image/*');
  });

  it('falls back from generic mime types to filename-based inference consistently', () => {
    expect(inferConversationFileMimeType('photo.avif')).toBe('image/avif');
    expect(resolveConversationFileMimeType('application/octet-stream', 'paper.pdf')).toBe('application/pdf');
    expect(detectConversationFileKind({
      filename: 'paper.pdf',
      mimeType: 'application/octet-stream',
    })).toBe('document');
  });

  it('strips MIME parameters before matching support and kind rules', () => {
    expect(resolveConversationFileMimeType('text/plain; charset=utf-8', 'notes.txt')).toBe('text/plain');
    expect(classifyConversationFileMimeType('text/plain; charset=utf-8')).toBe('document');
    expect(detectConversationFileKind({
      filename: 'notes.txt',
      mimeType: 'text/plain; charset=utf-8',
    })).toBe('document');
    expect(isSupportedConversationFileMimeType('text/plain; charset=utf-8')).toBe(true);
  });
});
