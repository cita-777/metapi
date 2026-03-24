import { describe, expect, it } from 'vitest';

import {
  buildConversationFileAccept,
  buildConversationFileHint,
  isConversationUploadedFileSupported,
  resolveConversationFileCapability,
} from './conversationFileCapabilities.js';

describe('resolveConversationFileCapability', () => {
  it('keeps OpenAI and Responses on native file references', () => {
    expect(resolveConversationFileCapability('openai')).toEqual({
      supported: true,
      imageMode: 'native',
      audioMode: 'native',
      documentMode: 'native',
      reason: '',
    });
    expect(resolveConversationFileCapability('responses')).toEqual({
      supported: true,
      imageMode: 'native',
      audioMode: 'native',
      documentMode: 'native',
      reason: '',
    });
  });

  it('maps Claude and Gemini media support separately', () => {
    expect(resolveConversationFileCapability('claude')).toEqual({
      supported: true,
      imageMode: 'native',
      audioMode: 'unsupported',
      documentMode: 'inline_only',
      reason: '当前界面的会话附件会以内联文档方式发送。',
    });
    expect(resolveConversationFileCapability('gemini')).toEqual({
      supported: true,
      imageMode: 'native',
      audioMode: 'native',
      documentMode: 'inline_only',
      reason: '当前界面的会话附件会以内联文档方式发送。',
    });
  });

  it('builds the accept list from the supported file kinds', () => {
    expect(buildConversationFileAccept(resolveConversationFileCapability('claude'))).toBe(
      '.pdf,.txt,.md,.markdown,.json,image/*',
    );
    expect(buildConversationFileAccept(resolveConversationFileCapability('gemini'))).toBe(
      '.pdf,.txt,.md,.markdown,.json,image/*,audio/*',
    );
  });

  it('describes the actual per-kind transport behavior', () => {
    expect(buildConversationFileHint(resolveConversationFileCapability('claude'))).toBe(
      '支持 PDF / TXT / Markdown / JSON / 图片；文档会以内联数据注入，图片会按图片部件发送。',
    );
    expect(buildConversationFileHint(resolveConversationFileCapability('gemini'))).toBe(
      '支持 PDF / TXT / Markdown / JSON / 图片 / 音频；文档会以内联数据注入，图片会按图片部件发送，音频会按音频部件发送。',
    );
  });

  it('rejects unsupported file kinds before send', () => {
    const claudeCapability = resolveConversationFileCapability('claude');

    expect(isConversationUploadedFileSupported(claudeCapability, {
      filename: 'paper.pdf',
      mimeType: 'application/pdf',
    })).toBe(true);
    expect(isConversationUploadedFileSupported(claudeCapability, {
      filename: 'chart.png',
      mimeType: 'image/png',
    })).toBe(true);
    expect(isConversationUploadedFileSupported(claudeCapability, {
      filename: 'voice.mp3',
      mimeType: 'audio/mpeg',
    })).toBe(false);
    expect(isConversationUploadedFileSupported(claudeCapability, {
      filename: 'paper.pdf',
      mimeType: 'application/octet-stream',
    })).toBe(true);
  });
});
