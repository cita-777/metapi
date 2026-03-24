import React from 'react';
import type { ConversationDraftFile } from '../helpers/modelTesterSession.js';

type ConversationCapability = {
  supported: boolean;
  reason?: string | null;
};

type ConversationComposerProps = {
  isMobile: boolean;
  sending: boolean;
  customRequestMode: boolean;
  conversationFileCapability: ConversationCapability;
  conversationFileSupported: boolean;
  conversationFileAccept: string;
  conversationFileHint: string;
  conversationFiles: ConversationDraftFile[];
  conversationFileInputRef: React.RefObject<HTMLInputElement>;
  input: string;
  canSend: boolean;
  inputBaseStyle: React.CSSProperties;
  onInputChange: (value: string) => void;
  onFilesChange: (fileList: FileList | null) => Promise<void> | void;
  onRemoveConversationFile: (localId: string) => void;
  onSend: () => Promise<void> | void;
  onStop: () => Promise<void> | void;
};

export default function ConversationComposer({
  isMobile,
  sending,
  customRequestMode,
  conversationFileCapability,
  conversationFileSupported,
  conversationFileAccept,
  conversationFileHint,
  conversationFiles,
  conversationFileInputRef,
  input,
  canSend,
  inputBaseStyle,
  onInputChange,
  onFilesChange,
  onRemoveConversationFile,
  onSend,
  onStop,
}: ConversationComposerProps) {
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: isMobile ? 'stretch' : 'flex-end', flexDirection: isMobile ? 'column' : 'row' }}>
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
            accept={conversationFileAccept}
            style={{ display: 'none' }}
            onChange={(event) => {
              void onFilesChange(event.target.files);
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
                  ? (conversationFileCapability.reason || '当前协议暂不支持会话附件注入。')
                  : conversationFileHint}
            </span>
          </div>
          {conversationFiles.length > 0 ? (
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
                    {!sending ? (
                      <button
                        type="button"
                        onClick={() => onRemoveConversationFile(file.localId)}
                        aria-label={`移除附件 ${file.name || file.localId || '附件'}`}
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
                    ) : null}
                  </span>
                );
              })}
            </div>
          ) : null}
        </div>

        <textarea
          value={input}
          onChange={(event) => onInputChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.nativeEvent.isComposing) return;
            if (event.key === 'Enter' && !event.shiftKey) {
              event.preventDefault();
              if (sending) {
                void onStop();
                return;
              }
              void onSend();
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
            void onStop();
            return;
          }
          void onSend();
        }}
        disabled={sending ? false : !canSend}
        className="btn btn-primary"
        style={{
          height: isMobile ? 50 : 78,
          padding: isMobile ? '0 16px' : '0 20px',
          fontSize: 14,
          fontWeight: 600,
          display: 'flex',
          flexDirection: isMobile ? 'row' : 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 4,
          minWidth: isMobile ? '100%' : 88,
          width: isMobile ? '100%' : 'auto',
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
  );
}
