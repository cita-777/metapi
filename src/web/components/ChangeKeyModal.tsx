import React, { useState } from 'react';
import { api } from '../api.js';
import { useToast } from './Toast.js';
import { persistAuthSession } from '../authSession.js';
import CenteredModal from './CenteredModal.js';
import { AsyncButton, Button } from './ui/Button.js';

export default function ChangeKeyModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [oldToken, setOldToken] = useState('');
  const [newToken, setNewToken] = useState('');
  const [confirmToken, setConfirmToken] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const toast = useToast();

  const handleSubmit = async () => {
    setError('');
    if (!oldToken || !newToken || !confirmToken) {
      setError('请填写所有字段');
      return;
    }
    if (newToken !== confirmToken) {
      setError('两次输入的新 Token 不一致');
      return;
    }
    if (newToken.length < 6) {
      setError('新 Token 至少 6 个字符');
      return;
    }

    setSaving(true);
    try {
      const res = await api.changeAuthToken(oldToken, newToken);
      if (res.success) {
        toast.success('Token 已更新，请使用新 Token 重新登录');
        persistAuthSession(localStorage, newToken);
        onClose();
        setOldToken('');
        setNewToken('');
        setConfirmToken('');
      } else {
        setError(res.message || '更新失败');
      }
    } catch (error: unknown) {
      setError(error instanceof Error ? error.message : '更新失败');
    } finally {
      setSaving(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%', padding: '10px 14px', border: '1px solid var(--color-border)',
    borderRadius: 'var(--radius-sm)', fontSize: 13, outline: 'none',
    background: 'var(--color-bg)', color: 'var(--color-text-primary)',
  };

  return (
    <CenteredModal
      open={open}
      onClose={onClose}
      title="修改管理员 Token"
      maxWidth={420}
      closeOnBackdrop
      closeOnEscape={false}
      showCloseButton={false}
      bodyStyle={{ display: 'flex', flexDirection: 'column', gap: 12 }}
      footer={(
        <>
          <Button onClick={onClose} variant="ghost">取消</Button>
          <AsyncButton onClick={() => void handleSubmit()} variant="primary" loading={saving} loadingLabel="更新中...">
            确认修改
          </AsyncButton>
        </>
      )}
    >
      <>
          <div>
            <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 6 }}>旧 Token</label>
            <input
              type="password"
              value={oldToken}
              onChange={e => { setOldToken(e.target.value); setError(''); }}
              placeholder="输入当前 Token"
              style={inputStyle}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 6 }}>新 Token</label>
            <input
              type="password"
              value={newToken}
              onChange={e => { setNewToken(e.target.value); setError(''); }}
              placeholder="输入新 Token (至少 6 位)"
              style={inputStyle}
            />
          </div>
          <div>
            <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--color-text-secondary)', display: 'block', marginBottom: 6 }}>确认新 Token</label>
            <input
              type="password"
              value={confirmToken}
              onChange={e => { setConfirmToken(e.target.value); setError(''); }}
              placeholder="再次输入新 Token"
              style={inputStyle}
            />
          </div>

          {error && (
            <div className="alert alert-error">
              {error}
            </div>
          )}
      </>
    </CenteredModal>
  );
}
