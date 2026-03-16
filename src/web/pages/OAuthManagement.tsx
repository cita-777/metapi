import { useEffect, useState } from 'react';
import { api, type OAuthConnectionInfo, type OAuthProviderInfo } from '../api.js';

const POLL_INTERVAL_MS = 1500;

type ActiveSession = {
  provider: string;
  state: string;
};

function openOAuthPopup(provider: string, authorizationUrl: string) {
  if (typeof window === 'undefined' || typeof window.open !== 'function') return;
  const popup = window.open(
    authorizationUrl,
    `oauth-${provider}`,
    'popup=yes,width=540,height=760,resizable=yes,scrollbars=yes',
  );
  if (popup && typeof popup.focus === 'function') {
    popup.focus();
  }
}

function resolveConnectionStatusLabel(status?: string): string {
  return status === 'abnormal' ? '异常' : '正常';
}

export default function OAuthManagement() {
  const [providers, setProviders] = useState<OAuthProviderInfo[]>([]);
  const [connections, setConnections] = useState<OAuthConnectionInfo[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [activeSession, setActiveSession] = useState<ActiveSession | null>(null);
  const [sessionMessage, setSessionMessage] = useState('');
  const [actionLoadingKey, setActionLoadingKey] = useState('');

  const loadConnections = async () => {
    const response = await api.getOAuthConnections();
    setConnections(Array.isArray(response?.items) ? response.items : []);
  };

  const load = async () => {
    try {
      const [providersResponse] = await Promise.all([
        api.getOAuthProviders(),
        loadConnections(),
      ]);
      setProviders(Array.isArray(providersResponse?.providers) ? providersResponse.providers : []);
    } finally {
      setLoaded(true);
    }
  };

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    if (!activeSession) return;

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const poll = async () => {
      try {
        const session = await api.getOAuthSession(activeSession.state);
        if (cancelled) return;

        if (session.status === 'pending') {
          setSessionMessage('等待授权完成');
          timer = setTimeout(poll, POLL_INTERVAL_MS);
          return;
        }

        if (session.status === 'success') {
          setSessionMessage('授权成功');
          await loadConnections();
          setActiveSession(null);
          return;
        }

        setSessionMessage(`授权失败：${session.error || '未知错误'}`);
        setActiveSession(null);
      } catch (error: any) {
        if (cancelled) return;
        setSessionMessage(error?.message || 'OAuth 会话状态查询失败');
        setActiveSession(null);
      }
    };

    poll();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeSession]);

  const handleStart = async (provider: string, accountId?: number) => {
    const actionKey = `start:${provider}:${accountId || 0}`;
    setActionLoadingKey(actionKey);
    try {
      const started = accountId
        ? await api.rebindOAuthConnection(accountId)
        : await api.startOAuthProvider(provider);
      setSessionMessage('等待授权完成');
      setActiveSession({
        provider: started.provider,
        state: started.state,
      });
      openOAuthPopup(provider, started.authorizationUrl);
    } catch (error: any) {
      setSessionMessage(error?.message || '无法启动 OAuth 授权');
    } finally {
      setActionLoadingKey('');
    }
  };

  const handleDelete = async (accountId: number) => {
    if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
      const confirmed = window.confirm('确定要删除这个 OAuth 连接吗？');
      if (!confirmed) return;
    }
    const actionKey = `delete:${accountId}`;
    setActionLoadingKey(actionKey);
    try {
      await api.deleteOAuthConnection(accountId);
      setSessionMessage('连接已删除');
      await loadConnections();
    } catch (error: any) {
      setSessionMessage(error?.message || '删除 OAuth 连接失败');
    } finally {
      setActionLoadingKey('');
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <div className="page-title">OAuth 管理</div>
          <div className="page-subtitle">统一管理需要浏览器授权的上游连接。首版支持 Codex。</div>
        </div>
      </div>

      {sessionMessage && (
        <div className="card" style={{ padding: 16, marginBottom: 16 }}>
          <div style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>{sessionMessage}</div>
        </div>
      )}

      <div className="card" style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>授权入口</div>
        <div style={{ display: 'grid', gap: 12 }}>
          {providers.map((provider) => {
            const actionKey = `start:${provider.provider}:0`;
            return (
              <div key={provider.provider} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>{provider.label}</div>
                  <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>{provider.platform}</div>
                </div>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => handleStart(provider.provider)}
                  disabled={actionLoadingKey === actionKey}
                >
                  {actionLoadingKey === actionKey ? '启动中...' : `连接 ${provider.label}`}
                </button>
              </div>
            );
          })}
          {loaded && providers.length === 0 && (
            <div style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>当前没有可用的 OAuth Provider。</div>
          )}
        </div>
      </div>

      <div className="card" style={{ padding: 20 }}>
        <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>已连接账号</div>
        <div style={{ display: 'grid', gap: 12 }}>
          {connections.map((connection) => {
            const rebindActionKey = `start:${connection.provider}:${connection.accountId}`;
            const deleteActionKey = `delete:${connection.accountId}`;
            return (
              <div key={connection.accountId} style={{ border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', padding: 14 }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 14, fontWeight: 600 }}>{connection.email || connection.username || connection.provider}</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
                      {connection.planType || 'unknown'} · {connection.modelCount} 个模型
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
                      {resolveConnectionStatusLabel(connection.status)} · {connection.routeChannelCount || 0} 条路由
                    </div>
                    {connection.lastModelSyncAt && (
                      <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 4 }}>
                        最近同步: {connection.lastModelSyncAt}
                      </div>
                    )}
                    {connection.lastModelSyncError && (
                      <div style={{ fontSize: 12, color: 'var(--color-danger)', marginTop: 4 }}>
                        {connection.lastModelSyncError}
                      </div>
                    )}
                    {connection.modelsPreview.length > 0 && (
                      <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginTop: 6 }}>
                        {connection.modelsPreview.join(', ')}
                      </div>
                    )}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => handleStart(connection.provider, connection.accountId)}
                      disabled={actionLoadingKey === rebindActionKey || actionLoadingKey === deleteActionKey}
                    >
                      {actionLoadingKey === rebindActionKey ? '启动中...' : '重新授权'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => handleDelete(connection.accountId)}
                      disabled={actionLoadingKey === rebindActionKey || actionLoadingKey === deleteActionKey}
                    >
                      {actionLoadingKey === deleteActionKey ? '删除中...' : '删除连接'}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
          {loaded && connections.length === 0 && (
            <div style={{ fontSize: 13, color: 'var(--color-text-muted)' }}>还没有 OAuth 连接。</div>
          )}
        </div>
      </div>
    </div>
  );
}
