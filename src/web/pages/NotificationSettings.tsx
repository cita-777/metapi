import React, { useEffect, useState } from 'react';
import { api, type RuntimeSettingsPayload } from '../api.js';
import { useToast } from '../components/Toast.js';
import { tr } from '../i18n.js';

type RuntimeSettings = {
    webhookUrl: string;
    barkUrl: string;
    webhookEnabled: boolean;
    barkEnabled: boolean;
    serverChanEnabled: boolean;
    telegramEnabled: boolean;
    telegramApiBaseUrl: string;
    telegramChatId: string;
    telegramUseSystemProxy: boolean;
    telegramMessageThreadId: string;
    smtpEnabled: boolean;
    smtpHost: string;
    smtpPort: number;
    smtpSecure: boolean;
    smtpUser: string;
    smtpPassMasked?: string;
    smtpFrom: string;
    smtpTo: string;
    serverChanKeyMasked?: string;
    telegramBotTokenMasked?: string;
    notifyCooldownSec: number;
};

export default function NotificationSettings() {
    const [runtime, setRuntime] = useState<RuntimeSettings>({
        webhookUrl: '',
        barkUrl: '',
        webhookEnabled: true,
        barkEnabled: true,
        serverChanEnabled: false,
        telegramEnabled: false,
        telegramApiBaseUrl: 'https://api.telegram.org',
        telegramChatId: '',
        telegramUseSystemProxy: false,
        telegramMessageThreadId: '',
        smtpEnabled: false,
        smtpHost: '',
        smtpPort: 587,
        smtpSecure: false,
        smtpUser: '',
        smtpFrom: '',
        smtpTo: '',
        notifyCooldownSec: 300,
    });

    const [serverChanKey, setServerChanKey] = useState('');
    const [telegramBotToken, setTelegramBotToken] = useState('');
    const [smtpPass, setSmtpPass] = useState('');
    const [loading, setLoading] = useState(true);
    const [savingNotify, setSavingNotify] = useState(false);
    const [testingNotify, setTestingNotify] = useState(false);
    const toast = useToast();

    const inputStyle: React.CSSProperties = {
        width: '100%',
        padding: '10px 14px',
        border: '1px solid var(--color-border)',
        borderRadius: 'var(--radius-sm)',
        fontSize: 13,
        outline: 'none',
        background: 'var(--color-bg)',
        color: 'var(--color-text-primary)',
        transition: 'border-color 0.2s',
    };

    const loadSettings = async () => {
        setLoading(true);
        try {
            const runtimeInfo = await api.getRuntimeSettings();
            setRuntime({
                webhookUrl: runtimeInfo.webhookUrl || '',
                barkUrl: runtimeInfo.barkUrl || '',
                webhookEnabled: runtimeInfo.webhookEnabled ?? true,
                barkEnabled: runtimeInfo.barkEnabled ?? true,
                serverChanEnabled: !!runtimeInfo.serverChanEnabled,
                telegramEnabled: !!runtimeInfo.telegramEnabled,
                telegramApiBaseUrl: runtimeInfo.telegramApiBaseUrl || 'https://api.telegram.org',
                telegramChatId: runtimeInfo.telegramChatId || '',
                telegramUseSystemProxy: !!runtimeInfo.telegramUseSystemProxy,
                telegramMessageThreadId: runtimeInfo.telegramMessageThreadId || '',
                smtpEnabled: !!runtimeInfo.smtpEnabled,
                smtpHost: runtimeInfo.smtpHost || '',
                smtpPort: Number(runtimeInfo.smtpPort) || 587,
                smtpSecure: !!runtimeInfo.smtpSecure,
                smtpUser: runtimeInfo.smtpUser || '',
                smtpPassMasked: runtimeInfo.smtpPassMasked || '',
                smtpFrom: runtimeInfo.smtpFrom || '',
                smtpTo: runtimeInfo.smtpTo || '',
                serverChanKeyMasked: runtimeInfo.serverChanKeyMasked || '',
                telegramBotTokenMasked: runtimeInfo.telegramBotTokenMasked || '',
                notifyCooldownSec: Number.isFinite(Number(runtimeInfo.notifyCooldownSec))
                    ? Math.max(0, Math.trunc(Number(runtimeInfo.notifyCooldownSec)))
                    : 300,
            });
        } catch (err: any) {
            toast.error(err?.message || '加载通知设置失败');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadSettings();
    }, []);

    const saveNotify = async () => {
        setSavingNotify(true);
        try {
            const payload: RuntimeSettingsPayload = {
                webhookUrl: runtime.webhookUrl,
                barkUrl: runtime.barkUrl,
                webhookEnabled: runtime.webhookEnabled,
                barkEnabled: runtime.barkEnabled,
                serverChanEnabled: runtime.serverChanEnabled,
                telegramEnabled: runtime.telegramEnabled,
                telegramApiBaseUrl: runtime.telegramApiBaseUrl,
                telegramChatId: runtime.telegramChatId,
                telegramUseSystemProxy: runtime.telegramUseSystemProxy,
                telegramMessageThreadId: runtime.telegramMessageThreadId,
                smtpEnabled: runtime.smtpEnabled,
                smtpHost: runtime.smtpHost,
                smtpPort: runtime.smtpPort,
                smtpSecure: runtime.smtpSecure,
                smtpUser: runtime.smtpUser,
                smtpFrom: runtime.smtpFrom,
                smtpTo: runtime.smtpTo,
                notifyCooldownSec: Math.max(0, Math.trunc(Number(runtime.notifyCooldownSec) || 0)),
            };
            if (serverChanKey.trim()) payload.serverChanKey = serverChanKey.trim();
            if (telegramBotToken.trim()) payload.telegramBotToken = telegramBotToken.trim();
            if (smtpPass.trim()) payload.smtpPass = smtpPass.trim();

            const res = await api.updateRuntimeSettings(payload);
            setRuntime((prev) => ({
                ...prev,
                serverChanKeyMasked: res.serverChanKeyMasked || prev.serverChanKeyMasked,
                telegramBotTokenMasked: res.telegramBotTokenMasked || prev.telegramBotTokenMasked,
                smtpPassMasked: res.smtpPassMasked || prev.smtpPassMasked,
            }));
            setServerChanKey('');
            setTelegramBotToken('');
            setSmtpPass('');
            toast.success('通知设置已保存');
        } catch (err: any) {
            toast.error(err?.message || '保存失败');
        } finally {
            setSavingNotify(false);
        }
    };

    const testNotify = async () => {
        setTestingNotify(true);
        try {
            const res = await api.testNotification();
            toast.success(res?.message || '测试通知已发送');
        } catch (err: any) {
            toast.error(err?.message || '触发测试通知失败');
        } finally {
            setTestingNotify(false);
        }
    };

    if (loading) {
        return (
            <div className="animate-fade-in">
                <div className="skeleton" style={{ width: 220, height: 28, marginBottom: 20 }} />
                <div className="skeleton" style={{ width: '100%', height: 320, borderRadius: 'var(--radius-sm)' }} />
            </div>
        );
    }

    return (
        <div className="animate-fade-in" style={{ paddingBottom: 40 }}>
            {/* 头部标题与操作 */}
            <div className="page-header">
                <h2 className="page-title">{tr('通知设置')}</h2>
                <div className="page-actions">
                    <button onClick={testNotify} disabled={testingNotify} className="btn btn-success">
                        {testingNotify ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 发送中...</> : '发送测试通知'}
                    </button>
                    <button onClick={saveNotify} disabled={savingNotify} className="btn btn-primary">
                        {savingNotify ? <><span className="spinner spinner-sm" style={{ borderTopColor: 'white', borderColor: 'rgba(255,255,255,0.3)' }} /> 保存中...</> : '保存通知设置'}
                    </button>
                </div>
            </div>

            <div style={{ maxWidth: 860, display: 'flex', flexDirection: 'column', gap: 20 }}>

                <div className="card animate-slide-up stagger-1" style={{ padding: 20 }}>
                    <div style={{ fontWeight: 600, fontSize: 15, marginBottom: 8 }}>告警去噪与冷静期</div>
                    <div style={{ fontSize: 12, color: 'var(--color-text-muted)', marginBottom: 12 }}>
                        相同告警在冷静期内不会重复推送；冷静期结束后会自动合并重复条数。
                    </div>
                    <div style={{ maxWidth: 260 }}>
                        <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>
                            冷静期（秒）
                        </div>
                        <input
                            type="number"
                            min={0}
                            value={runtime.notifyCooldownSec}
                            onChange={(e) => setRuntime((prev) => ({
                                ...prev,
                                notifyCooldownSec: Math.max(0, Math.trunc(Number(e.target.value) || 0)),
                            }))}
                            style={inputStyle}
                        />
                    </div>
                </div>

                {/* 卡片：Webhook & Bark */}
                <div className="card animate-slide-up stagger-2" style={{ padding: 24, border: (runtime.webhookEnabled || runtime.barkEnabled) ? '1px solid var(--color-primary)' : '1px solid var(--color-border-light)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{ width: 32, height: 32, borderRadius: 8, background: 'var(--color-primary-light)', color: 'var(--color-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>
                            </div>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 15 }}>Webhook & Bark</div>
                                <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>通过 HTTP URL 推送消息通知（自动识别企业微信、飞书格式）</div>
                            </div>
                        </div>

                        <div style={{ display: 'flex', gap: 16 }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                <span style={{ fontSize: 13, fontWeight: 500, color: runtime.webhookEnabled ? 'var(--color-primary)' : 'var(--color-text-muted)' }}>启用 Webhook</span>
                                <input
                                    type="checkbox"
                                    style={{ width: 16, height: 16, cursor: 'pointer' }}
                                    checked={runtime.webhookEnabled}
                                    onChange={(e) => setRuntime((prev) => ({ ...prev, webhookEnabled: e.target.checked }))}
                                />
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                <span style={{ fontSize: 13, fontWeight: 500, color: runtime.barkEnabled ? 'var(--color-primary)' : 'var(--color-text-muted)' }}>启用 Bark</span>
                                <input
                                    type="checkbox"
                                    style={{ width: 16, height: 16, cursor: 'pointer' }}
                                    checked={runtime.barkEnabled}
                                    onChange={(e) => setRuntime((prev) => ({ ...prev, barkEnabled: e.target.checked }))}
                                />
                            </label>
                        </div>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                        <div style={{ opacity: runtime.webhookEnabled ? 1 : 0.6, transition: 'opacity 0.2s' }}>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>Webhook URL</div>
                            <input
                                value={runtime.webhookUrl}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, webhookUrl: e.target.value }))}
                                placeholder="https://your-webhook-url (可选)"
                                style={inputStyle}
                                disabled={!runtime.webhookEnabled}
                            />
                        </div>
                        <div style={{ opacity: runtime.barkEnabled ? 1 : 0.6, transition: 'opacity 0.2s' }}>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>Bark URL</div>
                            <input
                                value={runtime.barkUrl}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, barkUrl: e.target.value }))}
                                placeholder="https://api.day.app/your_key (可选)"
                                style={inputStyle}
                                disabled={!runtime.barkEnabled}
                            />
                        </div>
                    </div>
                </div>

                {/* 卡片：Server酱 */}
                <div className="card animate-slide-up stagger-3" style={{ padding: 24, border: runtime.serverChanEnabled ? '1px solid var(--color-primary)' : '1px solid var(--color-border-light)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{ width: 32, height: 32, borderRadius: 8, background: 'var(--color-warning-soft)', color: 'var(--color-warning)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" /></svg>
                            </div>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 15 }}>Server酱 (SendKey)</div>
                                <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>微信推送消息支持</div>
                            </div>
                        </div>

                        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                            <span style={{ fontSize: 13, fontWeight: 500, color: runtime.serverChanEnabled ? 'var(--color-primary)' : 'var(--color-text-muted)' }}>启用 Server酱</span>
                            <input
                                type="checkbox"
                                style={{ width: 16, height: 16, cursor: 'pointer' }}
                                checked={runtime.serverChanEnabled}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, serverChanEnabled: e.target.checked }))}
                            />
                        </label>
                    </div>

                    <div style={{ opacity: runtime.serverChanEnabled ? 1 : 0.6, transition: 'opacity 0.2s' }}>
                        <code style={{ display: 'block', padding: '10px 14px', background: 'var(--color-bg)', borderRadius: 'var(--radius-sm)', fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', border: '1px solid var(--color-border-light)', marginBottom: 10 }}>
                            当前配置: {runtime.serverChanKeyMasked || '未设置'}
                        </code>
                        <input
                            type="password"
                            value={serverChanKey}
                            onChange={(e) => setServerChanKey(e.target.value)}
                            placeholder="输入新的 Server酱 Key（留空则不改）"
                            style={inputStyle}
                            disabled={!runtime.serverChanEnabled}
                        />
                    </div>
                </div>

                {/* 卡片：Telegram */} 
                <div className="card animate-slide-up stagger-4" style={{ padding: 24, border: runtime.telegramEnabled ? '1px solid var(--color-primary)' : '1px solid var(--color-border-light)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{ width: 32, height: 32, borderRadius: 8, background: 'var(--color-primary-light)', color: 'var(--color-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 11l18-8-6 18-3-7-9-3z" /></svg>
                            </div>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 15 }}>Telegram Bot</div>
                                <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>通过 Telegram 机器人推送消息通知</div>
                            </div>
                        </div>

                        <div style={{ display: 'flex', gap: 16 }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                <span style={{ fontSize: 13, fontWeight: 500, color: runtime.telegramUseSystemProxy ? 'var(--color-primary)' : 'var(--color-text-muted)' }}>使用系统代理</span>
                                <input
                                    type="checkbox"
                                    style={{ width: 16, height: 16, cursor: 'pointer' }}
                                    checked={runtime.telegramUseSystemProxy}
                                    onChange={(e) => setRuntime((prev) => ({ ...prev, telegramUseSystemProxy: e.target.checked }))}
                                />
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                <span style={{ fontSize: 13, fontWeight: 500, color: runtime.telegramEnabled ? 'var(--color-primary)' : 'var(--color-text-muted)' }}>启用 Telegram</span>
                                <input
                                    type="checkbox"
                                    style={{ width: 16, height: 16, cursor: 'pointer' }}
                                    checked={runtime.telegramEnabled}
                                    onChange={(e) => setRuntime((prev) => ({ ...prev, telegramEnabled: e.target.checked }))}
                                />
                            </label>
                        </div>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '16px 20px', opacity: runtime.telegramEnabled ? 1 : 0.6, transition: 'opacity 0.2s' }}>
                        <div style={{ gridColumn: '1 / -1' }}>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>Telegram API Base URL</div>
                            <input
                                value={runtime.telegramApiBaseUrl}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, telegramApiBaseUrl: e.target.value }))}
                                placeholder="例如: https://your-proxy.example.com"
                                style={inputStyle}
                                disabled={!runtime.telegramEnabled}
                            />
                            <div style={{ marginTop: 8, fontSize: 12, color: 'var(--color-text-muted)' }}>
                                留空或使用默认值时直连官方 Telegram API；如需国内反代，可填写反代前缀。
                            </div>
                        </div>
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>Telegram Chat ID</div>
                            <input
                                value={runtime.telegramChatId}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, telegramChatId: e.target.value }))}
                                placeholder="例如: -1001234567890 或 @your_channel"
                                style={inputStyle}
                                disabled={!runtime.telegramEnabled}
                            />
                        </div>
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>Telegram Topic ID</div>
                            <input
                                value={runtime.telegramMessageThreadId}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, telegramMessageThreadId: e.target.value }))}
                                placeholder="例如: 77"
                                style={inputStyle}
                                disabled={!runtime.telegramEnabled}
                            />
                        </div>
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>
                                Telegram Bot Token
                                {runtime.telegramBotTokenMasked && <span style={{ color: 'var(--color-primary)', marginLeft: 8, fontSize: 12 }}>(当前已设置)</span>}
                            </div>
                            <input
                                type="password"
                                value={telegramBotToken}
                                onChange={(e) => setTelegramBotToken(e.target.value)}
                                placeholder="输入新的 Bot Token（留空则不改）"
                                style={inputStyle}
                                disabled={!runtime.telegramEnabled}
                            />
                        </div>
                    </div>
                </div>

                {/* 卡片：SMTP 邮件设置 */}
                <div className="card animate-slide-up stagger-4" style={{ padding: 24, border: runtime.smtpEnabled ? '1px solid var(--color-primary)' : '1px solid var(--color-border-light)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div style={{ width: 32, height: 32, borderRadius: 8, background: 'var(--color-primary-light)', color: 'var(--color-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                                <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
                            </div>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 15 }}>邮件服务 (SMTP)</div>
                                <div style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>通过电子邮件推送提醒</div>
                            </div>
                        </div>

                        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                            <span style={{ fontSize: 13, fontWeight: 500, color: runtime.smtpEnabled ? 'var(--color-primary)' : 'var(--color-text-muted)' }}>启用 SMTP</span>
                            <input
                                type="checkbox"
                                style={{ width: 16, height: 16, cursor: 'pointer' }}
                                checked={runtime.smtpEnabled}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, smtpEnabled: e.target.checked }))}
                            />
                        </label>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '16px 20px', opacity: runtime.smtpEnabled ? 1 : 0.6, transition: 'opacity 0.2s' }}>
                        {/* Host */}
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>SMTP 服务器</div>
                            <input
                                value={runtime.smtpHost}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, smtpHost: e.target.value }))}
                                placeholder="例如: smtp.qq.com"
                                style={inputStyle}
                                disabled={!runtime.smtpEnabled}
                            />
                        </div>
                        {/* Port & Secure */}
                        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-end' }}>
                            <div style={{ flex: 1 }}>
                                <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>端口</div>
                                <input
                                    type="number"
                                    min={1}
                                    value={runtime.smtpPort}
                                    onChange={(e) => setRuntime((prev) => ({ ...prev, smtpPort: Number(e.target.value) || 0 }))}
                                    style={inputStyle}
                                    disabled={!runtime.smtpEnabled}
                                />
                            </div>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--color-text-secondary)', paddingBottom: 12 }}>
                                <input
                                    type="checkbox"
                                    checked={runtime.smtpSecure}
                                    onChange={(e) => setRuntime((prev) => ({ ...prev, smtpSecure: e.target.checked }))}
                                    disabled={!runtime.smtpEnabled}
                                />
                                启用 TLS/SSL
                            </label>
                        </div>
                        {/* User */}
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>账号用户</div>
                            <input
                                value={runtime.smtpUser}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, smtpUser: e.target.value }))}
                                placeholder="SMTP 用户名"
                                style={inputStyle}
                                disabled={!runtime.smtpEnabled}
                            />
                        </div>
                        {/* Pass */}
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>
                                账号密码
                                {runtime.smtpPassMasked && <span style={{ color: 'var(--color-primary)', marginLeft: 8, fontSize: 12 }}>(当前已设置)</span>}
                            </div>
                            <input
                                type="password"
                                value={smtpPass}
                                onChange={(e) => setSmtpPass(e.target.value)}
                                placeholder="输入以更改密码..."
                                style={inputStyle}
                                disabled={!runtime.smtpEnabled}
                            />
                        </div>
                        {/* From */}
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>发件人地址</div>
                            <input
                                value={runtime.smtpFrom}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, smtpFrom: e.target.value }))}
                                placeholder="例如: admin@example.com"
                                style={inputStyle}
                                disabled={!runtime.smtpEnabled}
                            />
                        </div>
                        {/* To */}
                        <div>
                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 8, color: 'var(--color-text-secondary)' }}>接收地址</div>
                            <input
                                value={runtime.smtpTo}
                                onChange={(e) => setRuntime((prev) => ({ ...prev, smtpTo: e.target.value }))}
                                placeholder="例如: target@example.com"
                                style={inputStyle}
                                disabled={!runtime.smtpEnabled}
                            />
                        </div>

                    </div>
                </div>

            </div>
        </div>
    );
}
