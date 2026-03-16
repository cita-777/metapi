import { tr } from '../i18n.js';
import { SITE_DOCS_URL } from '../docsLink.js';

const VERSION = '1.2.3';

const FEATURES = [
  { icon: '🌐', title: '统一代理网关', desc: '一个 Key、一个入口，兼容 OpenAI / Claude 下游格式' },
  { icon: '🧠', title: '智能路由引擎', desc: '按成本、延迟、成功率自动选择最优通道，故障自动转移' },
  { icon: '📡', title: '多站点聚合', desc: '集中管理 New API / One API / OneHub / DoneHub / Veloera 等' },
  { icon: '🔍', title: '自动模型发现', desc: '上游新增模型自动出现在模型列表，零配置路由生成' },
  { icon: '🏪', title: '模型广场', desc: '跨站模型覆盖、定价对比、延迟与成功率实测数据' },
  { icon: '✅', title: '自动签到', desc: '定时签到 + 余额刷新，不再手动操心' },
  { icon: '🔔', title: '多渠道告警', desc: 'Webhook / Bark / Server酱 / 邮件，余额不足及时提醒' },
  { icon: '📦', title: '轻量部署', desc: '单 Docker 容器，内置 SQLite，无外部依赖' },
];

const TECH_STACK = [
  { name: 'Fastify', desc: '高性能 Node.js 后端框架' },
  { name: 'React', desc: '用户界面库' },
  { name: 'TypeScript', desc: '端到端类型安全' },
  { name: 'Tailwind CSS v4', desc: '原子化样式框架' },
  { name: 'Drizzle ORM', desc: '轻量 TypeScript ORM' },
  { name: 'SQLite', desc: '零配置嵌入式数据库' },
];

const LINKS = [
  { label: 'GitHub', href: 'https://github.com/cita-777/metapi', icon: '📂' },
  { label: 'Docker Hub', href: 'https://hub.docker.com/r/1467078763/metapi', icon: '🐳' },
  { label: '站点文档', href: SITE_DOCS_URL, icon: '📚' },
];

export default function About() {
  return (
    <div className="animate-fade-in" style={{ maxWidth: 860 }}>
      {/* Header */}
      <div className="page-header" style={{ marginBottom: 14 }}>
        <h2 className="page-title">{tr('关于 Metapi')}</h2>
      </div>

      {/* Hero card */}
      <div className="card animate-slide-up stagger-1" style={{ padding: 22, marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 14 }}>
          <img
            src="/logo.png"
            alt="Metapi"
            style={{ width: 48, height: 48, borderRadius: 12, flexShrink: 0 }}
          />
          <div>
            <div style={{ fontSize: 18, fontWeight: 700 }}>Metapi</div>
            <div style={{ fontSize: 12, color: 'var(--color-text-tertiary)', marginTop: 2 }}>v{VERSION}</div>
          </div>
        </div>
        <div style={{ fontSize: 14, color: 'var(--color-text-secondary)', lineHeight: 1.8 }}>
          {tr('中转站的中转站 — 将你在各处注册的 New API / One API / OneHub 等 AI 中转站聚合为一个统一网关。一个 API Key、一个入口，自动发现模型、智能路由、成本最优。')}
        </div>
      </div>

      {/* Features */}
      <div className="card animate-slide-up stagger-2" style={{ padding: 22, marginBottom: 14 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 14 }}>{tr('核心特色')}</h3>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))',
          gap: 10,
        }}>
          {FEATURES.map((f) => (
            <div key={f.title} style={{
              display: 'flex', gap: 10, padding: '8px 0',
              borderBottom: '1px solid var(--color-border-light)',
            }}>
              <span style={{ fontSize: 18, lineHeight: '24px', flexShrink: 0 }}>{f.icon}</span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{tr(f.title)}</div>
                <div style={{ fontSize: 12, color: 'var(--color-text-tertiary)', marginTop: 2, lineHeight: 1.5 }}>
                  {tr(f.desc)}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Tech Stack */}
      <div className="card animate-slide-up stagger-3" style={{ padding: 22, marginBottom: 14 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 14 }}>{tr('技术栈')}</h3>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
          gap: 10,
        }}>
          {TECH_STACK.map((t) => (
            <div key={t.name} style={{
              padding: '10px 14px',
              borderRadius: 8,
              border: '1px solid var(--color-border-light)',
              background: 'var(--color-bg-secondary)',
            }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{t.name}</div>
              <div style={{ fontSize: 12, color: 'var(--color-text-tertiary)', marginTop: 2 }}>
                {tr(t.desc)}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Links */}
      <div className="card animate-slide-up stagger-4" style={{ padding: 22, marginBottom: 14 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 14 }}>{tr('项目链接')}</h3>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {LINKS.map((l) => (
            <a
              key={l.label}
              href={l.href}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '8px 16px', borderRadius: 8,
                border: '1px solid var(--color-border-light)',
                background: 'var(--color-bg-secondary)',
                color: 'var(--color-text-primary)',
                textDecoration: 'none', fontSize: 13, fontWeight: 500,
                transition: 'border-color 0.15s',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--color-primary)')}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--color-border-light)')}
            >
              <span>{l.icon}</span>
              <span>{tr(l.label)}</span>
            </a>
          ))}
        </div>
      </div>

      {/* Privacy */}
      <div className="card animate-slide-up stagger-5" style={{ padding: 22 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 10 }}>{tr('数据与隐私')}</h3>
        <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', lineHeight: 1.8 }}>
          {tr('Metapi 完全自托管，所有数据（账号、令牌、路由、日志）均存储在本地 SQLite 数据库中，不会向任何第三方发送数据。代理请求仅在你的服务器与上游站点之间直连传输。')}
        </div>
      </div>
    </div>
  );
}
