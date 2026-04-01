import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { zhToEnSupplemental } from './i18n.supplement.js';

export type Language = 'zh' | 'en';

const LANGUAGE_STORAGE_KEY = 'app_language';

const zhToEn: Record<string, string> = {
  '管理员': 'Admin',
  '登录令牌无效': 'Invalid admin token',
  '当前 IP 不在管理白名单中': 'Current IP is not in admin allowlist',
  '当前识别到的管理端 IP（由服务端判定）：': 'Current recognized admin IP (server-side detected):',
  '无法连接到服务器': 'Unable to connect to server',
  '请输入管理员令牌后继续。': 'Enter admin token to continue.',
  '管理员令牌': 'Admin Token',
  '管理员入口': 'Admin Access',
  '部署文档': 'Deployment Docs',
  '管理员登录后继续。': 'Continue with admin sign-in.',
  '仅校验本地服务访问权限，不会把令牌发送到第三方。': 'Only checks local service access and never sends the token to a third party.',
  '验证中...': 'Verifying...',
  '登录': 'Sign In',
  '中转站的中转站': 'The Hub of Hubs',
  '把分散的 New API / One API / OneHub 等站点聚合成统一网关，自动发现模型、智能路由、成本更优。': 'Turn fragmented New API / One API / OneHub sites into one unified gateway with auto model discovery, smart routing, and better cost control.',
  '兼容 New API / One API / OneHub / DoneHub / Veloera / AnyRouter / Sub2API': 'Compatible with New API / One API / OneHub / DoneHub / Veloera / AnyRouter / Sub2API',
  '用户名不能为空': 'Username cannot be empty',
  '用户名最多 24 个字符': 'Username can be at most 24 characters',
  '个人信息': 'Profile',
  '右上角头像实时预览': 'Top-right avatar live preview',
  '用户名': 'Username',
  '例如：小王': 'e.g. Alex',
  '头像（Dicebear 随机） · 风格：': 'Avatar (Dicebear Random) · Style:',
  '换一个随机头像': 'Randomize Avatar',
  '取消': 'Cancel',
  '保存': 'Save',
  '关闭': 'Close',
  '打开': 'Open',
  '导航': 'Navigate',
  '重置': 'Reset',
  '全部': 'All',
  '清空': 'Clear',
  '全部已读': 'Mark All Read',
  '控制台': 'Console',
  '仪表盘': 'Dashboard',
  '站点': 'Sites',
  '账号': 'Accounts',
  '未关联站点': 'Unlinked Site',
  '余额': 'Balance',
  '令牌管理': 'Account Tokens',
  '签到记录': 'Check-in Logs',
  '全部签到': 'Check In All',
  '签到中...': 'Checking In...',
  '刷新状态中...': 'Refreshing...',
  '刷新账户状态': 'Refresh Account Status',
  '+ 添加账号': '+ Add Account',
  '路由': 'Routes',
  '模型路由': 'Model Routes',
  '使用日志': 'Usage Logs',
  '暂无使用日志': 'No Usage Logs',
  '可用性监控': 'Availability Monitor',
  '系统': 'System',
  '设置': 'Settings',
  '程序日志': 'System Logs',
  '导入/导出': 'Import/Export',
  '通知设置': 'Notification Settings',
  '暂无通知': 'No Notifications',
  '模型广场': 'Model Marketplace',
  '模型广场刷新进行中': 'Marketplace refresh in progress',
  '已开始刷新模型广场': 'Started refreshing marketplace',
  '没有找到匹配结果': 'No matching results',
  '搜索站点、账号、模型、日志...': 'Search sites, accounts, models, logs...',
  '模型操练场': 'Model Playground',
  '模型测试': 'Model Testing',
  '关于': 'About',
  '关于 Metapi': 'About Metapi',
  '站点文档': 'Site Docs',
  '任务状态已更新': 'Task status updated',
  '会话已过期，请重新登录': 'Session expired, please sign in again',
  '首次使用建议先阅读站点文档：': 'For first-time setup, read site docs: ',
  '首次使用建议先阅读快速上手：': 'For first-time setup, start with Quick Start: ',
  '首次使用建议先阅读快速开始：': 'For first-time setup, start with Quick Start: ',
  '个人信息已保存': 'Profile saved',
  '搜索': 'Search',
  '搜索 (Ctrl+K)': 'Search (Ctrl+K)',
  '通知': 'Notifications',
  '浅色': 'Light',
  '深色': 'Dark',
  '跟随系统': 'Follow System',
  '浅色模式': 'Light Mode',
  '深色模式': 'Dark Mode',
  '退出登录': 'Sign Out',
  '收起侧边栏': 'Collapse Sidebar',
  '系统设置': 'System Settings',
  '站点管理': 'Site Management',
  '账号管理': 'Connection Management',
  '导入 / 导出': 'Import / Export',
  '监控内嵌': 'Embedded Monitor',
  '品牌': 'Brands',
  '全部品牌': 'All Brands',
  '其他': 'Other',
  '供应商': 'Providers',
  '排序方式': 'Sort By',
  '账号数': 'Accounts',
  '令牌数': 'Tokens',
  '延迟': 'Latency',
  '成功率': 'Success Rate',
  '名称': 'Name',
  '收起': 'Collapse',
  '筛选': 'Filter',
  '加载元数据中...': 'Loading metadata...',
  '卡片视图': 'Card View',
  '表格视图': 'Table View',
  '模糊搜索模型名称': 'Fuzzy Search Model Name',
  '覆盖槽位': 'Coverage Slots',
  '去重账号': 'Unique Accounts',
  '平均延迟': 'Avg Latency',
  '共': 'Total',
  '个模型': 'models',
  '个账号': 'accounts',
  '个令牌': 'tokens',
  '个站点': 'sites',
  '令牌': 'Token',
  '复制': 'Copy',
  '复制模型名': 'Copy Model Name',
  '展开': 'Expand',
  '健康': 'Healthy',
  '风险': 'Risk',
  '低延迟': 'Low Latency',
  '基础信息': 'Basic Info',
  '接口能力': 'Endpoint Capabilities',
  '分组计费': 'Group Pricing',
  '暂无标签': 'No Tags',
  '未提供': 'Not Provided',
  '暂无价格元数据': 'No Pricing Metadata',
  '正在加载价格元数据...': 'Loading pricing metadata...',
  '正在加载模型元数据...': 'Loading model metadata...',
  '上游未提供模型说明。': 'Upstream did not provide a model description.',
  '上游未提供文字说明，但已同步标签、能力或价格信息。': 'Upstream did not provide a text description, but tags, capabilities, or pricing data were synchronized.',
  '当前上游仅返回模型 ID，未返回说明字段（常见于很多站点）。': 'The upstream returned only model IDs and no description field (common on many sites).',
  '暂无模型数据': 'No Model Data',
  '请先检查站点与账号状态，然后点击刷新。': 'Check site and account status first, then refresh.',
  '模型名称': 'Model Name',
  '操作': 'Actions',
  '每页条数': 'Rows Per Page',
  '查看': 'Viewing',
  '来自供应商': 'From Provider',
  '品牌的所有模型': 'Brand Models',
  '的模型': 'models',
  '其他未归类的模型': 'Other uncategorized models',
  '所有模型 accountCount 累计值，同一账号在多个模型中会重复计数': 'Cumulative accountCount across all models; same account may be counted repeatedly.',
  '当前筛选范围内去重后的唯一账号数': 'Unique deduplicated accounts in current filters.',
  '刷新选中概率': 'Refresh Selection Probability',
  '自动重建': 'Auto Rebuild',
  '手动增改路由': 'Manual Route Edit',
  '隐藏手动模式': 'Hide Manual Mode',
  '新建群组': 'Create Group',
  '收起群组创建': 'Hide Group Creator',
  '用于创建群组路由（聚合多个上游模型为一个下游模型名，即模型重定向）；自动路由仍会保持开启。': 'Use this to create a group route (aggregate multiple upstream models as one downstream model name); auto-routing remains enabled.',
  '群组显示名（可选，例如 claude-opus-4-6）': 'Group display name (optional, e.g. claude-opus-4-6)',
  '创建群组': 'Create Group',
  '群组已创建': 'Group created',
  '创建群组失败': 'Failed to create group',
  '搜索模型路由...': 'Search model routes...',
  '通道数量': 'Channel Count',
  '排序字段': 'Sort Field',
  '切换排序方向': 'Toggle Sort Direction',
  '升序 ↑': 'Ascending ↑',
  '降序 ↓': 'Descending ↓',
  '手动模式适合高级场景；自动路由仍会保持开启。': 'Manual mode fits advanced scenarios; auto-routing stays enabled.',
  '路由名称（可选，例如 claude 系列）': 'Route name (optional, e.g. Claude Series)',
  '图标（可选，支持 emoji）': 'Icon (optional, supports emoji)',
  '模型匹配（如 gpt-4o、claude-*、re:^claude-.*$）': 'Model pattern (e.g. gpt-4o, claude-*, re:^claude-.*$)',
  '正则请使用 re: 前缀；例如 re:^claude-(opus|sonnet)-4-6$': 'Use re: prefix for regex, e.g. re:^claude-(opus|sonnet)-4-6$',
  '模型映射 key 支持精确匹配、通配符和 re: 正则；按顺序匹配，精确优先。': 'Model mapping keys support exact, glob and re: regex; evaluated in order with exact priority.',
  '规则预览：命中样本': 'Rule preview: matched samples',
  '当前暂无可预览模型，请先同步模型。': 'No preview models yet. Sync models first.',
  '当前规则未命中任何样本模型。': 'Current rule does not match any sample models.',
  '仅展示前 12 个命中样本。': 'Showing only the first 12 matched samples.',
  '映射预览': 'Mapping preview',
  '启用': 'Enabled',
  '禁用': 'Disabled',
  '通道': 'channels',
  '按模型过滤': 'Filter by model',
  '排序保存中': 'Saving order',
  '删除路由': 'Delete Route',
  '选择账号': 'Select Account',
  '条路由': 'routes',
  '品牌路由': 'Brand Routes',
  '群组': 'Groups',
  '全部群组': 'All Groups',
  '群组路由': 'Group Routes',
  '查看群组路由': 'Viewing group routes',
  '查看未归类品牌路由': 'Viewing uncategorized brand routes',
  '当前精确路由': 'Current exact routes',
  '条，为避免首屏卡顿，默认不自动计算概率，点击“加载选择解释”后按需获取。': 'routes. To avoid first-screen lag, probabilities are not auto-calculated by default. Click "Load Selection Explanation" to fetch when needed.',
  '通配符路由按请求实时决策；概率解释仅在精确模型路由中展示。': 'Wildcard routes are decided in real time; probability explanation is shown only for exact model routes.',
  '通配符路由按请求实时决策；概率解释在当前路由内统一估算。': 'Wildcard routes are decided in real time; probability explanation is estimated uniformly within the current route.',
  '系统会根据模型可用性自动生成路由。优先级按 P0/P1 等桶管理，同一桶内可有多个通道；拖动通道或灰色分隔线即可调整。精确模型路由会自动过滤只支持该模型的账号和令牌。群组路由中的优先级调整会直接回写来源通道。选中概率表示请求到达时该通道被选中的概率。成本来源优先级为：实测成本 → 账号配置成本 → 目录参考价 → 默认回退单价。': 'Routes are auto-generated by model availability. Priorities are managed as P0/P1 buckets, and multiple channels can share the same bucket; drag channels or the gray separators to adjust them. Exact model routes auto-filter accounts and tokens that support that model. Priority edits inside group routes write back to the source channels directly. Selection probability is the chance a channel is chosen. Cost priority: measured cost -> account configured cost -> catalog reference price -> default fallback unit price.',
  '该群组会将多个来源模型聚合为一个对外模型名；这里调整优先级桶时会直接回写来源通道。若某个来源模型被其他群组复用，保存前会提示影响范围。': 'This group aggregates multiple source models into one public model name. Priority bucket edits here write back to the source channels directly. If a source model is reused by other groups, you will be warned about the impact before saving.',
  '通配符路由按请求实时决策；下方优先级桶在整条路由内全局生效，来源模型只作为通道标签展示。': 'Wildcard routes decide per request. The priority buckets below apply globally across the whole route, while source models are shown only as channel labels.',
  '系统会根据模型可用性自动生成路由；精确模型路由会自动过滤只支持该模型的账号和令牌。': 'Routes are auto-generated by model availability; exact model routes auto-filter accounts and tokens that support that model.',
  'P 值是硬优先级，只会在当前最高可用优先级内结合权重、成本和健康度随机选择': 'P value is a hard priority. Selection stays within the highest available priority tier, then chooses randomly using weight, cost, and health signals.',
  '忽略 P 值，按全局顺序依次调用；连续失败 3 次后进入分级冷却': 'Ignore P value and call in global order; after 3 consecutive failures the channel enters staged cooldown.',
  '先避开最近失败或不健康站点，再在稳定池里按顺序轮询；P 值表示轮询顺位': 'Avoid recently failed or unhealthy sites first, then rotate through the stable pool in order; P value means rotation order.',
  '当前策略不看 P 值；如果之后切回其他策略，拖拽保存的顺序仍会保留。': 'This strategy does not use P value; if you switch back to other strategies later, the saved drag order is still kept.',
  '当前策略下，稳定站点会按 P 顺序轮换；不稳定站点会被自动降权或临时避让。': 'Under this strategy, stable sites rotate by P order; unstable sites are automatically downweighted or temporarily avoided.',
  '只要更高优先级还有可用通道，后面的通道本次就不会参与选择。': 'As long as a higher-priority tier still has available channels, later channels will not participate in this selection.',
  '选中概率用于解释当前策略下这一次请求更可能落到哪里；轮询和稳定优先更适合把它当作顺序参考。': 'Selection probability explains where this request is more likely to land under the current strategy; for round robin and stable first it is better treated as an order hint.',
  '代理端点': 'Proxy Endpoints',
  '路由行为': 'Routing Behavior',
  '指标口径': 'Metric Notes',
  'metapi 将多个上游兼容供应商聚合为统一的 OpenAI / Claude 下游兼容入口。': 'Metapi aggregates multiple upstream compatible providers into a unified OpenAI / Claude compatible downstream endpoint.',
  '核心目标：自动签到、自动模型发现、自动路由重建、统一代理可观测性。': 'Core goals: auto check-in, auto model discovery, auto route rebuild, and unified proxy observability.',
  '1. 路由根据模型可用性自动生成。': '1. Routes are auto-generated based on model availability.',
  '2. 当模型或账号发生变更时，路由通道会自动重建。': '2. Route channels are auto-rebuilt when models or accounts change.',
  '3. 手动覆盖配置为可选项，且会尽可能保留。': '3. Manual overrides are optional and kept whenever possible.',
  '4. 成本来源优先级：实测成本 → 账号配置成本 → 目录参考价 → 默认回退单价。': '4. Cost source priority: measured cost -> account configured cost -> catalog reference price -> default fallback unit price.',
  '5. 同站点多通道会进行概率分摊，避免仅因通道数量导致过度偏置。': '5. Multi-channel routes from the same site share probability to avoid bias from channel count alone.',
  '1. 模型广场价格来自上游目录数据，用于展示参考。': '1. Marketplace prices come from upstream catalog data for reference.',
  '2. 路由实测成本来自代理真实请求统计，两者不是同一数据源。': '2. Route measured cost comes from real proxy requests; it is not the same data source.',
  '3. 覆盖槽位是模型维度累计值；去重账号是唯一账号数。': '3. Coverage slots are model-level cumulative counts; unique accounts are deduplicated account counts.',
  '请求超时（': 'Request timed out (',
  '未知账号': 'Unknown Account',
  '未知站点': 'Unknown Site',
  '未知': 'Unknown',
  '未设置': 'Not Set',
  '成功': 'Success',
  '失败': 'Failed',
  '警告': 'Warning',
  '信息': 'Info',
  '异常': 'Error',
  '加载中...': 'Loading...',
  '刷新': 'Refresh',
  '保存中...': 'Saving...',
  '保存失败': 'Save failed',
  '同步中...': 'Syncing...',
  '同步': 'Sync',
  '添加': 'Add',
  '编辑': 'Edit',
  '删除': 'Delete',
  '选择站点': 'Select Site',
  '选择令牌（可选）': 'Select Token (optional)',
  '选择账号后同步站点令牌': 'Select an account to sync site tokens',
  '站点名称': 'Site Name',
  '站点 URL (例如 https://api.example.com)': 'Site URL (e.g. https://api.example.com)',
  '自动检测': 'Auto Detect',
  '检测中': 'Detecting',
  '保存站点': 'Save Site',
  '保存修改': 'Save Changes',
  '编辑站点': 'Edit Site',
  '添加站点': 'Add Site',
  '暂无站点': 'No Sites',
  '点击“+ 添加站点”开始使用。': 'Click "+ Add Site" to start.',
  '重建中...': 'Rebuilding...',
  '发送中...': 'Sending...',
  '导入中...': 'Importing...',
  '创建中...': 'Creating...',
  '更新中...': 'Updating...',
  '登录并添加...': 'Logging in and adding...',
  '添加中...': 'Adding...',
  '同步站点令牌': 'Sync Site Tokens',
  '同步全部账号': 'Sync All Accounts',
  '+ 新增令牌': '+ New Token',
  '保存通知设置': 'Save Notification Settings',
  '发送测试通知': 'Send Test Notification',
  '通知设置已保存': 'Notification settings saved',
  '测试通知已发送': 'Test notification sent',
  '操作失败': 'Operation failed',
  '操作已中止': 'Operation aborted',
  '清空日志': 'Clear Logs',
  '加载更多': 'Load More',
  '全部类型': 'All Types',
  '仅看未读': 'Unread Only',
  '时间': 'Time',
  '类型': 'Type',
  '级别': 'Level',
  '标题': 'Title',
  '内容': 'Content',
  '状态': 'Status',
  '已读': 'Read',
  '未读': 'Unread',
  '标记已读': 'Mark Read',
  '标记中...': 'Marking...',
  '清空中...': 'Clearing...',

  // About page
  '中转站的中转站 — 将你在各处注册的 New API / One API / OneHub 等 AI 中转站聚合为一个统一网关。一个 API Key、一个入口，自动发现模型、智能路由、成本最优。': 'The hub of hubs — aggregate all your New API / One API / OneHub relay sites into one unified gateway. One API Key, one endpoint, with auto model discovery, smart routing, and cost optimization.',
  '核心特色': 'Key Features',
  '统一代理网关': 'Unified Proxy Gateway',
  '一个 Key、一个入口，兼容 OpenAI / Claude 下游格式': 'One Key, one endpoint, compatible with OpenAI / Claude downstream formats',
  '智能路由引擎': 'Smart Routing Engine',
  '按成本、延迟、成功率自动选择最优通道，故障自动转移': 'Auto-selects the optimal channel by cost, latency, and success rate with automatic failover',
  '多站点聚合': 'Multi-Site Aggregation',
  '集中管理 New API / One API / OneHub / DoneHub / Veloera 等': 'Centrally manage New API / One API / OneHub / DoneHub / Veloera and more',
  '自动模型发现': 'Auto Model Discovery',
  '上游新增模型自动出现在模型列表，零配置路由生成': 'New upstream models appear automatically, with zero-config route generation',
  '跨站模型覆盖、定价对比、延迟与成功率实测数据': 'Cross-site model coverage, pricing comparison, latency and success rate metrics',
  '自动签到': 'Auto Check-in',
  '定时签到 + 余额刷新，不再手动操心': 'Scheduled check-in and balance refresh, never miss one again',
  '多渠道告警': 'Multi-Channel Alerts',
  'Webhook / Bark / Server酱 / 邮件，余额不足及时提醒': 'Webhook / Bark / ServerChan / Email — get notified when balance is low',
  '轻量部署': 'Lightweight Deployment',
  '单 Docker 容器，内置 SQLite，无外部依赖': 'Single Docker container with built-in SQLite, no external dependencies',
  '技术栈': 'Tech Stack',
  '高性能 Node.js 后端框架': 'High-performance Node.js backend framework',
  '用户界面库': 'User interface library',
  '端到端类型安全': 'End-to-end type safety',
  '原子化样式框架': 'Utility-first CSS framework',
  '轻量 TypeScript ORM': 'Lightweight TypeScript ORM',
  '零配置嵌入式数据库': 'Zero-config embedded database',
  '项目链接': 'Project Links',
  '数据与隐私': 'Data & Privacy',
  'Metapi 完全自托管，所有数据（账号、令牌、路由、日志）均存储在本地 SQLite 数据库中，不会向任何第三方发送数据。代理请求仅在你的服务器与上游站点之间直连传输。': 'Metapi is fully self-hosted. All data (accounts, tokens, routes, logs) is stored in a local SQLite database and never sent to any third party. Proxy requests travel directly between your server and upstream sites.',
};

for (const [source, target] of Object.entries(zhToEnSupplemental)) {
  if (!zhToEn[source]) {
    zhToEn[source] = target;
  }
}

const HAS_HAN_RE = /[\u3400-\u9fff]/;
const HAN_BLOCK_RE = /[\u3400-\u9fff]+/g;
const LATIN_OR_DIGIT_RE = /[A-Za-z0-9]/;
const TRANSLATABLE_ATTRS = ['placeholder', 'title', 'aria-label'] as const;
const SKIP_PARENT_SELECTOR = 'script, style, code, pre, kbd, samp';
const zhToEnPhrases = Object.entries(zhToEn).sort((a, b) => b[0].length - a[0].length);
const textNodeOriginalMap = new WeakMap<Text, string>();
const elementAttrOriginalMap = new WeakMap<Element, Map<string, string>>();

const CJK_PUNCT_TO_ASCII: Record<string, string> = {
  '，': ', ',
  '。': '. ',
  '：': ': ',
  '；': '; ',
  '！': '! ',
  '？': '? ',
  '（': '(',
  '）': ')',
  '【': '[',
  '】': ']',
  '“': '"',
  '”': '"',
  '‘': '\'',
  '’': '\'',
  '、': ', ',
};

function enforceStrictEnglish(text: string): string {
  const normalizedPunctuation = text.replace(/[，。：；！？（）【】“”‘’、]/g, (ch) => CJK_PUNCT_TO_ASCII[ch] ?? ch);
  const strippedHan = normalizedPunctuation.replace(HAN_BLOCK_RE, ' ');
  const compacted = strippedHan.replace(/\s+/g, ' ').trim();
  if (!compacted) return 'Untranslated';
  if (!LATIN_OR_DIGIT_RE.test(compacted)) return 'Untranslated';
  return compacted;
}

function resolveStoredLanguage(): Language {
  const stored = localStorage.getItem(LANGUAGE_STORAGE_KEY);
  if (stored === 'zh' || stored === 'en') return stored;
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en';
}

let runtimeLanguage: Language = 'zh';

export function translateText(text: string, language: Language): string {
  if (language === 'zh') return text;
  if (!text) return text;
  if (!HAS_HAN_RE.test(text)) return zhToEn[text] ?? text;
  const exact = zhToEn[text];
  if (exact) return exact;

  let translated = text;
  for (const [source, target] of zhToEnPhrases) {
    if (!source || source === target) continue;
    if (!translated.includes(source)) continue;
    translated = translated.split(source).join(target);
  }
  if (HAS_HAN_RE.test(translated)) return enforceStrictEnglish(translated);
  return translated;
}

export function tr(text: string): string {
  return translateText(text, runtimeLanguage);
}

type I18nContextValue = {
  language: Language;
  setLanguage: (next: Language) => void;
  toggleLanguage: () => void;
  t: (text: string) => string;
};

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [language, setLanguageState] = useState<Language>(() => {
    const resolved = resolveStoredLanguage();
    runtimeLanguage = resolved;
    return resolved;
  });

  useEffect(() => {
    runtimeLanguage = language;
    document.documentElement.setAttribute('lang', language === 'zh' ? 'zh-CN' : 'en');
  }, [language]);

  useEffect(() => {
    const root = document.body;
    if (!root) return;

    const shouldTranslateTextNode = (node: Text): boolean => {
      const parent = node.parentElement;
      if (!parent) return false;
      if (parent.closest(SKIP_PARENT_SELECTOR)) return false;
      if (parent.isContentEditable) return false;
      const value = node.nodeValue || '';
      if (!value.trim()) return false;
      if (!HAS_HAN_RE.test(value) && language !== 'zh') return false;
      return true;
    };

    const processTextNode = (node: Text) => {
      if (!shouldTranslateTextNode(node)) return;
      const current = node.nodeValue || '';
      const stored = textNodeOriginalMap.get(node);
      if (!stored) {
        textNodeOriginalMap.set(node, current);
      } else {
        const expected = translateText(stored, language);
        if (current !== expected && current !== stored) {
          textNodeOriginalMap.set(node, current);
        }
      }
      const source = textNodeOriginalMap.get(node) || current;
      const next = translateText(source, language);
      if (next !== current) {
        node.nodeValue = next;
      }
    };

    const processElementAttrs = (el: Element) => {
      if (el.matches(SKIP_PARENT_SELECTOR)) return;
      let attrMap = elementAttrOriginalMap.get(el);
      if (!attrMap) {
        attrMap = new Map<string, string>();
        elementAttrOriginalMap.set(el, attrMap);
      }

      for (const attr of TRANSLATABLE_ATTRS) {
        const current = el.getAttribute(attr);
        if (!current || !current.trim()) continue;
        const stored = attrMap.get(attr);
        if (!stored) {
          attrMap.set(attr, current);
        } else {
          const expected = translateText(stored, language);
          if (current !== expected && current !== stored) {
            attrMap.set(attr, current);
          }
        }

        const source = attrMap.get(attr) || current;
        const next = translateText(source, language);
        if (next !== current) {
          el.setAttribute(attr, next);
        }
      }
    };

    const walk = (node: Node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        processTextNode(node as Text);
        return;
      }
      if (node.nodeType !== Node.ELEMENT_NODE) return;

      const el = node as Element;
      processElementAttrs(el);
      for (const child of Array.from(el.childNodes)) {
        walk(child);
      }
    };

    walk(root);
    if (language !== 'en') {
      return;
    }

    const observer = new MutationObserver((records) => {
      for (const record of records) {
        if (record.type === 'characterData') {
          processTextNode(record.target as Text);
          continue;
        }

        if (record.type === 'attributes') {
          processElementAttrs(record.target as Element);
          continue;
        }

        if (record.type === 'childList') {
          for (const node of Array.from(record.addedNodes)) {
            walk(node);
          }
        }
      }
    });

    observer.observe(root, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: [...TRANSLATABLE_ATTRS],
    });

    return () => {
      observer.disconnect();
    };
  }, [language]);

  const setLanguage = useCallback((next: Language) => {
    runtimeLanguage = next;
    setLanguageState(next);
    localStorage.setItem(LANGUAGE_STORAGE_KEY, next);
    document.documentElement.setAttribute('lang', next === 'zh' ? 'zh-CN' : 'en');
  }, []);

  const toggleLanguage = useCallback(() => {
    setLanguage(language === 'zh' ? 'en' : 'zh');
  }, [language, setLanguage]);

  const t = useCallback((text: string) => translateText(text, language), [language]);

  const value = useMemo<I18nContextValue>(() => ({
    language,
    setLanguage,
    toggleLanguage,
    t,
  }), [language, setLanguage, toggleLanguage, t]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const value = useContext(I18nContext);
  if (!value) {
    throw new Error('useI18n must be used within I18nProvider');
  }
  return value;
}
