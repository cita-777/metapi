# 全项目简化与前端一致性：技术设计

## 1. 设计目标与非目标

本任务的目标是把已经存在的重复行为收敛到明确的 owner，降低页面和服务
文件的编排复杂度，并让后续新增页面只能沿用同一套组件、样式和请求边界。
所有重构都必须保持现有路由、协议字段、数据库语义、权限语义和用户可见能力。

本任务不做全量 UI 换肤，不把业务页面改造成第三方模板，不引入全局状态库来
替代页面状态，也不借“简化”之名删除功能或跳过现有兼容测试。

## 2. 目标架构

### 2.1 Web 组件边界（Iris 参考模式）

```text
路由页 pages/**
    ↓ 只编排数据、URL intent 和领域状态
领域组件 pages/<domain>/**
    ↓ 只使用项目自己的语义 props
项目 UI 封装 components/ui/**
    ↓ 唯一允许直接引用第三方 UI 原语
Radix primitives + Metapi CSS tokens/classes
```

- Radix 只负责 Dialog、Select、Tabs、Popover 等交互、焦点和无障碍原语；
  不让路由页直接 import `@radix-ui/*`。
- `components/ui/**` 是稳定的项目 API。先保留现有
  `CenteredModal`、`MobileDrawer`、`ModernSelect` 的导出和 props 兼容，再
  在内部逐步委托给 Radix，避免一次改变所有页面和测试树。
- Metapi 继续使用现有靛蓝/灰色 CSS 变量和语义 class。Iris 的 Tailwind
  是参考项目的实现细节，不要求 Metapi 复制其暖色 token 或整体迁移到
  Tailwind。
- `Button`/`AsyncButton`、`Dialog`/`Drawer`、`Select`、`FormField`、
  `AsyncState`、`EmptyState`、`ErrorState` 等基础组件由项目封装层统一
  拥有。业务卡片、路由编辑器、模型测试器和图表继续由领域模块拥有。

### 2.2 样式入口

当前生产代码只有极少量真正的 Tailwind utility 使用，大部分页面依赖
`src/web/index.css` 的 token/class 和 inline style。第一阶段先用静态搜索和
构建产物确认这一事实；若确认没有必须保留的 utility，移除 Tailwind Vite
插件、CSS import 和依赖，并把现有 CSS token/class 明确记录为唯一样式入口。
若搜索发现实际依赖，则保留 Tailwind，但必须将其设为唯一 utility 入口并
禁止新增另一种 CSS 运行时。无论结果如何，页面都不能各自选择技术栈。

### 2.3 异步请求和页面状态

仓库不引入 React Query/SWR 作为全局 server-state 层（现有规范明确页面状态
由 React state + `api.ts` 管理）。新增一个窄职责的可取消异步 hook，例如：

```ts
type AsyncLoader<T> = (signal: AbortSignal) => Promise<T>;

type AsyncResource<T> = {
  data: T | null;
  loading: boolean;
  error: Error | null;
  reload: () => void;
  cancel: () => void;
};
```

具体命名以实现前搜索结果为准，但必须满足：

- 每次 target/filter 变化都会取消或使旧请求失效；
- `AbortError`、超时和真实失败在 UI 中可区分；
- silent refresh 不清空已经可用的数据；
- 页面仍然决定自己的 partial-failure 和 mutation reload 语义；
- 不把派生过滤结果再复制成第二份可变 server state。

`src/web/api.ts` 继续是认证、超时、错误提取和 SSE 的唯一边界。跨域 no-cors
的站点测速是明确的特殊能力，必须由单独的 `probeSiteSpeed` helper 统一
并发、超时和结果映射，而不是把它伪装成普通管理 API。

### 2.4 服务端所有权

- 账号验证诊断下沉到中性 service（建议
  `src/server/services/accountVerificationDiagnostics.ts`），route 只负责
  base URL/endpoint pool 选择和 HTTP 响应适配。
- 代理日志写入通过结构化 `recordProxyLog` owner 统一，保留不同 endpoint
  的 path、usageSource、billing/token 默认值和 warning scope。
- OneApi/Veloera 目前都直接继承 `BasePlatformAdapter`，不是
  `StandardApiProviderAdapterBase` 的子类。若要收敛共同流程，先抽取中性策略或
  helper，并用 header、quota divisor、models fallback、check-in capability 的
  参数化测试证明兼容；不得凭空改继承树。
- `proxy-core` 不再新增对 `routes/proxy` 的依赖。当前 `HEAD` 仍有 5 条违规：4 条
  proxy-core → routes/proxy，1 条 Accounts → Tokens page；当前工作树有对应的
  中性 service/facade 候选，但只有通过完整检查后才能删除 drift allowlist。
- Accounts 的 `TokensPanel` 迁移到领域子目录，解除 top-level page 互相 import 的
  一项边界债务；是否稳定纳入交付仍以 architecture test 和 drift 结果为准。

## 3. 分阶段交付

### 阶段 A：UI 基础与边界守卫

1. 引入最小 Radix 依赖并建立 `components/ui` wrapper；保留旧组件 API。
2. 统一 Dialog/Drawer 的 role、aria、焦点返回、body-scroll 引用计数、
   Escape/backdrop 策略和动画退出行为。
3. 将复制的 settings modal、Search/ChangeKey modal、下游/OAuth drawer、
   `window.confirm`/imperative dialog 逐步改为 wrapper；优先改高风险和
   低业务耦合路径。
4. 以 facade 方式改造 `ModernSelect`，先保持 `options/onChange` 和测试中
   的组件类型，再逐步替换内部实现。
5. 增加 `Button`/`AsyncButton` 和统一反馈 primitive，按页面增量迁移。
6. 扩展 drift check：第三方 UI 直引、认证页面 raw fetch、超大页面 ratchet；
   允许项必须有注释和 tracked-debt 记录。

### 阶段 B：请求、性能与 UX

1. 先迁移 SearchModal、Dashboard、ProxyLogs 三个高收益路径到可取消/单飞
   请求模式；再迁移至少一个普通管理页验证可复用性。
2. 修复 Dashboard 可见性轮询、ProxyLogs 2 秒自动刷新、SearchModal debounce
   竞态和 Models hydrate timer 清理。
3. 把 Dashboard 站点测速改为有上限的并发池，保留跨域 no-cors 能力和逐站
   失败反馈。
4. 对 ModelTester 流式 delta/debug 更新做 16–50ms 的 rAF/批处理，停止或
   abort 时强制 flush，保持字节级内容一致。
5. 复用 TokenRoutes 的 progressive chunk/IntersectionObserver 模式评估
   ProxyLogs/Accounts 大列表；只有测量证明有益时才引入窗口化。
6. 对 below-fold 图表增加可见性门控或更细粒度 chunk，目标是首屏不提前
   下载 2.15MB vchart vendor；图表出现时仍必须正常挂载。
7. 把高频重复 inline style、按钮和 empty-state markup 迁移到 wrapper/class，
   不进行机械式全量替换；每次替换都保留视觉和响应式测试。

### 阶段 C：服务端重复与跨层债务

1. 合并 accounts 两套验证诊断并保留 endpoint pool、网络错误和失败词汇
   语义。
2. 核对 `OneApiAdapter`/`VeloeraAdapter` 的真实继承和差异；先以中性策略与
   参数化 adapter 测试验证，再决定是否收敛共同流程，不强行改为
   `StandardApiProviderAdapterBase` 子类。
3. 统一 completions/embeddings/images/search/Gemini 的 proxy log 写入。
4. 迁移 `downstreamPolicy`、multipart helper 到中性 owner，验证并删除对应的
   proxy-core drift 违规；抽取 TokensPanel 消除页面互引。
5. 对所有跨层改动运行 route/service/transformer architecture tests，确认
   不改变协议转换和数据库行为。

## 4. 兼容性与回滚

- wrapper 优先保持现有导出名、props 和 CSS class；旧组件可作为 facade，
  以便逐页回滚。
- 每个阶段以独立 commit/子任务交付，出现视觉、焦点或协议回归时只回滚
  对应 wrapper/迁移 commit，不回滚用户已有的无关工作。
- 不做数据库迁移；若发现必须改 schema，暂停本任务并另建 schema 需求。
- 不把 `window.confirm` 的同步调用直接替换成未设计好的异步状态；先保留
  过渡 helper 或逐个重写调用方及测试。
- 跨域测速和登录 bootstrap 的 raw fetch 例外必须在架构报告中标注原因、
  owner 和后续迁移状态，不能用“全面禁止”破坏能力。

## 5. 可观测基线与验收数据

当前已验证：

- `npm run typecheck:web`：通过（Node v22.23.1 环境）；
- 规划阶段 `npm run build:web` 采样为 `2613 modules transformed`，约 `5.35s`；
  这是 Node `v22.23.1` 的本地基线，不是发布环境证明。最终复核见任务审计和
  `docs/frontend-architecture.md`。
- 规划阶段 web CSS：`136.78 kB`（gzip `22.00 kB`）；
- 最大 chunk：`vchart-vendor` `2,154.02 kB`（gzip `586.81 kB`）；
- 其他较大路由 chunk：TokenRoutes `176.61 kB`、Settings `105.96 kB`、
  ModelTester `88.98 kB`、DownstreamKeys `65.48 kB`、Accounts `60.73 kB`、
  Sites `59.67 kB`、ProxyLogs `58.56 kB`；
- 当前工作树运行 `npm run repo:drift-check`：`0 violations / 0 tracked debt`；
  同一 checker 只读扫描 `HEAD` 时为 `5 violations / 0 tracked debt`，不能把两种
  口径混写成“历史 debt 已清零”。
- inline `style={{` 热点（文件级近似）：Settings 192、ProxyLogs 185、
  Sites 134、Models 119、Accounts 109、ModelTester 108；
- 页面行数热点：ProxyLogs `3,832`、Accounts `3,499`、ModelTester `3,401`、
  Settings `2,647`、Sites `2,426`、TokenRoutes `2,041`、Dashboard `1,710`。

验收必须同时记录构建 chunk、请求在途数、stale response、关键交互和测试
结果；单纯“编译成功”不视为性能或 UX 完成。
