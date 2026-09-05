# 后端目录结构

## 运行时布局

后端是一个以 `src/server/` 为根目录的 TypeScript 服务：

```text
src/server/
├── index.ts                 # 启动引导、路由注册、调度器生命周期
├── config.ts                # 环境变量解析和 Fastify 选项
├── desktop.ts               # desktop/静态路由适配器
├── middleware/              # 认证、限流和请求级守卫
├── contracts/               # API 路由共享的 Zod payload parser
├── routes/
│   ├── api/                 # 需要认证的管理端 endpoint
│   └── proxy/               # /v1 和供应商兼容 endpoint 适配器
├── proxy-core/              # 代理编排、surface、executor、provider
├── services/                # 业务工作流、平台适配器、持久化
├── transformers/            # 协议纯净的请求/响应转换
├── db/                      # Drizzle schema、连接、迁移、兼容处理
└── shared/                 # 服务端内部共享的纯逻辑与兼容 facade
```

长期目录契约也记录在 `docs/project-structure.md` 中。

## 所有权边界

### 路由只做适配

`src/server/routes/api/**` 和 `src/server/routes/proxy/**` 负责注册 Fastify handler、读取请求上下文、调用 service/surface，并组装 HTTP 响应。它们可以执行小型边界归一化，但不得拥有代理 retry 策略、stream 生命周期、计费或持久化逻辑。

`src/server/routes/proxy/router.ts` 中的代理 router 只安装认证和 endpoint 适配器。`src/server/routes/proxy/endpointFlow.ts` 只从 `src/server/proxy-core/orchestration/` 重新导出 `executeEndpointFlow()`，不得实现第二套流程。`src/server/routes/proxy/architecture-boundaries.test.ts` 中的架构测试用于执行这一边界。

### Core、service 与 transformer

- endpoint fallback 和请求编排放在 `src/server/proxy-core/orchestration/`；共享 channel/session 记账放在 `proxy-core/surfaces/sharedSurface.ts`；供应商特定的运行时工作放在 `proxy-core/providers/` 或 `proxy-core/executors/`。
- 可复用业务工作流和平台集成放在 `src/server/services/`。如果一个 helper 被多个路由导入，它就不应位于 `routes/proxy/`。
- `src/server/transformers/` 必须保持协议纯净，不得导入 Fastify、route module、OAuth service、token router 或运行时 dispatch 代码。`src/server/transformers/final-hard-cut.architecture.test.ts` 是可执行边界检查。
- 数据库访问和兼容处理放在 `src/server/db/`；路由应调用共享 store/service，不得重复 SQL。

### Contract 与 middleware

对外部形态的 JSON，在 `src/server/contracts/` 中新增或扩展 payload parser。路由随后处理 parser 返回的 `{ success, data/error }`。跨领域的认证和限流属于 `middleware/`，不要分别写进每个 endpoint body。

## 命名与文件放置

- 文件名使用 camelCase，并加上能说明职责的后缀，例如 `siteApiEndpointService.ts`、`routeRefreshWorkflow.ts` 和 `proxyLogStore.ts`。
- 测试与生产文件相邻放置，使用 `*.test.ts` 或 `*.test.tsx`。导入/所有权不变量使用 `*.architecture.test.ts`。
- provider adapter 放在 `services/platforms/`，discovery 注册和顺序以 `services/platforms/index.ts` 为准；不要把平台特定 HTTP 逻辑散落到通用 service。注意 `OneApiAdapter`、`VeloeraAdapter` 直接继承 `BasePlatformAdapter`，而 `StandardApiProviderAdapterBase` 是另一条 provider 继承线；抽象前必须先核对 header、quota divisor、models fallback 和 check-in capability。
- 生成的数据库产物放在 `src/server/db/generated/`，SQL migration 文件放在 `drizzle/`。不要手工把生成数据或运行时数据放进 `src/server/`。

## 代表性模块

- 启动与生命周期：`src/server/index.ts`
- API 边界与校验：`src/server/routes/api/sites.ts` 以及 `src/server/contracts/siteRoutePayloads.ts`
- 代理 adapter/core 拆分：`src/server/routes/proxy/chat.ts` 以及 `src/server/proxy-core/surfaces/chatSurface.ts`
- 可复用工作流：`src/server/services/accountMutationWorkflow.ts`
- 协议转换：`src/server/transformers/openai/` 和 `src/server/transformers/anthropic/`
- 持久化：`src/server/db/index.ts`、`src/server/db/schema.ts` 和 `src/server/services/proxyLogStore.ts`

如果现有所有权区域已经适合某项行为，不要再引入并行的 `utils/`、`lib/` 或路由局部副本。

## 共享 proxy log 边界

`src/server/proxy-core/surfaces/sharedSurface.ts` 的 `writeSurfaceProxyLog()` 负责 UTC 时间、消息组合、usage/billing、stream timing、client/session/trace metadata、`insertProxyLog()` 和 best-effort warning。尚未迁移的 endpoint local `logProxy` 必须逐字段对照后再收敛，不能以“同名 helper”掩盖 `downstreamPath`、`upstreamPath` 或默认值差异。
