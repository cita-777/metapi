# 前端类型安全

## TypeScript 配置

共享 `tsconfig.json` 启用 `strict: true`、`forceConsistentCasingInFileNames` 和 `isolatedModules`。web 生产代码由 `tsconfig.web.json` 检查，`tsconfig.web.test.json` 覆盖测试和测试声明。即使旧页面仍有 `any`，新代码也必须遵守严格 contract。

## API Contract 与类型组织

在 `src/web/api.ts` 的 API 边界附近定义 response/request shape，并导出给 page/component。现有示例包括 `RuntimeSettingsPayload`、`ProxyLogListItem`、`OAuthConnectionInfo` 和 `ProxyTestRequestEnvelope`。已知 server contract 为有限集合时，使用 string union 表示 status、method 和 strategy，不要使用不受约束的 string。

页面专属 view model 和 helper input/output type 放在所属 page 或 `pages/helpers/`；server 与 web 共同使用的跨层 contract 放在 `src/shared/`（例如 `shared/tokenRouteContract.ts`）。

## Unknown 边界与运行时归一化

将 JSON、`Response.json()`、`localStorage`、URL parameter 和第三方 metadata 在运行时视为不可信。渲染前用 `Array.isArray`、`typeof`、有限数字检查、discriminant 和小型 type guard 收窄。API client 有意归一化 HTTP error text；页面在存储前归一化可选 array/record。

```ts
const rows = Array.isArray(data?.items)
  ? data.items as ProxyLogListItem[]
  : [];
```

相比在多个 component 重复这个 cast，优先使用 typed API method 或专用 parser。解析持久化 JSON 时，用 `try/catch` 包住 `JSON.parse`，并回退到有效默认值；`App.tsx` 对 user profile 的处理可作参考。

## Assertions 与遗留代码

新代码避免 `as any`、non-null assertion 和未经检查的 cast。使用 `unknown` 加 type guard，或改善导出的 API type。少数遗留 page helper（例如 `pages/helpers/accountConnection.ts`）仍接收 `any`；不要把这条边界复制到新模块，也不要在无关变更中扩大它。

DOM/browser API 在测试或 SSR-like render 中可能不存在时，做 feature detection（`typeof window`、`typeof document`、`typeof navigator`），并只建模所需的窄 shape，例如 `CenteredModal.tsx` 和 `useIsMobile.ts`。

## 验证

服务端 payload 校验由 `src/server/contracts/` 中的 Zod parser 拥有。web client 应依赖 typed API method 的编译期 contract，同时防御性处理 malformed/partial response；当前没有第二套完整 Zod schema。用户输入在 mutation 前需要本地语义校验（例如 `App.tsx` 中的 profile length 检查），server 仍是权威。

## 常见错误

- 假设 `Response.json()` 一定符合声明 shape，却不检查可选字段。
- 为了消除一个缺失属性，把整个 API payload cast 成 `any`。
- 在多个 page 中复制互不相关的 server enum string literal。
- 未做归一化就把 storage/query value 当成 number 或 boolean。
- 添加与共享 server/web contract 不一致的 frontend-only type。
