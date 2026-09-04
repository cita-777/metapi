# 前端 Hook 规范

## 命名与职责

自定义 hook 以 `use` 开头，并返回小而明确的状态/行为 contract。将 DOM、计时和 subscription 细节放入 hook；页面/组件保留领域渲染。当前示例有 `useIsMobile()`、`useAnimatedVisibility()`、`useThemeLabelColor()` 和页面领域的 `useRouteChannels()`。

不得有条件地或在 event handler 中调用 hook。昂贵的派生值或需要稳定 identity 边界时使用 `useMemo`；传给 memoized child 或 effect 且确有需要时使用 `useCallback`。

## Effect 与 cleanup

每个安装 listener、timer、poll、animation frame 或 request 的 effect 都必须 cleanup。`useIsMobile.ts` 移除 `matchMedia`/`resize` listener；`useAnimatedVisibility.ts` 取消 animation frame/timer；modal/drawer fallback 恢复 `document.body.style.overflow` 并移除 Escape listener。浏览器中的 Radix modal overlay 已拥有 `RemoveScroll`，不要在同一 renderer 再创建第二个 body-lock owner。

异步 effect 必须阻止 stale data 覆盖较新的 state。仓库使用 cancelled flag（例如 `About.tsx` 和 `DownstreamKeyDrawer.tsx`）、递增 sequence ref（例如 `ProxyLogs.tsx` 和 `TokenRoutes.tsx`）或 `AbortController`（例如 `Sites.tsx` 和 `ModelTester.tsx`）。选择能覆盖竞态的最小模式，并在用户可见时测试 stale-result case。

```tsx
useEffect(() => {
  let cancelled = false;
  void api.getDownstreamApiKeyOverview(id).then((next) => {
    if (!cancelled) setOverview(next);
  });
  return () => { cancelled = true; };
}, [id]);
```

## 数据获取

没有 React Query/SWR 层。页面在 effect 或显式 handler 中调用 `api` 的 typed method，在本地追踪 loading/error state，并在 mutation 后刷新或 invalidate 自有数据。`api.ts` 负责认证、timeout、error extraction 和 SSE parsing；除非正在实现有明确文档的 browser-only primitive，否则 hook 不得绕过它使用 raw `fetch()`。

对于 polling 或 streaming，在 ref 中保存 `AbortController`/timer，在卸载或 target 变化时停止，并在 UI 中区分 user cancellation 与 timeout。`OAuthManagement.tsx` 和 `settings/UpdateCenterSection.tsx` 是 timer/SSE cleanup 示例。跨域 `no-cors` 探测和 `probe-stream` 属于明确的 browser-only 例外：必须在 helper/页面中拥有自己的 timeout、abort、reader cleanup 和逐项结果，不能伪装成普通管理 API。

## Hook 依赖与状态更新

dependency array 列出每个被引用的 prop、state value 和 callback。下一值依赖前值时使用 functional state update。不要用 ref 掩盖缺失依赖；ref 只用于 lifecycle identity、cancellation 或 imperative handle。保持 effect 窄职责，避免 toast/context object 或无关 UI 变化重启 request。

## 常见错误

- target 改变或 component 卸载后仍更新 state。
- 留下 interval、event listener、animation frame 或 stream reader。
- 缺少 loading/promise guard，启动重复 fetch。
- 把 derived filtering/sorting 放进 effect，而不是 `useMemo`。
- 在没有 owner、原因、auth/timeout/cancellation/test 说明的情况下调用 raw `fetch()`，丢失共享 auth/session-expiry 行为。

## 场景：可取消异步资源与流式批处理

### 1. 适用范围与触发条件（Scope / Trigger）

- Trigger：页面存在可重复读取、轮询、debounce 搜索、文件 body、SSE 或流式
  delta 时适用；普通一次性本地计算不需要引入该 helper。
- Scope：请求生命周期由 `useAsyncResource` 或等价窄 helper 拥有，领域数据、
  URL intent 和 mutation 仍由页面拥有。

### 2. 接口签名（Signatures）

```ts
type AsyncLoader<T> = (
  signal: AbortSignal,
  context: { silent: boolean; forceRefresh: boolean },
) => Promise<T>;

type AsyncResource<T> = {
  data: T | null;
  loading: boolean;
  refreshing: boolean;
  error: Error | null;
  errorKind: 'none' | 'abort' | 'timeout' | 'error';
  cancelled: boolean;
  reload(options?: {
    silent?: boolean;
    dedupe?: boolean;
    forceRefresh?: boolean;
  }): Promise<T | undefined>;
  cancel(): void;
};
```

流式更新使用 `createStreamUpdateBatcher(onFlush, delayMs?)`，在 16–50ms
窗口内提交 delta/raw event，结束、停止、abort 和卸载前必须显式 `flush()`。

### 3. 契约（Contracts）

- 每次新 request 都递增 request identity；旧 response 即使不支持 abort，也
  不能写入新 target/filter 的 state。
- `dedupe=true` 时已有 request 直接复用 promise；显式非 dedupe reload 会
  abort 旧 request。`silent=true` 保留旧 data，并只显示 refreshing。
- `AbortError` 映射为 `errorKind='abort'` 且不当作可操作业务错误；timeout
  映射为 `errorKind='timeout'`；真实失败保留 `Error` 和 `onError` 回调。
- effect cleanup 必须 abort controller、清除 timer/listener、取消 reader，
  并阻止 unmount 后 state 写入。`api.ts` 仍负责认证、timeout、body 和 SSE
  边界，hook 不得创建第二套认证 client。
- stream batcher 只合并提交时机，不拼接或重排单个 cumulative delta；raw
  event 顺序和保留窗口必须与未批处理实现一致。
- 页面进入后台时停止高频 polling，恢复可见时最多触发一次 refresh，并保持
  single-flight。

### 4. 校验与错误矩阵（Validation & Error Matrix）

| 条件 | 必须行为 |
| --- | --- |
| target/filter 改变 | abort 或 stale-guard 旧 request，旧结果不可见 |
| slow request + polling tick | 在途数最多一个；tick 复用或跳过 |
| silent refresh 有旧 data | data 保留，`refreshing=true`，失败不清空旧 data |
| caller cancel/unmount | `AbortSignal.aborted=true`，不 toast 业务错误，不 setState |
| timeout | `errorKind='timeout'`，显示可操作的重试语义 |
| loader 抛真实错误 | `errorKind='error'`、保留 `error`，按页面决定 toast/inline |
| stream stop/error/done | 先 flush，再取消 reader/timer/controller |
| batch window 内多个 cumulative delta | 最终文本与逐帧实现字节/字符等价 |

### 5. 正例、基线与反例（Good / Base / Bad Cases）

- Good：`SearchModal` 将 query 放入 ref，loader 接收 signal，输入变化先
  cancel，再由 debounce 触发 `reload()`；`Dashboard`/`ProxyLogs` polling
  使用 `dedupe=true` 和 visibility guard。
- Base：页面保留自己的 partial-failure 规则（例如 metadata 失败不覆盖基础
  列表），只把 controller、sequence 和状态转移交给 helper。
- Bad：effect 每次 tick 无条件 `fetch()`，或把每个派生过滤结果复制成新的
  server state；这会叠加请求并让 stale response 覆盖当前 UI。

### 6. 必需测试（Tests Required）

- helper 测试：abort、stale、silent refresh、dedupe、timeout/error 分类、
  unmount cleanup 和 `onError`。
- 页面测试：搜索 q1→q2 只显示 q2；轮询慢于 interval 时最多一个在途；
  hidden/visible 转换只刷新一次；metadata/timer 在卸载后无回调。
- stream 测试：batch flush 计数、stop 前 flush、重复 cumulative delta 去重、
  raw event 顺序、reader cancel 和 timer cleanup。
- API 测试：JSON/text/arrayBuffer/SSE body 在 timeout/外部 abort 时都能结束，
  returned `Response` 的 body 取消不会留下 pending promise。

### 7. 错误与正确对照（Wrong vs Correct）

#### 错误示例（Wrong）

```tsx
useEffect(() => {
  const timer = setInterval(() => void api.getProxyLogsQuery(filters), 2000);
  return () => clearInterval(timer);
}, [filters]);
```

#### 正确示例（Correct）

```tsx
const resource = useAsyncResource(
  (signal) => api.getProxyLogsQuery(filtersRef.current, { signal }),
  { autoLoad: false },
);
// polling effect checks visibility and calls reload({ silent: true, dedupe: true })
```
