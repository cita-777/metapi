# 前端请求性能与用户体验：设计

## 异步资源模型

保持页面本地状态，新增的 hook 只拥有请求生命周期，不拥有领域数据缓存：

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

实现可用 AbortController + sequence ref；`api.ts` 负责认证、timeout、错误
提取和 SSE，页面负责 partial failure、silent refresh 和 mutation invalidation。
不要把每个页面的 filter/sort 派生结果存成第二份可变状态。

## 轮询与并发

- Dashboard/ProxyLogs 用单飞锁或 abort previous，保证慢请求不会叠加；
- visibilitychange 时停止定时器，重新可见时最多立即刷新一次；
- SearchModal debounce timer、请求 controller 和关闭/卸载都清理；
- `probeSiteSpeed` 使用固定大小 worker pool、每站超时和结构化结果，不改变
  no-cors 的跨站限制。

## 流式渲染

ModelTester 累积 delta 和 debug raw 文本到 ref/队列，在 rAF 或 16–50ms 窗口
内批量提交 React state；完成、停止、错误、abort/unmount 都先 flush 再清理，
确保顺序、重复短 delta、工具调用和 debug 内容不变。

## Chunk 与可见性

保留已有路由 lazy loading。对 vchart 只做可测量的 below-fold gate 或更细
入口拆分，不把同一个库复制进多个 vendor chunk；以 network request、LCP/TTI
近似指标和图表出现后的布局稳定性验收。
