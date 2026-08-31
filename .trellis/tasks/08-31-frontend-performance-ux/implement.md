# 前端请求性能与用户体验：执行清单

1. 记录 baseline（build chunk、页面请求时间线、自动刷新并发、Search stale、
   ModelTester render/flush 计数），建立可重复的 fake API/SSE fixtures。
2. 实现并测试 `useAsyncResource`/等价 helper，先迁移 SearchModal 和一个简单
   页面，再迁移 Dashboard、ProxyLogs。
3. 修复 Dashboard visibility/single-flight、ProxyLogs 2 秒刷新锁、SearchModal
   debounce abort、Models hydrate timer cleanup。
4. 抽取 Dashboard `probeSiteSpeed`，加入并发池、超时和逐站结果；保留明确的
   cross-origin exception 注释和 drift allowlist。
5. 为 ModelTester 流式更新加批处理并做内容等价测试。
6. 评估 ProxyLogs/Accounts progressive list 与图表可见性门控，只有有数据才
   实施；补移动/键盘/空态/错误回归。
7. 生成前后性能报告并运行：

```bash
npm test -- src/web/components/search-modal.results.test.tsx src/web/pages/dashboard.*.test.tsx src/web/pages/ProxyLogs.server-driven.test.tsx
npm run typecheck:web
npm run build:web
npm run repo:drift-check
git diff --check
```

停止条件：内容顺序或协议字段变化、后台轮询继续堆积、跨域测速丢失、或无法
证明性能收益时，保留基线并停止该优化，不扩大重构。
