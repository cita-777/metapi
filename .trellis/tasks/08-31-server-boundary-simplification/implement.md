# 服务端边界简化：执行清单

1. 为 accounts 诊断抽取纯 helper/service 和 table-driven tests；先保持 route
   输出不变，再删除重复实现。
2. 核对 `OneApiAdapter`/`VeloeraAdapter` 的真实继承关系和平台差异；先以中性
   策略与参数化 adapter 测试验证，再决定是否抽取共同流程，不强行改为
   `StandardApiProviderAdapterBase` 子类。
3. 统一 shared `recordProxyLog`，逐个迁移 Gemini/completions/embeddings/images/
   search，运行每个 endpoint 的 usage/billing/stream 回归。
4. 迁移 downstream policy、multipart helper 和 TokensPanel；删除对应 drift
   allowlist，扩展 architecture test 防止回归。
5. 运行：

```bash
npm test -- src/server/routes/api/accounts* src/server/services/platforms src/server/proxy-core/surfaces src/server/routes/proxy
npm run typecheck:server
npm run repo:drift-check
npm run build:server
git diff --check
```

停止条件：协议 payload、错误 status、网络超时分类、proxy log 字段或数据库
行为变化时，恢复 facade/旧 owner 并回到父任务评审；不修改 schema。
