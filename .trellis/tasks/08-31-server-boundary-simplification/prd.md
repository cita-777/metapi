# 服务端边界简化

## 目标

在既有 single-source consolidation 之上，消除仍然存在且有证据的服务端重复
编排和 proxy-core 边界债务；保持协议转换、路由策略、权限、数据库和错误语义
不变，让 route 只做适配、service/workflow 才拥有业务流程。

## 已确认事实

- `accounts.ts` 的 `diagnoseVerificationFailure` 与 `detectVerifyFailureReason`
  两段逻辑都解析 shield/user-id、构造 Bearer/Cookie 变体并请求
  `/api/user/self`，只在 endpoint pool 和网络错误语义上有差异。
- `oneApi.ts` 与 `veloera.ts` 重复 check-in、balance、models/context cache；
  差异主要是 header、quota divisor 和文案。
- Gemini、completions、embeddings、images、search 中重复
  `formatUtcSqlDateTime → composeProxyLogMessage → insertProxyLog → catch warn`；
  `sharedSurface.ts` 已有可复用 owner 但并非所有路径使用。
- 当前工作树运行 `repo:drift-check` 为 `0 violations / 0 tracked debt`；同一
  checker 只读扫描 `HEAD` 为 `5 violations / 0 tracked debt`（4 条
  proxy-core → routes/proxy import，1 条 Accounts → Tokens page import）。任务
  记录必须标明扫描对象，不能把历史违规写成当前 debt。

## 需求

1. 抽取中性 `accountVerificationDiagnostics`（或等价 owner），统一两套验证
   诊断，保留 endpoint pool、`requireSiteApiBaseUrl`、network timeout、shield、
   user-id reason 和错误可见性。
2. 先核对平台继承关系：`OneApiAdapter` 与 `VeloeraAdapter` 当前都直接继承
   `BasePlatformAdapter`，不是 `StandardApiProviderAdapterBase` 的子类。只有在
   中性策略 owner 和参数化测试证明兼容后，才考虑抽取共同流程；不得为了“统一”
   强行改变继承树。header、quota divisor、check-in、models/context cache 的
   差异必须显式保留。
3. 统一结构化 `recordProxyLog` helper，迁移 proxy log 重复路径，保留每个
   endpoint 的 path、usageSource、billing/token 默认值和 warning scope。
4. 将 `downstreamPolicy`、multipart helper 等从 routes/proxy 移到正确的中性
   owner；迁移 Accounts TokensPanel 到 domain 子目录，删除已解决的 tracked debt。
5. 每个抽象都有参数化/架构回归测试；不增加 `any`、不改变 HTTP 状态或协议
   payload，不把 route 变成新的业务 owner。

## 验收标准

- [ ] accounts 验证诊断单一 owner 覆盖 shield、needs/invalid user-id、
      Bearer/Cookie、endpoint pool、超时和 network/no-response 语义；原有
      accounts verify/rebind 测试通过。
- [ ] OneApi/Veloera 适配器参数化测试证明 header、配额换算、模型 context cache、
      check-in 成功/失败语义一致。
- [ ] 各 proxy log 路径通过结构化 owner 写入一次，字段、usageSource、billing、
      client/session/trace 元数据与现有契约一致，insert 失败仍按 best-effort
      规则处理。
- [ ] proxy-core 不再新增或保留已解决的 routes/proxy import，Accounts 不再
      直接 import 顶层 Tokens 页面；drift check tracked debt 数量下降。
- [ ] server typecheck、相关服务/route/proxy tests、drift check、build 和
      diff check 通过；schema/migration 未被改动。

## 范围外

- 改变数据库 schema/migration/generated artifacts；
- 改变代理协议转换、路由选择或外部 API 合约；
- 无证据的“大一统 service”重写或删除兼容分支。
