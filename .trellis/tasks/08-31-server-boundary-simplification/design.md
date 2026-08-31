# 服务端边界简化：设计

## 账号验证诊断

service 接受规范化的候选 base URL、凭据/header 变体和 timeout 选项，返回
结构化诊断结果（reason、是否收到响应、HTTP status、是否需要 user id、可重试
信息）。route 只负责选择 endpoint pool 和把结果映射为现有 HTTP 响应。必须
保留 `sawNetworkError && !sawResponse` 等现有语义，不能用 catch-all 把 timeout
变成“未知”。

## OneApi/Veloera 共同流程

两者都直接继承 `BasePlatformAdapter`；`StandardApiProviderAdapterBase` 属于
另一条 provider 继承线，不能直接作为共同基类。若重复流程确实可收敛，应在
中性 service/策略模块中定义可选策略对象：

```ts
type StandardApiAdapterOptions = {
  buildAuthHeaders?: (credential: unknown) => Record<string, string>;
  quotaDivisor?: number;
  checkin?: { successMessage?: string; unsupported?: boolean };
};
```

OneApi/Veloera 的 adapter 或 service 只声明可验证的差异；平台探测、特殊 header、
quota divisor、models fallback、check-in capability 和错误文案仍由平台模块拥有，
避免中性抽象吞掉平台特性。必须先补参数化测试，再决定是否落地抽取。

## Proxy log 所有权

使用命名字段的结构化输入，不再传位置参数或 route-local `any`：

```ts
type ProxyLogRecordInput = {
  request: FastifyRequest;
  path: string;
  usage?: ProxyUsage;
  usageSource?: string;
  billing?: ProxyBillingDetails;
  // downstream/session/trace fields remain explicit
};
```

owner 负责 UTC 时间、消息组合、insert 和 best-effort warning；调用方保留业务
上决定的默认值和是否记录的条件。

## 边界债务（Boundary debt）

把 downstream policy 的 request/auth 适配与纯策略计算分离；把 multipart parser
放到 proxy-core/shared 或 service 中；把 TokensPanel 放进 `pages/tokens/`
或中性组件目录。更新 drift allowlist 只在真实迁移完成后进行。
