# Feature Proposal: 下游 API Key 独立管理页面（类似 NewAPI）

## 背景
当前管理后台缺少针对下游 API Key 的独立管理能力，导致按应用维度的用量分析、权限治理和审计追踪不够直观。

## 目标
- 提供独立的下游 API Key 管理页面
- 支持按 Key 维度查看请求量、成功率、Token、成本
- 提供完整的 Key 生命周期管理（创建、编辑、启停、轮换）

## MVP 功能
1. 列表页：搜索、筛选、排序、分页；展示名称、状态、最近使用、累计请求、成功率、累计 Token、累计成本。
2. 详情页：权限（模型/路由）、限额（请求/成本/Token 可选）、趋势图（24h/7d/30d）。
3. 管理动作：创建/编辑/启用/禁用/轮换/软删除。
4. 安全审计：不展示明文 key，关键操作写审计日志。

## 数据模型建议
- 在 `proxy_logs` 增加 `downstream_api_key_id`（nullable）。
- 请求落库时记录 key_id。
- 新增索引 `(downstream_api_key_id, created_at)`。
- 旧数据兼容读取（null）。

## 接口建议
- `GET /api/management/downstream-keys`
- `GET /api/management/downstream-keys/:id`
- `GET /api/management/downstream-keys/:id/stats?range=24h|7d|30d&bucket=hour|day`
- `POST /api/management/downstream-keys`
- `PATCH /api/management/downstream-keys/:id`
- `POST /api/management/downstream-keys/:id/rotate`

## 验收标准
- 可按 Key 维度查询 Token 历史趋势。
- UI 可完成常见管理动作。
- 不泄露明文密钥，操作可追溯。
- 对现有部署迁移友好。
