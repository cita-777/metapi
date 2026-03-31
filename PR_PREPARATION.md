# 模型白名单功能 - PR 准备文档

## 功能概述

实现全局模型白名单功能，允许管理员配置只启用特定模型的路由。当白名单配置后，不在白名单中的模型路由会被自动移除，实现精细化的模型访问控制。

## 业务场景

- **成本控制**: 只允许使用价格合理的模型
- **合规要求**: 限制只使用审批通过的模型
- **简化管理**: 隐藏不需要的模型，减少用户困惑
- **测试验证**: 在特定场景下只开放测试模型

## 技术实现

### 1. 配置层 (src/server/config.ts)

```typescript
globalAllowedModels: [] as string[]
```

- 默认为空数组（向后兼容）
- 存储在内存中，启动时从数据库加载

### 2. 数据持久化 (src/server/routes/api/settings.ts)

**数据库存储:**
- Key: `global_allowed_models`
- Value: JSON 字符串数组

**API 接口:**

#### GET /api/settings/runtime
返回当前白名单配置

#### PUT /api/settings/runtime
```json
{
  "globalAllowedModels": ["gpt-4", "gpt-4o", "claude-3-sonnet"]
}
```

**处理流程:**
1. 验证输入（必须是字符串数组）
2. 去重、trim、过滤空值
3. 比较新旧配置
4. 更新数据库和内存配置
5. 如果配置变更，自动触发路由重建

### 3. 路由重建 (src/server/services/modelService.ts)

**核心函数:** `rebuildTokenRoutesFromAvailability()`

```typescript
// 加载白名单
const globalAllowedModels = new Set(
  config.globalAllowedModels.map(m => m.toLowerCase().trim()).filter(Boolean)
);

// 判断模型是否允许
function isModelAllowedByWhitelist(modelName: string): boolean {
  if (globalAllowedModels.size === 0) return true; // 向后兼容
  return globalAllowedModels.has(modelName.toLowerCase().trim());
}

// 添加模型候选时过滤
const addModelCandidate = (modelNameRaw, accountId, tokenId, siteId) => {
  const modelName = (modelNameRaw || '').trim();
  if (!modelName) return;
  if (!isModelAllowedByWhitelist(modelName)) return; // 白名单过滤
  // ... 其他过滤逻辑
};
```

**处理逻辑:**
1. 从 `token_model_availability` 加载所有可用模型
2. 通过 `addModelCandidate()` 过滤，只保留白名单中的模型
3. 创建/更新路由和渠道
4. 删除不在白名单中的旧路由

### 4. 模型候选API (src/server/routes/api/stats.ts)

**接口:** GET /api/models/token-candidates

**返回字段:**
- `models`: 有token的模型
- `modelsWithoutToken`: 无token的模型
- `modelsMissingTokenGroups`: 缺少token分组的模型

**过滤逻辑:**
```typescript
if (globalAllowedModels.size > 0) {
  // 白名单模式：只返回白名单中的模型
  for (const [modelName, candidates] of Object.entries(result)) {
    if (globalAllowedModels.has(modelName.toLowerCase().trim())) {
      filteredResult[modelName] = candidates;
    }
  }
} else {
  // 向后兼容：返回所有模型
  Object.assign(filteredResult, result);
}
```

### 5. 前端UI (src/web/pages/Settings.tsx)

**新增卡片:** "全局模型白名单"

**功能特性:**
- 输入框手动添加模型名称（支持回车）
- 可用模型列表展示（点击快速添加）
- 已选模型徽章显示（绿色徽章）
- 点击 × 删除模型
- "保存模型白名单"按钮
- 保存成功后显示提示并自动刷新页面

**交互流程:**
1. 加载当前白名单配置
2. 加载可用模型列表
3. 用户添加/删除模型
4. 点击保存触发API调用
5. 后端自动重建路由
6. 前端显示成功提示

## 数据流程图

```
用户输入 → Settings API
           ↓
    数据库存储 (global_allowed_models)
           ↓
    内存配置更新 (config.globalAllowedModels)
           ↓
    触发路由重建 (异步后台任务)
           ↓
    加载 token_model_availability
           ↓
    白名单过滤 (isModelAllowedByWhitelist)
           ↓
    创建/更新/删除路由
           ↓
    候选API过滤 (token-candidates)
           ↓
    前端显示过滤后的模型列表
```

## 向后兼容性

| 场景 | 行为 |
|------|------|
| 白名单为空 | 允许所有模型（原有行为） |
| 白名单有值 | 只允许白名单中的模型 |
| 数据库无配置 | 默认为空数组 |
| API未传该字段 | 不修改现有配置 |

## 测试验证

### 功能测试清单

- [x] 白名单为空时，所有模型可见
- [x] 设置白名单后，只显示白名单模型
- [x] 大小写不敏感匹配（GPT-4 = gpt-4）
- [x] 自动trim空格
- [x] 保存后自动触发路由重建
- [x] 路由重建成功后，路由正确过滤
- [x] 候选API正确过滤三个返回字段
- [ ] 前端UI交互正常
- [ ] 输入框支持回车添加
- [ ] 可用模型列表正确显示
- [ ] 点击模型快速添加
- [ ] 删除模型功能正常
- [ ] 保存成功提示显示

### API 测试

```bash
# 查看白名单
curl -H "Authorization: Bearer test-admin-token" \
  http://localhost:4000/api/settings/runtime

# 设置白名单
curl -X PUT \
  -H "Authorization: Bearer test-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"globalAllowedModels": ["gpt-4", "gpt-4o"]}' \
  http://localhost:4000/api/settings/runtime

# 查看模型候选
curl -H "Authorization: Bearer test-admin-token" \
  http://localhost:4000/api/models/token-candidates
```

## 文件修改列表

| 文件 | 修改内容 | 行数 |
|------|---------|-----|
| src/server/config.ts | 新增 globalAllowedModels 配置 | 1 |
| src/server/routes/api/settings.ts | 类型定义、加载、保存、触发重建 | ~80 |
| src/server/services/modelService.ts | 白名单过滤逻辑 | ~20 |
| src/server/routes/api/stats.ts | 候选API过滤 | ~30 |
| src/web/pages/Settings.tsx | 前端UI组件 | ~150 |

**总计:** 约 280 行代码新增/修改

## 性能影响

- **内存:** 新增一个 Set 数据结构，大小为白名单模型数量
- **路由重建:** 无额外开销（仅增加一个 O(1) 的 Set 查找）
- **候选API:** 增加过滤循环，复杂度 O(n)，n为模型数量

**结论:** 性能影响可忽略不计

## 安全考虑

- ✅ 仅管理员可配置（需要 admin token）
- ✅ 输入验证（类型检查、trim、去重）
- ✅ 无SQL注入风险（使用 ORM）
- ✅ 配置变更自动记录日志

## 后续优化建议

1. **批量导入**: 支持从文件批量导入白名单
2. **预设模板**: 提供常用模型组合模板
3. **分组管理**: 支持多个白名单分组
4. **权限控制**: 不同用户看到不同白名单
5. **审计日志**: 记录白名单变更历史

## 已知限制

1. 白名单只支持精确匹配，不支持通配符或正则
2. 模型名称大小写不敏感，但保留原始大小写显示
3. 白名单全局生效，不支持按站点或账号单独配置

## 相关 Issue

- Issue #XXX: 模型访问控制需求
- Issue #XXX: 简化模型列表显示

## 测试环境

- Node.js: v20.x
- pnpm: 8.x
- SQLite: 3.x
- 测试服务器: http://localhost:4000
- 真实模型数据已验证

## 下一步计划

1. ✅ 完成功能开发和测试
2. ✅ 编写PR文档
3. ⏳ 等待用户前端测试验证
4. ⏳ 合并到主仓库
5. ⏳ 开始第二个功能：新站点跳转选择