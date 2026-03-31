# 本地测试环境搭建指南

## 目录结构

```
D:\Code\Projects\Metapi\
├── metapi                          # 主仓库（upstream）
├── metapi-routing-ux-optimization  # 开发 worktree (模型白名单功能)
├── metapi-upstream-latest          # 其他 worktree
└── ...
```

## 快速启动测试服务器

### 1. 进入开发 worktree

```bash
cd D:/Code/Projects/Metapi/metapi-routing-ux-optimization
```

### 2. 安装依赖（首次运行）

```bash
pnpm install
```

### 3. 构建项目

```bash
pnpm build
```

### 4. 启动测试服务器

```bash
DATA_DIR="./tmp/test-db" node dist/server/index.js
```

服务器将在 http://localhost:4000 启动

**测试Token:** `test-admin-token`

### 5. 访问前端

打开浏览器访问: http://localhost:4000

登录使用 Token: `test-admin-token`

## 测试数据准备

### 方式1: 导入真实站点

在前端"站点管理"中添加真实的 new-api 站点：
- 站点URL: 真实的 new-api 地址
- 平台: new-api
- 添加账号和token

然后触发模型发现：
```bash
curl -X POST -H "Authorization: Bearer test-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"refreshModels": true, "wait": true}' \
  http://localhost:4000/api/routes/rebuild
```

### 方式2: 使用测试脚本（可选）

```bash
DATA_DIR="./tmp/test-db" node scripts/seed-test-data.js
```

## 测试模型白名单功能

### 1. 进入设置页面

点击左侧导航"设置"，滚动到"全局模型白名单"卡片

### 2. 测试功能

#### 添加模型到白名单
- **方式1**: 在输入框输入模型名称，按回车
- **方式2**: 点击"可用模型列表"中的模型

#### 删除模型
- 点击已选模型徽章上的 × 按钮

#### 保存配置
- 点击"保存模型白名单"按钮
- 系统自动触发路由重建

### 3. 验证效果

#### 查看路由
进入"令牌路由"页面，确认只有白名单中的模型有路由

#### 查看模型候选
```bash
curl -H "Authorization: Bearer test-admin-token" \
  http://localhost:4000/api/models/token-candidates | python -m json.tool
```

应该只返回白名单中的模型

### 4. API 测试命令

#### 查看当前白名单
```bash
curl -H "Authorization: Bearer test-admin-token" \
  http://localhost:4000/api/settings/runtime | python -m json.tool | grep -A 5 "globalAllowedModels"
```

#### 设置白名单
```bash
curl -X PUT \
  -H "Authorization: Bearer test-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"globalAllowedModels": ["gpt-4", "gpt-4o"]}' \
  http://localhost:4000/api/settings/runtime | python -m json.tool
```

#### 清空白名单（允许所有模型）
```bash
curl -X PUT \
  -H "Authorization: Bearer test-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"globalAllowedModels": []}' \
  http://localhost:4000/api/settings/runtime | python -m json.tool
```

## 停止测试服务器

### 查找进程
```bash
# Windows
netstat -ano | grep ":4000" | grep "LISTENING"

# Linux/Mac
lsof -i :4000
```

### 停止进程
```bash
# Windows (替换 PID)
taskkill //F //PID <PID>

# Linux/Mac
kill <PID>
```

## 开发工作流

### 修改代码后重新构建

```bash
pnpm build
```

### 运行测试

```bash
pnpm test
```

### 提交代码

```bash
git add .
git commit -m "feat: 实现模型白名单功能"
git push origin routing-ux-optimization
```

## 常见问题

### Q: 路由列表为空？
A: 检查 token_model_availability 表是否有数据，触发模型发现重新加载

### Q: 白名单保存后路由消失？
A: 正常现象，白名单会过滤掉不在列表中的模型路由

### Q: 如何恢复所有模型？
A: 清空白名单（设置为空数组 []）即可

## 数据库位置

测试数据库存储在: `./tmp/test-db/hub.db`

查看数据库:
```bash
sqlite3 ./tmp/test-db/hub.db
```

常用查询:
```sql
-- 查看所有站点
SELECT id, name, url, platform FROM sites WHERE status = 'active';

-- 查看所有账号
SELECT id, site_id, username, status FROM accounts;

-- 查看所有token
SELECT id, account_id, name, value_status FROM account_tokens;

-- 查看模型可用性
SELECT COUNT(*) FROM token_model_availability;

-- 查看路由
SELECT COUNT(*) FROM token_routes;
```