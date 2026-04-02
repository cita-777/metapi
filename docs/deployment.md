# 🚢 部署指南

[返回文档中心](./README.md)

---

## 支持的运行方式

| 场景 | 推荐方式 | 对外访问方式 | 数据位置 |
|------|----------|--------------|----------|
| 云服务器 / NAS / 家用主机长期运行 | Docker / Docker Compose / Zeabur | 固定服务地址，例如 `http://your-host:4000` 或反向代理域名 | 你挂载的 `DATA_DIR` / 持久化卷 |
| 免费云部署（24h 在线） | Render + TiDB + UptimeRobot | Render 分配的 `.onrender.com` 域名或自定义域名 | TiDB Serverless（外部 MySQL 数据库） |
| 个人电脑本地使用 | 桌面版安装包 | 桌面窗口；默认本机客户端直连使用 `http://127.0.0.1:4000`，局域网客户端可使用当前机器 IP + `4000`；如有覆盖则按 `METAPI_DESKTOP_SERVER_PORT` 的实际端口访问 | Electron `app.getPath('userData')/data` |
| 二次开发 / 调试 | 本地开发 | 前端 `http://localhost:5173`，后端默认 `http://localhost:4000` | 仓库内 `./data` 或自定义 `DATA_DIR` |

> [!NOTE]
> - 当前不再提供 `Release` 压缩包 + Node.js 运行时的独立部署路径。
> - 生产/长期运行请用 Docker 系列方案；桌面版面向单机本地使用；源码运行请走本地开发流程。

## K3s / Helm 更新中心

如果你现在只是一个最普通的 Docker / Docker Compose 部署，请先跳过这节。

这套能力只适用于：

- 你已经在 K3s / Kubernetes 中部署了 Metapi
- 而且当前 Metapi 是通过 Helm release 管理的

它不适用于：

- 只有一个裸 Docker Compose 容器
- 想直接从管理后台更新外部 Docker 主机上的容器

但如果你是老用户，**正在计划从 Docker Compose 迁到 K3s / Helm，以获得滚动更新能力**，那么这一节和对应专题页是值得提前看的。它写的不是“怎么原地升级 Compose”，而是“迁移完成后你会如何使用更新中心”。

如果你已经通过 Helm 在 K3s / Kubernetes 中部署 Metapi，并希望在管理后台中：

- 查看当前运行版本
- 检查 GitHub Releases / Docker Hub 的稳定版
- 通过集群内 helper 手动触发一次升级

请直接阅读：

- [K3s 更新中心](./k3s-update-center.md)

这页会单独说明 helper 部署、主服务 token 对齐、设置页字段含义、实际升级顺序和已知限制。

## Zeabur 一键部署

<a href="https://zeabur.com/templates/DOX5PR">
  <img alt="Deploy on Zeabur" src="https://zeabur.com/button.svg" height="28">
</a>

点击按钮即可一键部署到 [Zeabur](https://zeabur.com)，无需手动配置 Docker 或服务器。

模板会自动完成：

- 拉取 `1467078763/metapi:latest` 镜像
- 配置 HTTP 端口（4000）
- 挂载持久化存储（`/app/data`）
- 分配域名

部署时需要填写以下变量：

| 变量 | 说明 |
|------|------|
| `AUTH_TOKEN` | 后台管理员登录令牌（请设置强密码） |
| `PROXY_TOKEN` | 下游客户端调用 `/v1/*` 时使用的 Bearer Token |
| `TZ` | 服务时区，影响定时任务和日志（如 `Asia/Shanghai`） |
| `PORT` | 内部监听端口（默认 `4000`，一般无需修改） |

部署完成后，通过 Zeabur 分配的域名访问后台管理面板即可。

---

## Render 一键部署（免费 24h 运行）

<a href="https://render.com/deploy?repo=https://github.com/cita-777/metapi">
  <img alt="Deploy to Render" src="https://render.com/images/deploy-to-render-button.svg" height="28">
</a>

通过 **Render + TiDB + UptimeRobot** 组合，可以实现 **完全免费的 24 小时持续运行**：

| 组件 | 作用 | 免费额度 |
|------|------|----------|
| [Render](https://render.com) | 运行 Metapi 容器 | Free Web Service（750 小时/月，闲置 15 分钟自动休眠） |
| [TiDB Serverless](https://tidbcloud.com) | MySQL 兼容数据库，替代 SQLite 实现数据持久化 | 5 GiB 存储 + 5000 万 Request Units/月 |
| [UptimeRobot](https://uptimerobot.com) | 每 5 分钟 ping 一次，防止 Render 免费实例休眠 | 50 个免费监控 |

> [!IMPORTANT]
> Render 免费版 **不支持持久化磁盘**，容器重启后本地文件会丢失。因此 **必须使用外部数据库**（推荐 TiDB Serverless），不能使用默认的 SQLite。

### 步骤 1：注册 TiDB Serverless 并获取连接串

1. 前往 [TiDB Cloud](https://tidbcloud.com) 注册账号
2. 创建一个 **Serverless** 集群（免费）
3. 在集群概览页点击 **Connect**，在弹出的面板中：
   - **Connection Type**: Public
   - **Database**: ⚠️ **必须改为 `test`**（默认是 `sys`，这是系统库，不允许建表！）
   - 点击 **Generate Password** 生成密码并妥善保存
4. 使用面板中显示的参数拼接 `DB_URL`：

   ```
   mysql://<USERNAME>:<PASSWORD>@<HOST>:4000/test?ssl={"rejectUnauthorized":true}
   ```

   > ⚠️ 注意：`<HOST>`、`<USERNAME>`、`<PASSWORD>` 从 Connect 面板中获取，**数据库名必须用 `test` 而非默认的 `sys`**。

> [!TIP]
> 这里只是以TiDB作为示例，你也可以使用其他提供免费额度的云数据库方案（如 Neon、Supabase 等），只需将 `DB_TYPE` 设为对应的 `mysql` 或 `postgres`，并填入正确的连接串即可。什么？你不会其他的？把步骤复制给Gemini问他怎么改。

### 步骤 2：部署到 Render

**方式一：一键部署（推荐）**

1. 点击上方 **Deploy to Render** 按钮
2. 如果你 Fork 了仓库，也可以使用你自己的仓库地址
3. 在 Render 界面中填写环境变量（见下表）

**方式二：手动创建**

1. 在 [Render Dashboard](https://dashboard.render.com) 点击 **New → Web Service**
2. 连接你的 GitHub 仓库（或使用公开仓库地址 `https://github.com/cita-777/metapi`）
3. 配置：
   - **Environment**: Docker
   - **Dockerfile Path**: `./docker/Dockerfile`
   - **Docker Build Context**: `.`（仓库根目录）
   - **Instance Type**: Free
4. 添加环境变量（见下表）

### 环境变量配置

| 变量 | 说明 | 示例值 |
|------|------|--------|
| `AUTH_TOKEN` | 管理后台登录令牌（**必填**） | 你的强密码 |
| `PROXY_TOKEN` | 代理接口 Bearer Token（**必填**） | 你的代理密钥 |
| `DB_TYPE` | 数据库类型（**必填**） | `mysql` |
| `DB_URL` | TiDB 连接串（**必填**） | `mysql://user:pass@host:4000/db?ssl=...` |
| `DB_SSL` | 启用 SSL 连接 | `true` |
| `TZ` | 时区 | `Asia/Shanghai` |
| `PORT` | 服务端口（默认即可） | `4000` |

### 步骤 3：配置 UptimeRobot 防休眠

Render 免费实例在 15 分钟无流量后会自动休眠。使用 UptimeRobot 定时 ping 可以保持实例 24h 在线：

1. 前往 [UptimeRobot](https://uptimerobot.com) 注册免费账号
2. 添加新监控：
   - **Monitor Type**: HTTP(s)
   - **URL**: `https://your-app.onrender.com`（替换为 Render 分配的域名）
   - **Monitoring Interval**: 5 minutes
3. 保存即可，UptimeRobot 会每 5 分钟访问一次你的服务，防止休眠

> [!TIP]
> 部署完成后，通过 Render 分配的 `.onrender.com` 域名访问后台，使用 `AUTH_TOKEN` 登录即可。也可以在 Render 设置中绑定自定义域名。

---

## Docker Compose 部署（推荐）

### 标准步骤

```bash
mkdir metapi && cd metapi

# 创建 docker-compose.yml（参见快速上手）
# 设置环境变量
export AUTH_TOKEN=your-admin-token
export PROXY_TOKEN=your-proxy-sk-token

# 启动
docker compose up -d
```

### 使用 `.env` 文件

如果不想每次 export，可以创建 `.env` 文件：

```bash
# .env
AUTH_TOKEN=your-admin-token
PROXY_TOKEN=your-proxy-sk-token
TZ=Asia/Shanghai
PORT=4000
```

```bash
docker compose --env-file .env up -d
```

> ⚠️ `.env` 文件包含敏感信息，请勿提交到 Git 仓库。

## Docker 命令部署

```bash
docker run -d --name metapi \
  -p 4000:4000 \
  -e AUTH_TOKEN=your-admin-token \
  -e PROXY_TOKEN=your-proxy-sk-token \
  -e TZ=Asia/Shanghai \
  -v ./data:/app/data \
  --restart unless-stopped \
  1467078763/metapi:latest
```

> **路径说明：**
> - `./data:/app/data` — 相对路径，数据存到当前目录下的 `data` 文件夹
> - 也可以使用绝对路径：`/your/custom/path:/app/data`

## 桌面版部署（Windows / macOS / Linux）

桌面版面向个人电脑本地使用，基本安装与配置流程见 [快速上手 → 桌面版启动](./getting-started.md#方式二-桌面版启动-windows-macos-linux)。

以下是部署相关的补充说明。

### 桌面版特性

- 内置本地 Metapi 服务，无需手动准备 Node.js 运行环境
- 托盘菜单支持重新打开窗口、重启后端、开机自启
- 支持基于 GitHub Releases 的应用内更新检查

> [!IMPORTANT]
> 桌面版首次启动时，如果没有显式注入 `AUTH_TOKEN`，管理员登录令牌默认是 `change-me-admin-token`。
> 这只适合本机初始调试使用，首次登录后应立即修改。

> [!NOTE]
> 服务器部署不再提供裸 Node.js Release 压缩包，统一推荐 Docker / Docker Compose。

### 桌面版升级

1. 通过应用内更新提示安装新版本，或从 Releases 下载最新安装包覆盖安装
2. 用户数据目录会保留，升级后自动继续使用原有数据
3. 如需排查启动问题，优先查看 `app.getPath('userData')/logs` 下的最新日志

Linux 安装包选择建议：

- Fedora / RHEL / CentOS / openSUSE 优先使用 `.rpm`
- Debian / Ubuntu / Linux Mint 优先使用 `.deb`
- 其他发行版可使用 `.AppImage`

## 本地开发运行（源码调试）

开发、调试或提交 PR 的完整流程见 [快速上手 → 本地开发启动](./getting-started.md#方式三-本地开发启动) 和 [CONTRIBUTING.md](../CONTRIBUTING.md)。

> [!NOTE]
> 这条路径是开发流程，不是下载 `Release` 包后再手动跑 Node.js 的替代说法。

---

## 反向代理

以下反向代理配置面向 Docker / 服务器模式。桌面版内置后端默认监听 `0.0.0.0:4000`，但通常仍作为单机桌面应用使用；如果要给局域网或公网客户端访问，请自行配置防火墙、反向代理和认证边界。若你显式设置了 `METAPI_DESKTOP_SERVER_PORT`，请把示例里的 `4000` 改成对应端口。

### Nginx

流式请求（SSE）需要关闭缓冲，否则流式输出会异常：

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:4000;

        # SSE 关键配置
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;

        # 标准代理头
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 超时设置（长对话场景）
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

### Caddy

```
your-domain.com {
    reverse_proxy localhost:4000 {
        flush_interval -1
    }
}
```

## 升级

```bash
# 拉取最新镜像
docker compose pull

# 重新启动（数据不受影响）
docker compose up -d

# 清理旧镜像
docker image prune -f
```

## 回滚

如果升级后出现问题，请参考 [运维手册 → 数据备份与恢复](./operations.md#数据备份) 进行回滚。

核心思路：升级前备份数据目录（或数据库），出问题时停止服务、还原数据、指定旧版镜像重启。

## 数据持久化

不同运行方式的数据目录不同：

| 运行方式 | 数据目录 | 说明 |
|----------|----------|------|
| Docker / Docker Compose / Zeabur | 容器内 `DATA_DIR`（常见为 `/app/data`） | 需要映射到宿主机目录或平台持久化卷 |
| Render + TiDB | TiDB Serverless（外部 MySQL） | 无本地持久化，数据全部存储在 TiDB 云端数据库 |
| 本地开发 | `DATA_DIR`，默认 `./data` | 位于当前仓库工作目录 |
| 桌面版 | `app.getPath('userData')/data` | 不在仓库目录里，升级桌面应用时会保留 |

桌面版日志位于 `app.getPath('userData')/logs`；Docker / 本地开发模式的日志则跟随各自进程输出或你配置的日志目录。

只要备份了对应的数据目录，升级、重启通常都不会丢失现有配置和 SQLite 数据。

完整备份策略见 [运维手册 → 数据备份](./operations.md#数据备份)。

---

## 下一步

- [配置说明](./configuration.md) — 详细环境变量
- [运维手册](./operations.md) — 日志排查、健康检查
