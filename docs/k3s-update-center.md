# ☸️ K3s 更新中心（高级）

[返回部署指南](./deployment.md) · [返回配置说明](./configuration.md) · [返回文档中心](./README.md)

---

本页适用于已经把 Metapi 部署到 **K3s / Kubernetes + Helm** 的用户。

K3s 更新中心的日常入口位于：

```text
设置 → 更新中心
```

本文主要说明三件事：

- 哪些配置直接在后台页面里填写
- 哪些配置仍然需要主服务环境变量或 helper manifest
- 哪些前提不满足时，页面虽然能打开，但无法真正部署

如果你现在的环境只是一个最普通的 **Docker Compose 安装**，只有一个 Metapi 容器，其他什么都没有，那么先记住一句话：

> [!IMPORTANT]
> **如果你只是想原地给现有 Compose 容器加一个“后台点按钮更新”的能力，那你现在大概率用不上这页。**
>
> 当前“更新中心”不会直接帮你更新一台普通 Docker 主机上的 Compose 容器。它依赖集群里的 Deploy Helper 去执行 `helm upgrade` 和 `kubectl rollout status`，所以只适用于已经有 K3s / Kubernetes / Helm 的环境。
>
> 但如果你是老用户，正打算 **从 Docker Compose 迁到 K3s / Helm，以获得滚动更新能力**，那这页仍然值得看，因为它描述的就是迁移完成后的目标形态。

## 配置到底在哪里配

更新中心涉及后台页面、主服务环境变量、helper 部署清单三层配置，最容易混淆，建议先看下面这张对照表。

| 你要配什么 | 去哪里配 | 说明 |
|------|------|------|
| 是否启用更新中心 | UI：设置 → 更新中心 | 日常使用优先在 UI 操作 |
| Deploy Helper URL | UI：设置 → 更新中心 | 例如集群内 Service 地址 |
| Namespace / Release Name / Chart Ref / Image Repository | UI：设置 → 更新中心 | 都是页面里直接填的部署配置 |
| GitHub Releases / Docker Hub / 默认部署来源 | UI：设置 → 更新中心 | 属于页面里的版本来源策略 |
| 主 Metapi 到 helper 的认证 token | 主 Metapi 环境变量 | `DEPLOY_HELPER_TOKEN` 或 `UPDATE_CENTER_HELPER_TOKEN` |
| helper 自己监听在哪个地址和端口 | helper 环境变量 / manifest | `DEPLOY_HELPER_HOST` / `DEPLOY_HELPER_PORT` |
| helper 自己的 Bearer Token | helper 环境变量 / manifest | `DEPLOY_HELPER_TOKEN`，且必须与主服务一致 |
| chart 是否真的支持 digest 部署 | chart 文件本身 | 这不是 UI，也不是普通 env，要看 chart 模板 |

其中可以这样理解：

- 日常使用时，更新中心的大部分配置直接在 **设置 → 更新中心** 页面填写
- 环境变量主要负责主服务与 helper 之间的认证，以及 helper 自身的监听参数

## 先判断：是否适用

| 你的现状 | 是否适用 | 你现在该怎么做 |
|------|------------|--------------|
| 只有一个 `docker compose up -d` 跑起来的 Metapi 容器 | 不需要 | 继续用普通 Docker 升级方式 |
| 目前是 Docker Compose，准备迁到 K3s / Helm 来获得滚动更新 | 需要 | 把本页当成迁移后的目标架构说明，先完成迁移，再启用更新中心 |
| 有 K3s / Kubernetes 集群，但 Metapi 不是用 Helm release 部署的 | 暂时不建议 | 这套更新中心无法直接接管现有部署 |
| Metapi 已经是 Helm release，想在后台里看版本并手动点一次升级 | 需要 | 继续看下文 |

## 如果你现在只有一个 Docker Compose 容器

这就是大多数用户的真实情况。

对这类用户来说，当前版本最实用的升级路径仍然是普通 Docker 流程：

```bash
docker compose pull
docker compose up -d
```

如果你还想更稳一点，可以先看镜像版本或仓库 release，再决定要不要拉新镜像。

你现在**不需要额外准备**这些东西：

- K3s / Kubernetes 集群
- Helm
- Deploy Helper
- 额外的 Bearer Token
- 集群内 Service 地址

除非你本来就在用 K3s / Helm，否则本页可以直接跳过。

## 如果你正准备从 Docker Compose 迁到 K3s

这其实是一个很合理的升级方向。

很多老用户想迁到 K3s / Helm，核心诉求通常不是“为了多一个页面”，而是为了获得这些能力：

- 发布时尽量减少停机时间
- 用 Helm 管理版本和回滚
- 后续在后台里看版本来源，并人工触发一次升级

对这类用户来说，本页不是“现在立刻就能用”的操作手册，而是：

- “迁移完成后，你会得到什么能力”
- “为了用上这个能力，集群侧要提前满足什么前提”

### 推荐的迁移顺序

如果你现在还是 Docker Compose 用户，建议按下面的顺序规划：

1. 先备份当前实例数据。
   - 如果当前运行库还是 SQLite，先备份 `data/` 目录。
   - 具体备份方式见 [运维手册](./operations.md)。
2. 评估迁移后的运行数据库。
   - 如果你迁到 K3s 只是想“单副本 + 更规范部署”，SQLite 仍然可以先用。
   - 如果你更看重后续可维护性、滚动发布体验和外部持久化，通常更建议切到 MySQL / PostgreSQL。
3. 在新环境里先把 Metapi 作为 Helm release 跑起来。
4. 确认新实例可正常登录、数据正常、代理请求正常。
5. 再部署 Deploy Helper，并启用更新中心。

### 一个很重要的认知

“迁到 K3s” 和 “启用更新中心” 是两件相关但不同的事：

- 迁到 K3s / Helm
  - 是部署形态升级
- 启用更新中心
  - 是迁移完成后，额外获得的一个后台升级入口

所以更准确的理解应该是：

- **先把 Docker Compose 用户迁成 Helm 用户，再谈更新中心。**

## 那这个功能到底是干什么的

对已经在 K3s / Kubernetes 里跑 Metapi 的用户，这个“更新中心”主要解决的是：

- 在后台里看当前运行版本
- 看官方 GitHub Releases / Docker Hub 有没有新的稳定版
- 在后台定时检查新版本，并在首次发现时提醒一次
- 确认 Deploy Helper 是否健康
- 点一次按钮，触发一轮 Helm 升级
- 在页面里回看部署日志

它的定位更接近：

- “集群内人工触发升级面板”

而不是：

- “单容器自动升级器”
- “Docker Compose 一键更新”
- “无人值守自动发布系统”

## 使用它之前，你至少要已经有这些东西

- 一个可用的 K3s / Kubernetes 集群
- 用 Helm 部署的 Metapi release
- 你的 chart 至少支持下面三个 values：
  - `image.repository`
  - `image.tag`
  - `image.digest`
- 目标 Deployment 带有 `app.kubernetes.io/instance=<releaseName>` 标签
- 主 Metapi 服务可以访问：
  - GitHub API
  - Docker Hub API
  - Deploy Helper 的集群内地址

如果上面有任何一项不成立，就先不要配更新中心。

## helper 是什么

Deploy Helper 是一个跑在集群里的小服务。它不负责对外提供 Metapi 功能，只负责接受主 Metapi 发来的部署请求，然后在集群里执行：

- `helm history`
- `helm get values`
- `helm upgrade`
- `kubectl rollout status`
- 必要时 `helm rollback`

所以你可以把它理解成：

- “一个专门替管理后台执行 Helm/Kubectl 的集群内代理”

## 什么时候你才应该去配 helper

只有当你已经满足下面这个目标时，才值得去配：

- “我已经在 K3s / Helm 里跑 Metapi 了，现在想在后台里看版本，并且人工点一下完成升级”

如果你现在只是：

- “我有一个 Compose 容器，想在后台里点按钮更新它”

那答案是：

- 当前版本还不支持这个场景。

如果你现在是：

- “我正在把 Compose 老实例迁到 K3s，希望迁完以后用后台来做后续版本升级”

那答案是：

- 这是一个合理场景，本页正是说明迁移后该如何接入更新中心。

## K3s / Helm 用户的接入步骤

如果你确实已经是 K3s / Helm 用户，接入顺序建议如下。

### 1. 先部署 Deploy Helper

仓库里带了一个最小示例清单：

- `deploy/k3s/metapi-deploy-helper.yaml`
- `deploy/k3s/chart`

使用前至少要改这些值：

- `namespace`
- `DEPLOY_HELPER_TOKEN`
- `image`

如果你准备直接按仓库示例接入，推荐把它们放到这两个路径：

- `/opt/metapi-k3s/metapi-deploy-helper.yaml`
- `/opt/metapi-k3s/chart`

这里有一个很容易漏掉、但会直接决定更新中心是否真的可靠的约束：

- 后台里的 `Chart Ref`
- helper Pod 里挂载进去的 chart 路径

这两个值必须指向同一份 chart。

如果你在设置页把 `Chart Ref` 填成 `/opt/metapi-k3s/chart`，但 helper Pod 里根本没有把那份 chart 挂进去，那么更新中心即使能看到版本，也无法稳定把 digest 部署到真正运行中的 Pod。

最小部署命令示例：

```bash
kubectl create namespace ai
mkdir -p /opt/metapi-k3s/chart
cp -R deploy/k3s/chart/. /opt/metapi-k3s/chart/
cp deploy/k3s/metapi-deploy-helper.yaml /opt/metapi-k3s/metapi-deploy-helper.yaml
kubectl apply -f /opt/metapi-k3s/metapi-deploy-helper.yaml
```

### 1.1 首次接入前一定要做的自检

新用户最容易踩的坑不是 helper 起不来，而是：

- chart 虽然能执行 `helm upgrade`
- 但它其实没有消费 `image.digest`
- 同时 `imagePullPolicy` 还停留在 `IfNotPresent`

这样更新中心会显示任务成功、Helm revision 也会增加，但线上真正运行的镜像可能根本没变。

仓库自带的 `deploy/k3s/chart` 已经把这件事处理成默认正确：

- `values.yaml` 里包含 `image.digest`
- `templates/deployment.yaml` 在有 digest 时会渲染成 `repository@digest`
- chart 默认 `imagePullPolicy: Always`
- helper 示例清单也默认 `imagePullPolicy: Always`

你可以在接入前先跑一次自检：

```bash
helm template metapi /opt/metapi-k3s/chart \
  --set image.repository=1467078763/metapi \
  --set image.tag=latest \
  --set-string image.digest=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  | grep -n 'image:'
```

你期望看到的是：

- `image: "1467078763/metapi@sha256:..."`

如果输出仍然是：

- `image: "1467078763/metapi:latest"`

那说明这份 chart 还是 tag 语义，先不要继续配置更新中心。

### 2. 让主 Metapi 和 helper 用同一个 token

主 Metapi 端支持这两个环境变量，设置一个即可：

- `DEPLOY_HELPER_TOKEN`
- `UPDATE_CENTER_HELPER_TOKEN`

helper 端使用：

- `DEPLOY_HELPER_TOKEN`

它们的值必须完全一致。

这一步仍然是**环境变量级配置**，因为它本质上是主服务与 helper 之间的认证，而不是普通用户日常在 UI 里调的业务参数。

### 3. 在后台“设置 → 更新中心”里填配置

从这一步开始，**优先按 UI 来操作**，不要再回头把下面这些字段硬塞进环境变量。

需要填写的核心字段有：

| 字段 | 怎么理解 | 典型示例 |
|------|--------|----------|
| `Deploy Helper URL` | 主 Metapi 访问 helper 的地址 | `http://metapi-deploy-helper.ai.svc.cluster.local:9850` |
| `Namespace` | 目标 release 所在命名空间 | `ai` |
| `Release Name` | Helm release 名 | `metapi` |
| `Chart Ref` | helper Pod 能访问到的 chart 引用 | `/opt/metapi-k3s/chart` |
| `Image Repository` | 升级时写入 chart 的镜像仓库 | `1467078763/metapi` |
| `默认部署来源` | 默认从 GitHub 还是 Docker Hub 取版本 | `GitHub Releases` |

另外还有 3 个开关：

- `启用更新中心`
- `GitHub Releases`
- `Docker Hub`

对已经跑起来的 K3s / Helm 用户来说，更新中心的日常配置主要就在这一页：

```text
设置 → 更新中心
```

### 4. 实际操作顺序

推荐这样用：

1. 先保存配置
2. 等后台自动发现新版本，或手动点一次“检查更新”立即刷新
3. 确认页面状态都正常：
   - 当前运行版本正常显示
   - 版本来源发现了可部署版本
   - 如果 Docker Hub 显示的是 `latest @ sha256:...`，说明页面已经识别到 alias tag 当前指向的具体镜像 digest
   - Deploy Helper 显示健康
4. 再点部署按钮
5. 在页面下方看部署日志
6. 如果升级后发现问题，可以直接在“回退历史”里点旧 revision 回滚；只要该 revision 当时记录了 digest，就会跟着一起回到对应镜像

如果实时日志流断开，页面会自动回退到最近任务快照。

### 4.1 新用户最值得先做的一次确认

第一次接入时，不要急着点部署。先确认下面 4 件事同时成立：

1. `Chart Ref` 和 helper 挂载路径指向的是同一份 chart。
2. 这份 chart 支持 `image.digest`，并且在有 digest 时会渲染成 `repository@digest`。
3. chart 和 helper 都没有继续使用会掩盖新镜像的 `imagePullPolicy: IfNotPresent`。
4. 页面里显示的目标 digest，和 helper 最终读到的运行中 digest 能对上。

只要这 4 件事成立，新用户就不会再遇到“页面说部署成功，但线上还是旧镜像”的假成功。

## 这套能力当前不适合什么场景

- 只有一台 Docker 主机、一个 Compose 文件、一个 Metapi 容器
- 想让后台直接远程更新 Docker Compose 服务
- 没有 Helm release，只是手工 apply 的 Deployment
- 需要全自动无人值守升级
- 需要灰度、分批、审批、回滚编排等更完整的发布系统

## About 页和更新中心的关系

About 页里的“更新提醒”更像一个轻量入口：

- 让你知道大概有没有新版本

真正的配置和部署入口仍然在：

- “设置 → 更新中心”

所以即使你是普通 Docker Compose 用户，也可以把 About 页里的版本提醒当成“看看最近有没有新版本”的地方，但不要把它理解成“马上就能自动更新我这台机器”。

## 常见问题

### 为什么我在设置页里能看到更新中心，但还是没法用

因为这个页面会跟着功能一起出现，但真正能否部署，取决于你有没有：

- K3s / Kubernetes
- Helm release
- Deploy Helper
- 主服务的 `DEPLOY_HELPER_TOKEN`（或兼容别名 `UPDATE_CENTER_HELPER_TOKEN`）与 helper 侧 `DEPLOY_HELPER_TOKEN` 保持一致

另外，如果你想用“按 digest 精确部署/回退”这条链路，还要确认你的 chart 没有忽略 `image.digest` 这个值；否则页面虽然能显示 digest，真正部署时还是只会落到 tag 语义。

缺其中任何一项，都只能看，不能真正部署。

### 为什么页面显示任务成功，但线上镜像还是没变

最常见的根因只有两类：

- 你的 chart 其实没有消费 `image.digest`
- 你的 Deployment 或 helper 还在使用 `imagePullPolicy: IfNotPresent`

这两种情况叠在一起时，就会出现“Helm revision 往前走了，但实际运行的 imageID 没动”的假成功。

如果你是第一次接入，最稳妥的方式就是直接从仓库自带的：

- `deploy/k3s/chart`
- `deploy/k3s/metapi-deploy-helper.yaml`

开始，不要自己先抄一份简化版再改。

### 为什么我只有 Docker Compose，按钮没有意义

因为当前部署链路不是去操作外部 Docker 主机，而是去调用集群里的 helper，然后由 helper 执行 `helm` / `kubectl`。

### 那普通 Docker Compose 用户现在该怎么升级

继续使用正常 Docker 流程即可：

```bash
docker compose pull
docker compose up -d
```

如果你担心直接升级，可以先看仓库 Releases 或镜像 tag，再决定是否升级。

## 相关入口

- [部署指南](./deployment.md)
- [配置说明](./configuration.md)
- [运维手册](./operations.md)
