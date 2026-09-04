# 前端状态管理

## 状态类别

Metapi 使用 React 内置 state primitive 和两个聚焦的 Context provider，没有外部 global store。新增状态前先分类：

| 类别 | 现有模式 | 示例 |
| --- | --- | --- |
| 组件/页面本地 | 所属 component 中的 `useState` | editor form、选中行、`Accounts.tsx` 和 `Sites.tsx` 中的 loading/error flag |
| 派生 | `useMemo`、纯 helper 或 render 时计算 | `Models.tsx` 中过滤/排序 model、`TokenRoutes.tsx` 中 route candidate |
| 命令式/生命周期 | `useRef` | sequence ID、abort controller、timer、DOM ref |
| URL/导航 | React Router location/search + `navigate` | page 中的 `segment`、`create`、`siteId` 和 `q` query parameter |
| 浏览器持久化 | 小型 module 通过 `localStorage` | auth expiry、theme/profile、playground draft、首次使用 reminder |
| 跨树 UI context | React Context | `App.tsx` 中的 `I18nProvider` 和 `ToastProvider` |
| Server state | 显式 `api` 调用 + 页面本地 state | site/account/route/log 和 background-job status |

## 选择归属位置

把状态放在拥有该行为的最低层级 component。只有两个 sibling 确实需要协调时才提升；只有已经由 `I18nProvider` 或 `ToastProvider` 表达的横切关注点才使用 Context。不要为单页获取并展示的数据添加 global store。

如果视图应在导航后保留、可加入书签或驱动 create/focus intent，使用 URL state。像 `Accounts.tsx` 和 `Sites.tsx` 一样消费并清理一次性 query parameter，不要让过期 command 留在浏览器 history 中。

## Server state 与 mutation

`api.ts` 是唯一 client boundary。页面应：

1. 在 effect 或显式 action 中加载数据；
2. 在存储前归一化响应；
3. 暴露 loading/error/empty state；
4. mutation 后更新或重新加载受影响的页面 state；以及
5. 当 filter、ID 或 route 变化时忽略 stale response。

独立资源只有在 UI 能接受共享失败语义时，才在 page/API helper 中使用 `Promise.all`；`api.getSiteSnapshot()` 是现有示例。optimistic update 应窄而可逆；当前大多数 mutation 都会重新加载权威 server snapshot。

## 持久化状态与重置

使用 `authSession.ts`、`appLocalState.ts` 或所属 feature helper 中命名的 storage key。对 JSON 读取做校验/parse 包装并提供默认值。`Settings.tsx` 中的 factory-reset path 调用 `clearAppInstallationState()`，一起清除 auth/theme/profile/reminder state；新的安装级 key 必须加入这个集中 cleanup function。

除既有 admin session contract 外，绝不持久化 secret，也不要用 `localStorage` 替代 server authorization。

## 常见错误

- 在多个无关 Context 中复制同一份 server snapshot。
- 存储派生过滤列表，使其与 source 漂移。
- effect 发起 request 却不清理过期 selection/preview data。
- 添加持久化 key 却没有 reset/migration 行为。
- query parameter 处理完成后仍把 URL intent 当作持久状态。
