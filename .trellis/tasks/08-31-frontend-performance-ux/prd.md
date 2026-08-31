# 前端请求性能与用户体验

## 目标

在不改变页面能力和 API 契约的前提下，统一可取消/防陈旧的请求生命周期，
降低重复请求和无谓渲染，改善大列表、图表、搜索、轮询和模型测试器的响应，
并让加载、空态、错误和取消反馈在页面间一致。

## 已确认事实

- 规划阶段的 `npm run build:web` 采样为 `2613 modules transformed`、约 `5.35s`；
  `vchart-vendor` 为 `2,154.02 kB`（gzip `586.81 kB`），是唯一明显超大的 chunk。
  最终交付复核为 `2614 modules`、CSS `136.83 kB`，详见项目审计；旧的 2,548
  modules / 5.30s 数字只作为历史材料。
- Dashboard 首屏有三组数据请求，可见性轮询没有 in-flight single-flight；
  ProxyLogs 每 2 秒刷新但没有请求并发锁；SearchModal debounce 没有 abort/
  sequence；Models hydrate timer 未完整清理。
- ModelTester 对每个 SSE chunk 更新消息和 debug 状态，可能造成整树高频渲染；
  Dashboard 对所有站点测速使用无上限 `Promise.all`。
- TokenRoutes 已有 progressive chunk + IntersectionObserver，可作为评估样例；
  规范要求继续使用 React state + `api.ts`，不新增全局 server-state 库。
- 当前工作树的 `useAsyncResource`、`siteSpeedProbe` 和 `streamBatcher` 是未提交
  候选/WIP；在 focused tests、typecheck、build 和 review 通过前，不视为已完成
  的产品能力。

## 需求

1. 提供窄职责、类型安全的可取消异步 hook/helper，支持 stale guard、silent
   refresh、AbortError/timeout 区分和 unmount cleanup；迁移至少四个页面路径。
2. 修复 SearchModal、Dashboard、ProxyLogs、Models 的竞态、timer 和轮询行为；
   页面切后台时停止高频轮询，回到前台只做一次刷新。
3. 将 Dashboard 跨域测速抽成共享 `probeSiteSpeed`/等价 helper，限制并发、
   超时和逐站结果映射，保留 no-cors 特殊能力并记录架构例外。
4. 对 ModelTester 流式 delta/debug 更新做 16–50ms 批处理，停止/abort 时
   flush，保证最终文本和 debug 字节序列不变。
5. 只在测量证明必要时复用 progressive list 或图表可见性门控，避免首屏提前
   下载 vchart vendor；保证图表出现时无布局跳动和功能缺失。
6. 统一选定页面的 loading/empty/error/cancel feedback 和翻译，不把错误吞掉。
7. 输出前后 chunk、请求在途数、stale response 和关键交互测量报告。

## 验收标准

- [ ] async helper 有 abort、stale、silent refresh、unmount 和错误分类测试；
      至少四个真实页面使用它。
- [ ] SearchModal 快速 q1→q2 只显示 q2；Dashboard/ProxyLogs 自动刷新在慢
      请求下最多一个在途请求；停止/卸载后没有残留请求或 timer。
- [ ] Dashboard 测速并发上限可测试（目标不超过 4），逐站失败可见，跨域能力
      不丢失。
- [ ] ModelTester 内容完全一致且渲染频率/长任务指标改善或有证据说明瓶颈
      已转移；首字响应不出现可感知回退。
- [ ] 首屏/路由 chunk 不回归，below-fold 图表不会无条件提前下载超大 vendor；
      图表可见后仍正常渲染。
- [ ] 桌面、移动、键盘、翻译、加载/空态/错误/取消行为有回归测试。
- [ ] web typecheck、focused/full tests、drift check、build 和 diff check 通过。

## 范围外

- 引入 React Query/SWR/Zustand 等全局数据层；
- 改变服务器 API 响应、代理协议、分页语义或删除功能；
- 在没有测量的情况下对所有列表做窗口化或重写所有页面。
