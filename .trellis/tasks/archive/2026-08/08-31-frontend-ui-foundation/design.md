# 前端 UI 基础与 Radix 封装层：设计

## 组件分层

```text
page/domain component
        ↓ semantic props
src/web/components/ui/*  (Metapi-owned API + theme/classes)
        ↓ behavior only
Radix primitives
```

第三方依赖只出现在 `components/ui`，并通过 CSS token 或现有 class 适配。
业务页面不得知道 Radix 的 `Root/Trigger/Content` 结构。

## 兼容 API

- `CenteredModal` 继续作为旧调用方 facade；内部可以委托新的 Dialog wrapper。
  先补 role/aria-labelledby、focus return 和多实例 body-lock，再迁移调用方。
- `MobileDrawer` 继续提供现有 `open/onClose/title/side` 语义；桌面 drawer
  与移动 drawer 共享底层 close/portal/focus 逻辑，但保留不同 CSS 尺寸。
- `ModernSelect` 保留当前 `options`、`value`、`onChange`、搜索和
  placeholder props。Radix Select 只作为实现细节；若 Radix 的 test renderer
  或 portal 行为不兼容，先保持旧内部实现，不能破坏 facade。
- `Button`/`AsyncButton` 只封装 `type`、`disabled`、`aria-busy`、loading
  indicator 和现有 `.btn-*` variants，不把页面动作塞进一个 boolean 矩阵。

## 生命周期与无障碍

- 使用计数或 owner 集合管理 body scroll lock，避免两个 portal 同时存在时
  一个卸载恢复滚动而另一个仍打开。
- Dialog/Drawer 明确 close policy；默认行为保持现有调用方设置，不擅自把
  backdrop/Escape 从关闭变成开启。
- 打开时记录触发元素，关闭时优先返回仍连接的触发元素，其次使用现有
  fallback focus；所有 close path 都清理 listener/timer。
- Toast 使用 `role=status`/`aria-live`，卸载时清理 timeout，保留现有 toast
  去重与自动消失时间。

## 迁移顺序

1. 新增 wrapper 和测试，不动调用方；
2. 迁移低耦合的 Search/ChangeKey/settings modal；
3. 迁移下游/OAuth drawer 和 TokenRoutes confirm；
4. 保留 `ModernSelect` facade 后逐步切换内部行为；
5. 增量替换 Button/feedback，最后才考虑删除无用依赖或旧 CSS。

每一步都能单独回滚，且旧导出保持可用。
