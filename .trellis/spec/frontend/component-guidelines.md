# 前端组件规范

## 组件形状

使用函数组件和小型、显式的 props 类型。数据加载和页面编排留在 page；共享组件聚焦渲染、交互和无障碍。`ToastProvider`/`I18nProvider` 是现有 Context provider；consumer 使用 `useToast()`/`useI18n()`，不要直接读取 provider state。

```tsx
type ResponsiveBatchActionBarProps = {
  isMobile: boolean;
  info: React.ReactNode;
  children: React.ReactNode;
};

export default function ResponsiveBatchActionBar(props: ResponsiveBatchActionBarProps) {
  // 选择共享的 mobile 或 desktop 展示
}
```

优先通过 `children` 和窄类型 render prop 组合，而不是大型 boolean-prop 矩阵。只有当 component/effect 确实受益时，才用 `useCallback` 稳定 callback。

## Props 与数据

- 显式声明可选值（`string | null`、可选数组，以及适当的 `React.ReactNode`）。
- 将 API data 视为可能不完整；在 page 或纯 helper 中归一化后再渲染。不要让每个 child 都访问无类型的嵌套 payload。
- 使用与现有 primitive 一致的语义命名（`onClose`、`mobileOpen`、`mobileContent`、`isMobile`）。
- 非 form submit 的交互控件显式设置 `type="button"`；重复操作有风险时，在请求进行中禁用控件。

## 共享交互 primitive

创建另一套实现前，先使用既有 shell：

- `CenteredModal` 提供 animated presence、可选 Escape/backdrop close、body-scroll lock、close button 和 portal。
- `MobileDrawer` 提供 portal、`role="dialog"`、`aria-modal`、可选的带 label title、Escape/backdrop close、body-scroll lock 和 close animation。
- `ResponsiveFilterPanel` 在共享 breakpoint 将 desktop content 映射到 `MobileFilterSheet`；`ResponsiveBatchActionBar` 映射到 `MobileBatchBar`。
- `MobileCard`、`MobileDrawer`、`useIsMobile` 和 `mobileLayout.ts` 是现有 mobile 词汇。

除非交互确实属于不同 family 且有自己的测试，否则不要在 page 中重复 modal backdrop、portal、Escape 或 body-scroll 逻辑。

## 样式

应用使用 `src/web/index.css` 中的全局样式、Tailwind 的 Vite import 和既有 CSS-variable design token/class（`card`、`btn`、`modal-*`、`mobile-*`、`var(--color-...)`）。组件通常把语义 class 与少量一次性布局 inline style 组合使用。遵循相邻代码；某种样式被复用时扩展全局词汇，不要为单个组件引入新的 CSS module/styled-components 约定。

## 无障碍

- 操作和导航使用真实的 `<button>` 或 `<a>`；图标没有可见文字时提供 `aria-label`。
- 将 `<label htmlFor>` 与 form control 配对，例如 `App.tsx` 的登录表单。
- dialog 必须暴露 title/label；在 shell 要求时提供 `role="dialog"`/`aria-modal` 和显式 close affordance。`CenteredModal` 默认关闭 backdrop/Escape，只有有意选择时才 opt in。
- 修改 modal 或 drawer markup 时，保留 keyboard 行为以及 focus/scroll lock；`centered-modal.test.tsx` 和 `mobile-drawer.test.tsx` 是参考测试。
- 可见 status/error 文本必须通过 `t()`/`tr()` 翻译。

## 常见错误

- 创建绕过 `CenteredModal` 或 `MobileDrawer` 且未测试 cleanup 的页面 modal。
- 在 mobile 上继续渲染 desktop filter/action markup，而不是使用共享 responsive primitive。
- 使用可点击 `<div>` 代替能提供键盘语义的 button。
- 把原始 server object 传过多个 child，再添加重复 cast。
- 忘记在 dialog panel 内停止 event propagation，或卸载后没有恢复 body overflow。

## 场景：项目 UI 封装与 overlay 生命周期

### 1. 适用范围与触发条件（Scope / Trigger）

- Trigger：新增或迁移 dialog、drawer、select、button、loading/empty/error
  feedback，或修改第三方交互原语边界时适用。
- Scope：`src/web/components/ui/**` 是唯一允许直接引用 `@radix-ui/*` 的
  owner；页面和领域组件只能依赖项目封装的语义 props。

### 2. 接口签名（Signatures）

```ts
type DialogProps = {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  children: React.ReactNode;
  closeOnBackdrop?: boolean;
  closeOnEscape?: boolean;
  ariaLabel?: string;
};

type DrawerProps = DialogProps & { side?: 'left' | 'right' };
type AsyncButtonProps = ButtonProps & { pending?: boolean; loading?: boolean };
```

`Dialog`、`Drawer`、`Button`/`AsyncButton`、`LoadingState`、`EmptyState`、
`ErrorState` 的公开类型位于 `src/web/components/ui/index.ts`；
`CenteredModal`、`MobileDrawer`、`ModernSelect` 仅作为兼容导出路径。

### 3. 契约（Contracts）

- overlay panel 必须暴露 `role="dialog"`、`aria-modal="true"`，并通过可见
  title 或 `ariaLabel` 命名；异步操作可用 `aria-busy`。
- fallback renderer 的 `Dialog`/`Drawer` body scroll lock 使用引用计数；浏览器
  renderer 由 Radix modal overlay 的 `RemoveScroll` 单独拥有滚动锁，wrapper
  不得再叠加第二个 owner。无论 renderer 如何选择，关闭一个 surface 都不得
  恢复仍被其他 surface 占用的滚动锁。Escape 只由最顶层 surface 处理。
- `closeOnBackdrop` 和 `closeOnEscape` 默认为调用方现有语义，不能因为迁移
  wrapper 擅自改变。panel 点击必须阻止冒泡到 backdrop。
- 打开时记录触发焦点，关闭或卸载时尽量恢复仍连接的触发元素；失败只能是
  best-effort，不能阻止关闭。
- 非 submit button 默认 `type="button"`；`loading`/`pending` 时设置
  `disabled` 与 `aria-busy`，并显示项目既有 spinner/class。
- `ModernSelect` 保留 `options`、`value`、`onChange`、placeholder、搜索和
  controlled 行为。它当前是项目自己的 listbox facade，不得在文档或调用方
  中声称已经暴露 Radix Select API。

### 4. 校验与错误矩阵（Validation & Error Matrix）

| 条件 | 必须行为 |
| --- | --- |
| 无可见 title 且无 `ariaLabel` | wrapper 提供稳定的 visually-hidden/fallback label |
| 两个 overlay 同时打开 | body 保持 `overflow: hidden`，直到最后一个关闭 |
| 关闭事件由 backdrop 与 Radix dismissal 同 tick 触发 | `onClose` 只调用一次 |
| `closeOnEscape=false` | Escape 被消费，不调用 `onClose` |
| async button `loading/pending=true` | 禁用、`aria-busy=true`、显示 loading indicator |
| portal/body 不可用（SSR/test renderer） | 使用 inline fallback，不抛出渲染异常 |
| opener 已卸载 | 不抛异常，尝试 fallback focus 或跳过恢复 |

### 5. 正例、基线与反例（Good / Base / Bad Cases）

- Good：页面传 `title`、`onClose` 和显式 close policy，业务内容通过
  `children/footer` 组合，焦点和 scroll lock 由 `Dialog` 统一管理。
- Base：旧页面继续使用 `CenteredModal` 或 `MobileDrawer` facade；只要保留
  原 props/class 和对应行为测试即可逐步迁移。
- Bad：页面自行创建 backdrop、portal、Escape listener 或直接 import
  `@radix-ui/react-dialog`；这会产生第二套生命周期 owner 和不可检查的漂移。

### 6. 必需测试（Tests Required）

- wrapper unit/behavior tests：role/label、close button、Escape/backdrop policy、
  focus return、SSR/test fallback、卸载 cleanup。
- 多实例测试：同时挂载两个 surface，验证 body lock 引用计数和只关闭顶层。
- `Button` 测试：默认 type、disabled、`aria-busy`、spinner 和 loading 文案。
- `ModernSelect` 测试：controlled value、鼠标/键盘选择、disabled option、
  Escape 和搜索过滤；不要只断言 Radix 内部节点。
- 运行 `npm run repo:drift-check`，确认第三方交互原语只在
  `src/web/components/ui/**` 出现。

### 7. 错误与正确对照（Wrong vs Correct）

#### 错误示例（Wrong）

```tsx
// page 内重复实现 portal/backdrop，并把 Radix 结构泄漏给业务层
import * as DialogPrimitive from '@radix-ui/react-dialog';
return <DialogPrimitive.Content onEscapeKeyDown={...}>{children}</DialogPrimitive.Content>;
```

#### 正确示例（Correct）

```tsx
// page 只表达语义；行为、焦点、portal 和主题由项目 wrapper 拥有
return (
  <Dialog open={open} onClose={close} title={t('编辑站点')} closeOnEscape>
    <SiteEditor />
  </Dialog>
);
```
