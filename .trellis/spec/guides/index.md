# 思考指南

> **用途**：扩展思考范围，提前发现容易遗漏的问题。

---

## 为什么需要思考指南？

**大多数 bug 和技术债都来自“没有想到”，而不是能力不足：**

- 没有想到层边界会发生什么 → 产生跨层 bug
- 没有想到模式会重复 → 各处出现重复代码
- 没有想到边界情况 → 运行时错误
- 没有想到未来维护者 → 代码难以理解

这些指南帮助你在编码前提出正确的问题。

---

## 可用指南

| 指南 | 用途 | 使用时机 |
|-------|---------|-------------|
| [代码复用思考指南](./code-reuse-thinking-guide.md) | 识别已有模式并减少重复 | 发现相似实现时 |
| [跨层思考指南](./cross-layer-thinking-guide.md) | 梳理层之间的数据流 | 功能跨越多个层时 |
| [Trellis 文档语言约定](./documentation-language.md) | 统一 Trellis 开发文档的自然语言和机器字段边界 | 新建或修改 Trellis 任务、规范、研究记录或会话日志 |
| [Trellis 运行时契约](./trellis-runtime-contract.md) | 说明 workflow parser、任务生命周期、session pointer、JSONL 和 hooks | 修改 Trellis workflow、脚本、workspace 或 hook 时 |

---

## 快速参考：思考触发条件

### 需要思考跨层问题时

- [ ] 功能触及 3 个以上层（API、Service、Component、Database）
- [ ] 数据在层之间改变格式
- [ ] 多个消费者需要同一份数据
- [ ] 不确定某段逻辑应该放在哪里
- [ ] 正在添加 event kind、JSONL record、RPC payload 或 config field
- [ ] UI / command code 开始直接 cast 原始 payload 字段

→ 阅读[跨层思考指南](./cross-layer-thinking-guide.md)

### 需要思考代码复用时

- [ ] 正在编写与已有代码相似的代码
- [ ] 同一种模式已经出现 3 次以上
- [ ] 正在向多个位置添加同一个字段
- [ ] **正在修改任何 constant 或 config**
- [ ] **正在创建新的 utility/helper function** ← 先搜索！
- [ ] 两个以上文件在读取同一个无类型 payload 字段，并各自做 local cast
- [ ] 多个分支根据 `kind` / `action` 更新同一个派生状态

→ 阅读[代码复用思考指南](./code-reuse-thinking-guide.md)

### 需要编写 Trellis 文档时

- [ ] 正在新建或修改 `prd.md`、`design.md`、`implement.md`、研究记录或 journal
- [ ] 正在填写 JSONL 的 `reason`、任务备注或规范说明
- [ ] 需要引用英文命令、路径、协议或第三方名称

→ 阅读[Trellis 文档语言约定](./documentation-language.md)

### 需要修改 Trellis 运行时或注入内容时

- [ ] 正在修改 `.trellis/workflow.md` 的 phase、`[workflow-state:STATUS]` block 或 fallback
- [ ] 正在修改 `task.py`、session resolver、JSONL validator、workspace writer 或 `.codex/hooks/**`
- [ ] 正在改变 `status`、Codex `dispatch_mode`、active task pointer 或 hook JSON 输出

→ 阅读[Trellis 运行时契约](./trellis-runtime-contract.md)，并联查 writer、parser、resolver 和输出 schema。

### 核对 AI 跨审结果时

- [ ] 评审者声称“用户输入可能是恶意的” → 检查实际数据来源（内部 manifest？用户配置？外部 API？）
- [ ] 评审者指出“缺少校验” → 数据是否来自可信的内部来源？
- [ ] 评审者说“行为发生变化” → 阅读代码注释，这是有意设计吗？
- [ ] 评审者在测试中发现“bug” → 假设删除被测试的功能，测试仍然通过吗？如果通过，就是同义反复测试

**常见的 AI 评审误报模式**：

1. **信任边界混淆**：把内部数据（捆绑的 JSON manifest）当成不可信外部输入
2. **忽略设计注释**：把注释中记录的有意行为当成 bug
3. **误读变量**：没有追踪变量的真实定义（例如 Map 按 path 而不是 name 作为 key）

**核对规则**：每个 CRITICAL/WARNING 发现都必须结合实际代码核实后再处理。按约 35% 的误报率为 AI 评审预留核查预算。

---

## 修改前规则（重要）

> **修改任何值之前，必须先搜索！**

```bash
# 搜索准备修改的值
grep -r "value_to_change" .
```

这个习惯可以避免大多数“忘记同步某处”的 bug。

---

## 如何使用本目录

1. **编码前**：快速浏览相关思考指南
2. **编码中**：感到重复或复杂时，回看指南
3. **出现 bug 后**：把新发现补充到对应指南（从错误中学习）

---

## 贡献

发现新的“当时没想到”时刻？把它加入相关指南。

---

**核心原则**：30 分钟的思考可以节省 3 小时的调试。
