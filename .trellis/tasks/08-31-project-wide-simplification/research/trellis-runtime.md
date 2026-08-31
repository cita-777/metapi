# Metapi Trellis 运行时调查

## 查询元数据

- **查询**：调查本地 Trellis 的 workflow parser、status/breadcrumb 映射、Codex dispatch、按 session 隔离的活动任务、任务生命周期、JSONL manifest、workspace journal 和 Codex hooks 输入输出。
- **范围**：`.trellis/workflow.md`、`.trellis/scripts/common/active_task.py`、`task_store.py`、`task_context.py`、`task.py`、`session_context.py`、`add_session.py`、`developer.py`、`.codex/hooks/*.py`、`.codex/hooks.json`、`.trellis/config.yaml`。
- **日期**：2026-08-31。

## 可复现命令

```bash
python3 ./.trellis/scripts/get_context.py
python3 ./.trellis/scripts/get_context.py --mode phase --platform codex
python3 ./.trellis/scripts/task.py --help
python3 ./.trellis/scripts/task.py current --source
rg -n '\\[workflow-state:' .trellis/workflow.md
nl -ba .codex/hooks/inject-workflow-state.py
nl -ba .codex/hooks/session-start.py
nl -ba .codex/hooks/inject-subagent-context.py
python3 -m compileall -q .trellis/scripts .codex/hooks
```

## Workflow parser/tag 契约

- `.trellis/workflow.md` 是自然语言工作流和 breadcrumb body 的单一事实来源；`.codex/hooks/inject-workflow-state.py:189-219` 用正则解析 `[workflow-state:STATUS]`，`STATUS` 只能是 `[A-Za-z0-9_-]+`，开闭标签必须使用同一个值。
- `build_breadcrumb()`（约 `346-367` 行）按 `breadcrumb_key` 查 body；缺少标签或 workflow 文件时退化为通用提示。该 fallback 必须是简体中文，例如“请查阅 `.trellis/workflow.md` 确认当前步骤”，但不能改变 `<workflow-state>` 包装、status header 或解析正则。
- 初始调查时文件只有 `no_task` 标签，活动任务状态无法获得对应详细 body；随后已在本地 `workflow.md` 补齐 `planning`、`planning-inline`、`in_progress`、`in_progress-inline`、`completed` block。当前状态应以 `rg -n '\[workflow-state:' .trellis/workflow.md` 的实时结果为准。
- status 到 breadcrumb key 的约定：非 Codex 使用 `status`；Codex `dispatch_mode=auto` 使用普通 `status`，`inline` 使用 `${status}-inline`；旧值 `sub-agent` 归一化为 `auto`；非法显式值归一化为 `inline`（`inject-workflow-state.py:273-343`）。
- `no_task` 是没有活动任务的伪状态，不来自 `task.json.status`；stale pointer 会形成 `stale_<source_type>`，因此标签正则必须允许下划线和连字符。

## Codex dispatch 与上下文顺序

- `.trellis/config.yaml` 的 `codex.dispatch_mode` 默认 `auto`；`inject-workflow-state.py:296-323` 生成 `<codex-mode>` banner，说明 `auto` 优先 dispatch Trellis sub-agent，主 session 仍负责协调、澄清、更新规范、commit 和 finish；`inline` 由主 session 直接实现/检查。
- `.codex/hooks/inject-subagent-context.py` 处理 native `SubagentStart` 与平台 Task 输入；实现/检查 agent 读取顺序为 JSONL manifest → `prd.md` → `design.md`（若有）→ `implement.md`（若有），并按角色加载 spec/research。Codex 不应把继承 parent transcript 当作唯一上下文来源。
- Trellis 本身不注册 MCP server；`.codex/config.toml` 和 hooks 只负责本地 context injection/agent wiring。不要把全局 host 的 MCP 警告归因于 Trellis runtime。

## 按 session 隔离的活动任务（Session-specific active task）

- `.trellis/scripts/common/active_task.py:1-7` 明确说明 active task 是按 AI session/window 存储的指针，目录为 `.trellis/.runtime/sessions/`；没有稳定 session key 就没有可持久化的 active task。
- context key 优先来自 `TRELLIS_CONTEXT_ID`，也可由平台已验证的 session/conversation/transcript 环境变量解析（约 `37-149`、`294-322` 行）。脚本会 sanitize key 并限制长度，避免把原始路径直接当文件名。
- `task.py create` 在写入 task 目录后 best-effort 调用 `set_active_task`；有 session identity 时只影响当前 session，缺失时仍创建 `status=planning` 任务但不写全局指针。
- `task.py start`（`task.py:73-140`）设置当前 session 指针并把 `planning` 改为 `in_progress`；无 session identity 时进入 degraded mode，只改变 `task.json.status` 并提示当前 session 没有持久指针。`finish` 清除当前 session 文件，不改变 task status。
- 指针指向不存在目录或无法读取 task 时应显示 stale/unknown，不能静默选择另一个 task；修复 stale pointer 应使用 `task.py finish` 或重新 `start`，不要手改 `.runtime/sessions/`。

## 任务生命周期与机器字段（Task lifecycle）

| 命令 | 真实副作用 | 保持不变的字段/语义 |
| --- | --- | --- |
| `task.py create` | 创建 `.trellis/tasks/MM-DD-slug/`、`task.json`、默认 `prd.md`；按平台条件 seed JSONL；可建立 parent/child；best-effort 激活 session | `status=planning`、`id/name/title/parent/children/meta` 等 JSON key |
| `task.py start <dir>` | 设置 session pointer；将 `planning` 写为 `in_progress`；运行 `after_start` hook | `status` 值、路径解析和 hook 输入 `TASK_JSON_PATH` |
| `task.py finish` | 清除当前 session pointer；运行 `after_finish` hook（若 task 仍可解析） | 不把 finish 当作 completed；不自动改 task status |
| `task.py archive <dir>` | 将 task 标记 `completed`、写 `completedAt`、清除仍指向它的 session、移动到 `archive/YYYY-MM/`；按配置可 auto-commit；运行 `after_archive` hook | `completed` 是 archive writer 写入的 status；目录移动和 parent/child 处理顺序 |

`task.py create` 的 `--no-start` 只跳过 session 激活，不跳过目录和 status 写入。归档前的 branch stale 只 warning，不阻塞；`session_auto_commit: false` 时脚本不能触碰 Git。

## JSONL seed/manifest 契约

- `task_store.py:117-174` 只在检测到 sub-agent-capable platform（Codex `dispatch_mode=auto` 或配置目录）时创建 `implement.jsonl`、`check.jsonl`。seed 是一行 `{"_example": "..."}`，没有 `file` 字段，因此消费者会跳过它。
- `_SEED_EXAMPLE` 的自然语言应使用简体中文，但 JSON key `_example`、`file`、`type`、`reason` 和路径保持原文。seed 不是 curated entry；规划阶段必须补至少一个真实 `{"file":"...","reason":"..."}`。
- `task_context.py:226-314` 对每行 JSONL 做解析；空行/seed 行跳过，非法 JSON、缺失文件或目录是 error；代码文件路径只产生 hygiene warning，spec/research 之外的产品代码不应预注册到 manifest；超出 context byte cap 只 warning。
- `list-context` 展示 `implement.jsonl`/`check.jsonl` 的真实条目和 `reason`；`validate` 的输出是诊断接口，中文化不能改变退出码或 JSONL 解析。

本任务父 manifest 必须引用四份 research 与相关 spec；不得引用 `src/**` 产品代码作为上下文条目。子任务 manifest 可以按实际领域追加 research，但理由使用简体中文。

## 工作区与 journal 契约（Workspace/journal contract）

- `.trellis/workspace/<developer>/journal-N.md` 是 append-only session log；`add_session.py` 在约 2000 行时创建下一个文件，并更新 `index.md` 的 `@@@auto:*` managed regions。
- 旧 `index.md` 可能仍有英文列名；`add_session.py:94-105` 同时识别 `Total Sessions` 与 `会话总数`，因此中文化生成模板时必须保留旧英文读取兼容。
- journal rotation、session number、branch resolution、auto-commit scope 和 `.gitattributes` 合并行为是机器/协作语义；只翻译标题、提示和自然语言，不改 marker、列数或路径。

## Hook 输入输出契约

- `.codex/hooks.json` 将 `inject-workflow-state.py` 绑定到每轮 UserPromptSubmit 等价事件，将 `inject-subagent-context.py` 绑定到 `SubagentStart`；`session-start.py` 输出 Codex hook JSON。
- hook 从 stdin 读取 JSON；缺失、空白、malformed 或非 object 输入先安全归一化为空 dict，不能抛出未处理异常，也不能阻塞等待未关闭 stdin。在 Trellis 目录中，空 dict 会按“无活动任务”流程输出 breadcrumb；非 Trellis 目录则无输出。输出必须仍是合法 JSON，`ensure_ascii=False` 允许中文。
- `session-start.py` 输出 `{suppressOutput, systemMessage, hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:"..."}}`；`inject-workflow-state.py` 输出 `hookSpecificOutput.additionalContext` 或 Kiro 所需纯文本分支；`inject-subagent-context.py` 保持 role、task path、curated context 和平台输入 schema。
- 用户可见 fallback、status 摘要、`<trellis-bootstrap>`、`<ready>`、agent prompt 自然语言默认使用简体中文；`hookEventName`、XML-like tag、JSON key、status 值、命令和路径保持原文。
- skip 条件（`TRELLIS_HOOKS=0`、`TRELLIS_DISABLE_HOOKS=1`、`no-trellis` keyword、非 Trellis 目录）必须保持静默退出或既有退出码；中文化不能让 hook 在这些分支输出额外文本。

## 运行时反模式与验证

- 不在 hook 中另造与 workflow.md 冲突的 fallback status 字典；parser 只读取 tag body，缺失时报告可修复的中文 generic hint。
- 不把 Codex `dispatch_mode` 写成新的 status；dispatch mode 与 workflow state 是两个独立 contract。
- 不用全局 `.current-task` 替代 session pointer，不直接编辑 `.runtime/sessions/`，不把 `finish` 当作 archive。
- 修改 workflow tag 后运行：

```bash
python3 ./.trellis/scripts/get_context.py --mode phase --platform codex
python3 ./.trellis/scripts/task.py validate .trellis/tasks/08-31-project-wide-simplification
python3 ./.trellis/scripts/task.py validate .trellis/tasks/08-31-frontend-ui-foundation
python3 ./.trellis/scripts/task.py validate .trellis/tasks/08-31-frontend-performance-ux
python3 ./.trellis/scripts/task.py validate .trellis/tasks/08-31-server-boundary-simplification
python3 -m compileall -q .trellis/scripts .codex/hooks
```

另加静态审计：逐行解析所有 JSONL、检查 spec/research Markdown 链接和路径、搜索 placeholder/TODO、检查上游模板词是否误入 Metapi 规范，以及将 hook stdout 送入 `json.loads`。本轮不把已安装的上游英文 skill/template 批量翻译；只有实际修改的本地 Trellis 文档和 hook 文案按中文约定更新。
