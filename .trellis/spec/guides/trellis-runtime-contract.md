# Trellis 运行时契约

本文件是 Metapi 本地 Trellis runtime 的可执行说明，覆盖 workflow breadcrumb、Codex dispatch、任务生命周期、session pointer、JSONL manifest、workspace journal 和 `.codex/hooks/` 的输入输出。它描述当前仓库实际实现，不是上游 Trellis 模板的目录或版本说明。

## 1. 组件与单一事实来源

| 责任 | 实际文件 | 说明 |
| --- | --- | --- |
| 工作流正文和 breadcrumb body | `.trellis/workflow.md` | 自然语言阶段、路由和 `[workflow-state:STATUS]` block 的唯一来源 |
| 任务写入/归档 | `.trellis/scripts/task.py`、`common/task_store.py` | 创建、start、finish、archive、父子关系和 metadata |
| session active-task resolver | `.trellis/scripts/common/active_task.py` | 按 AI session/window 读写 `.trellis/.runtime/sessions/` |
| JSONL manifest 校验/展示 | `.trellis/scripts/common/task_context.py` | 读取 `implement.jsonl`/`check.jsonl`，跳过 seed，校验路径 |
| 上下文文本/JSON | `.trellis/scripts/common/session_context.py`、`get_context.py` | 输出 session、phase、package 和 task context |
| journal/index | `.trellis/scripts/add_session.py`、`common/developer.py` | append、轮换和 `@@@auto:*` managed regions |
| per-turn hook | `.codex/hooks/inject-workflow-state.py` | 解析 workflow tag 并注入 `<workflow-state>` |
| session-start hook | `.codex/hooks/session-start.py` | 输出 Codex hook JSON 和 compact context |
| sub-agent hook | `.codex/hooks/inject-subagent-context.py` | 注入角色、任务文档和 manifest 指向的 spec/research |

Trellis 不注册 MCP server。项目中的 `.codex/config.toml`、`.codex/hooks.json` 和 hooks 只负责本地上下文注入、任务生命周期和 agent wiring；全局 host 的 MCP 配置或警告不属于 Trellis runtime contract。

## 2. `[workflow-state:STATUS]` parser

### 2.1 语法

`inject-workflow-state.py` 使用等价于以下的正则读取 block：

```text
\[workflow-state:([A-Za-z0-9_-]+)\]\s*\n(.*?)\n\s*\[/workflow-state:\1\]
```

约束：

- `STATUS` 只能包含 ASCII 字母、数字、下划线和连字符，即 `[A-Za-z0-9_-]+`；
- 开标签和闭标签必须使用同一个 `STATUS`；大小写不应当依赖；
- body 去掉首尾空白后才加入 map；空 body 视为缺失；
- parser 只读 `.trellis/workflow.md`，不应在 Python hook 中复制与 workflow 冲突的 fallback status 字典；
- workflow 文件缺失、不可读或没有对应 tag 时，`build_breadcrumb()` 使用中文通用提示“请查阅 `.trellis/workflow.md` 确认当前步骤”，同时保留 `<workflow-state>` 包装和 status header。

### 2.2 status 与 breadcrumb key

| 来源 | breadcrumb key | 说明 |
| --- | --- | --- |
| 没有 session active task | `no_task` | runtime 伪状态，不写入 `task.json.status` |
| `task.json.status=planning` | `planning` | Phase 1；Codex `auto` 也使用该 key |
| `task.json.status=in_progress` | `in_progress` | Phase 2 与 Phase 3.2–3.4 |
| `task.json.status=completed` | `completed` | 归档前的收尾提示；实际归档会立即移动目录 |
| stale pointer | `stale_<source_type>` | `source_type` 由 resolver 产生，例如 `stale_session`；必须符合正则 |
| Codex + `dispatch_mode=inline` | `${status}-inline` | 使用 `planning-inline`、`in_progress-inline` 等专用 block |
| Codex + `dispatch_mode=auto` | `${status}` | 原生 `SubagentStart` 注入优先，child-side loading 为 fallback |

如果 `${status}-inline` 缺失，resolver 应回退查找普通 `status` body；两者都缺失才使用通用提示。非 Codex 平台不追加 `-inline`。

### 2.3 必须存在的 block

Metapi 的 workflow 至少应提供以下 block，并且 body 明确下一动作：

```text
[workflow-state:no_task]
...
[/workflow-state:no_task]

[workflow-state:planning]
...
[/workflow-state:planning]

[workflow-state:planning-inline]
...
[/workflow-state:planning-inline]

[workflow-state:in_progress]
...
[/workflow-state:in_progress]

[workflow-state:in_progress-inline]
...
[/workflow-state:in_progress-inline]

[workflow-state:completed]
...
[/workflow-state:completed]
```

每个 block 的 enforcement 行必须覆盖对应阶段中标记为 `[required · once]` 的步骤：planning 至少覆盖需求/研究/manifest/规划评审门；in_progress 至少覆盖实现前规范加载、实现、完整检查和 finish 前规范更新；completed 至少提示归档/收尾。Codex inline block 只改变执行者，不得删除这些门。

## 3. Codex `dispatch_mode` 分发模式

`codex.dispatch_mode` 位于 `.trellis/config.yaml`，不是 `task.json.status`：

- `auto`：默认值；实现和检查优先由 Trellis sub-agent 处理。主 session 仍负责协调、澄清、研究、更新规范、commit 和 finish。
- `inline`：主 session 直接实现和检查，不 dispatch implement/check sub-agent。
- `sub-agent`：旧别名，归一化为 `auto`，不得在新文档中作为第三种行为描述。
- 其他显式值：归一化为 `inline`，不在每轮重复警告。

`<codex-mode>` banner 说明 dispatch 协议；`<workflow-state>` body 说明当前阶段。两者是正交信息，不能用新增 status 代替 dispatch mode。

## 4. 按 session 隔离的活动任务（Session-specific active task）

### 4.1 指针来源

active task 只按 session/window 隔离，存放在：

```text
.trellis/.runtime/sessions/<sanitized-context-key>.json
```

resolver 的优先来源是 hook 传入的 `TRELLIS_CONTEXT_ID`，其次是已经在 `active_task.py` 明确登记的平台 session/conversation/transcript 环境变量。context key 会经过 `_sanitize_key()`，长度和字符集受限。没有稳定 key 时，不写入全局指针；不要恢复旧的 `.trellis/.current-task` 全局模型。

### 4.2 过期指针（stale pointer）

如果 session 文件仍指向不存在的 task 目录、归档后路径或损坏的 task metadata：

- resolver 返回 `stale=true` 或无可读 status；
- hook 注入 stale/unknown 提示，不得静默选择另一个活动任务；
- 操作者使用 `python3 ./.trellis/scripts/task.py finish` 清理当前 session，或对正确目录重新执行 `task.py start`；
- 不直接编辑 `.trellis/.runtime/sessions/`，除非是在专门的 runtime 修复任务中并有测试。

## 5. 任务生命周期（Task lifecycle）

### 5.1 `task.py create`

`task.py create "<title>"`：

1. 创建 `.trellis/tasks/MM-DD-slug/` 和 `task.json`，初始 `status` 为 `planning`；
2. 写入默认 `prd.md`；复杂任务由 AI 后续补 `design.md`、`implement.md` 和研究文件；
3. 在 Codex `auto` 或其他 sub-agent-capable 平台下 seed `implement.jsonl` 与 `check.jsonl`；
4. 按 `--parent` 建立双向 parent/children 链接；
5. 有 session identity 时 best-effort 设置当前 session pointer；没有 identity 时仍创建任务，但不污染其他 session；
6. 运行 `after_create` hook（失败只 warning，不应阻塞创建）。

`--no-start` 只跳过本次 session 激活，不跳过目录、task.json 或 PRD 写入。slug 只填写正文，不重复 `MM-DD-` 日期前缀。

### 5.2 `task.py start <dir>`

- 解析 task name、相对路径或绝对路径；
- 有 session key 时写当前 session pointer；
- 若 task 的 `status` 是 `planning`，改写为 `in_progress`；
- 运行 `after_start` hook；
- 如果没有 session identity，进入 degraded mode：仍写 `status=in_progress`，但明确提示 pointer 没有持久化，不能声称 session tracking 完整。

### 5.3 `task.py finish`

- 只清除当前 session 的 active-task pointer；
- 对仍可定位的 task 运行 `after_finish` hook；
- 不把 `status` 改成 `completed`，不移动 task 目录；
- 没有当前 task 时返回既有的无任务结果，不创建新 pointer。

### 5.4 `task.py archive <dir>`

- 先将 `task.json.status` 写为 `completed` 并写 `completedAt`；
- 清除仍指向该目录的 session pointer；
- 处理 parent/children 关系；
- 将目录移动到 `.trellis/tasks/archive/YYYY-MM/<dir>/`；
- `session_auto_commit` 为 true 时只 stage 归档相关 Trellis 路径并提交，false 时不触碰 Git；
- 运行 `after_archive` hook。

`completed` 是 archive writer 写入的机器状态；`finish` 不是 archive。branch 不存在只发 warning，不应阻塞归档。禁止用 broad `git add -f .trellis/` 处理归档。

## 6. JSONL seed 与上下文清单（manifest）

### 6.1 seed

`task_store.py` 的 seed 行形如：

```json
{"_example":"在这里填写 {\"file\":\"<path>\",\"reason\":\"<原因>\"}。只引用 spec/research 文件；完成整理后删除本行。"}
```

seed 只有 `_example`，没有 `file`，所以 validator、hook 和 agent prelude 会跳过它。`_example` 文案默认简体中文；JSON key、路径、`type`、`reason` 和 status 值必须保持机器契约。

### 6.2 整理后的真实条目（curated entry）

真实条目是一行 JSON object：

```jsonl
{"file":".trellis/spec/frontend/index.md","reason":"加载前端页面边界和质量门。"}
{"file":".trellis/tasks/08-31-project-wide-simplification/research/frontend-architecture.md","reason":"读取本任务已核实的前端请求和样式基线。"}
```

规则：

- `implement.jsonl` 给实现 agent 注入相关 spec/research；`check.jsonl` 给检查 agent 注入质量规范和必要研究；
- 不预注册 `src/**` 产品代码；agent 读取自己的 diff 和源码；
- 缺失文件/目录、非法 JSON 是 validation error；代码扩展名、超出 context byte cap 是 warning；
- 空行和没有 `file` 的 seed 静默跳过；
- `reason` 使用简体中文，字段名和路径保持原文。

## 7. Hook 输入输出

### 7.1 通用输入

Hook 从 stdin 读取 host JSON。应接受 `cwd`、`prompt`、session/conversation/transcript 标识和平台字段；缺失、空白、malformed 或非 object 输入采用 fail-closed 行为（空 dict、无 task 或无输出），`cwd` 等字段类型错误时也必须安全回退，不得抛出未处理异常或阻塞等待未关闭 stdin。

### 7.2 `inject-workflow-state.py`

- 普通分支输出 JSON，包含 `hookSpecificOutput.additionalContext`；Kiro 等纯文本分支输出 breadcrumb；
- additional context 形如 `<workflow-state>\n任务：<id>（<status>）\n<body>\n</workflow-state>`；没有 task 时 header 为 `状态：no_task`；
- `TRELLIS_HOOKS=0`、`TRELLIS_DISABLE_HOOKS=1`、非 Trellis 目录或 `no-trellis` keyword 时按现有逻辑静默退出；
- 缺失 tag 使用中文 generic hint，不改变 tag parser、status header 或退出码。

### 7.3 `session-start.py`

输出必须仍可由 `json.loads` 解析，并保留以下机器结构：

```json
{
  "suppressOutput": true,
  "systemMessage": "...",
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "..."
  }
}
```

`additionalContext` 可包含 `<session-context>`、`<current-state>`、`<trellis-workflow>`、`<guidelines>`、`<task-status>` 和 `<ready>`。自然语言默认简体中文；`hookEventName`、XML-like tag、JSON key、命令、路径和 status 值保持原文。

如果 hook 收到 malformed、空白、非 object 或非字符串 `cwd`，应采用当前进程目录
作为安全回退，不抛出未处理异常。若解析出的目录不是 Trellis 项目（没有
`.trellis/`），`session-start.py` 必须以退出码 0 静默结束，不能因为导入项目内
`common.active_task` 失败而阻断宿主 session。

### 7.4 `inject-subagent-context.py`

该 hook 读取平台 Task/Subagent 输入和 active task，按角色拼装：

```text
角色说明 → Active task: <path> → implement/check.jsonl → prd.md → design.md（可选）→ implement.md（可选）→ spec/research 内容
```

binary/超限文件只输出中文 warning 并跳过或截断；缺失 manifest 只 warning，不能伪造条目；非字符串的 host 字段（例如 `tool_name`、`agent_name`、`prompt`、`cwd`）应安全视为空值或回退到当前目录，不得抛出未处理异常。输出 schema、role 名、task path、文件路径和 JSON key 不得改名。实现/检查 agent 不应再次创建同类 agent，也不应依赖 parent transcript 才能得到任务契约。

## 8. 工作区与会话日志（Workspace 与 journal）

- `.trellis/workspace/<developer>/index.md` 和 `journal-N.md` 是 session 记录，不是产品运行数据；
- `journal-N.md` 超过 `max_journal_lines`（默认 2000）时创建下一个文件；
- `@@@auto:current-status`、`@@@auto:active-documents`、`@@@auto:session-history` marker 必须原样保留；
- `add_session.py` 同时读取历史英文 `Total Sessions` 和中文 `会话总数`，所以中文化生成模板不能删除兼容读取；
- session auto-commit 只允许当前开发者 journal/index 与当前 task 目录，不得把并行 task 或整个 `.trellis/` 纳入；
- journal 的标题、摘要、测试和后续步骤默认使用简体中文；commit hash、branch、命令、路径和表格机器列结构保持原文。

## 9. 修改与验证矩阵

| 修改对象 | 必须联查 | 最低验证 |
| --- | --- | --- |
| workflow tag/body | `inject-workflow-state.py`、`get_context.py --mode phase`、各 required step | tag 正则扫描、phase 输出、缺失 tag fallback |
| status writer | `task.py`、`task_store.py`、`active_task.py`、hook | create/start/finish/archive 的 JSON 与 pointer 状态 |
| dispatch mode | `config.yaml`、Codex banner、sub-agent hook、任务 manifest | `auto`/`inline`/`sub-agent`/非法值解析 |
| JSONL seed/validator | `task_context.py`、`inject-subagent-context.py`、四份任务 manifest | 逐行 `json.loads`、`task.py validate`、seed 不计数 |
| workspace 文案 | `developer.py`、`add_session.py`、现有 index/journal | 新模板生成、旧英文 index 读取、marker 不变 |
| hook IO | `.codex/hooks.json`、三个 hook、stdin/stdout | malformed/empty input、合法 JSON 输出、skip 条件 |

推荐命令：

```bash
python3 ./.trellis/scripts/get_context.py --mode packages
python3 ./.trellis/scripts/get_context.py --mode phase --platform codex
python3 ./.trellis/scripts/task.py validate .trellis/tasks/08-31-project-wide-simplification
python3 ./.trellis/scripts/task.py validate .trellis/tasks/08-31-frontend-ui-foundation
python3 ./.trellis/scripts/task.py validate .trellis/tasks/08-31-frontend-performance-ux
python3 ./.trellis/scripts/task.py validate .trellis/tasks/08-31-server-boundary-simplification
python3 -m compileall -q .trellis/scripts .codex/hooks
npm run repo:drift-check
git diff --check
```

静态审计还应检查 Markdown 链接/路径、JSONL 每行解析、`placeholder`/`TODO`、误残留的上游模板路径，以及把每个 hook stdout 送入 `json.loads`。任何“运行时契约已完成”的结论都必须附上述证据，而不是只凭文档存在。
