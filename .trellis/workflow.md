# 开发工作流

---

## 核心原则

1. **先规划再编码** — 在开始前先弄清楚要做什么
2. **注入规范而不是凭记忆** — 通过 hook/skill 注入指南，不要求 AI 依赖记忆
3. **持久化一切重要信息** — 研究、决策和经验都写入文件；对话会被压缩，文件不会
4. **增量开发** — 一次只处理一个任务
5. **记录经验** — 每个任务结束后，复盘并把新知识写回规范

---

## Trellis 系统

### 开发者身份

首次使用时初始化你的身份：

~~~bash
python3 ./.trellis/scripts/init_developer.py <your-name>
~~~

该命令创建 .trellis/.developer（已加入 gitignore）和 .trellis/workspace/<your-name>/。

### 规范系统

.trellis/spec/ 存放按 package 和 layer 组织的编码规范。

- .trellis/spec/<package>/<layer>/index.md — 规范入口，包含开发前检查和质量检查；具体规则位于它链接的 .md 文件中。
- .trellis/spec/guides/index.md — 跨 package 的思考指南。

~~~bash
python3 ./.trellis/scripts/get_context.py --mode packages   # 列出 package / layer
~~~

**需要更新规范的时机**：发现新的模式/约定、需要把 bug 预防措施写成规则，或形成新的技术决策。

### 任务系统

每个任务都在 .trellis/tasks/{MM-DD-name}/ 下拥有独立目录，包含 task.json、prd.md、可选的 design.md、可选的 implement.md、可选的 research/，以及供支持 sub-agent 的平台使用的上下文 manifest（implement.jsonl、check.jsonl）。

~~~bash
# 任务生命周期
python3 ./.trellis/scripts/task.py create "<title>" [--slug <name>] [--parent <dir>]
python3 ./.trellis/scripts/task.py start <name>          # 设置活动任务（可用时按 session 保存）
python3 ./.trellis/scripts/task.py current --source      # 显示活动任务及其来源
python3 ./.trellis/scripts/task.py finish                # 清除活动任务（触发 after_finish hook）
python3 ./.trellis/scripts/task.py archive <name>        # 移到 archive/{year-month}/
python3 ./.trellis/scripts/task.py list [--mine] [--status <s>]
python3 ./.trellis/scripts/task.py list-archive

# Code-spec 上下文（通过 JSONL 注入 implement/check agent）
# implement.jsonl / check.jsonl 在 task create 时为支持 sub-agent 的平台预置；
# 规划阶段需要时由 AI 填入真实的 spec + research 条目。
python3 ./.trellis/scripts/task.py add-context <name> <action> <file> <reason>
python3 ./.trellis/scripts/task.py list-context <name> [action]
python3 ./.trellis/scripts/task.py validate <name>

# 任务 metadata
python3 ./.trellis/scripts/task.py set-branch <name> <branch>
python3 ./.trellis/scripts/task.py set-base-branch <name> <branch>    # PR 目标分支
python3 ./.trellis/scripts/task.py set-scope <name> <scope>

# 层级（父任务/子任务）
python3 ./.trellis/scripts/task.py add-subtask <parent> <child>
python3 ./.trellis/scripts/task.py remove-subtask <parent> <child>

# 创建 PR
# 当前本地 task.py 不提供 create-pr；创建 PR 请按仓库既有流程手工执行。
~~~

> 使用 python3 ./.trellis/scripts/task.py --help 查看权威且最新的命令列表。

**活动任务机制**：task.py create 会创建任务目录，并在有 session identity 时自动设置当前 session 的活动任务指针，使规划 breadcrumb 立即生效。task.py start 写入相同指针（若已设置则幂等），并把 task.json.status 从 planning 切换为 in_progress。状态保存在 .trellis/.runtime/sessions/。如果 hook 输入、TRELLIS_CONTEXT_ID 或平台原生 session 环境中都没有 context key，task.py start 会提示并进入降级模式：仍切换 task.json.status，但不持久化 session 指针。task.py finish 删除当前 session 文件（不改变 status）。task.py archive <task> 写入 status=completed，把目录移到 archive/，并删除仍指向该任务的运行时 session 文件。

### 工作区系统

在 .trellis/workspace/<developer>/ 下记录每个 AI session，便于跨 session 追踪。

- journal-N.md — session 日志。每个文件最多 2000 行；超出后自动创建 journal-(N+1).md。
- index.md — 个人索引（总 session 数、最近活动）。

~~~bash
python3 ./.trellis/scripts/add_session.py --title "会话标题" --commit "hash" --summary "会话摘要"
~~~

### 上下文脚本

~~~bash
python3 ./.trellis/scripts/get_context.py                            # 完整 session runtime
python3 ./.trellis/scripts/get_context.py --mode packages            # 可用 package / spec layer
python3 ./.trellis/scripts/get_context.py --mode phase --step <X.Y>  # 某个工作流步骤的详细指南
~~~

---

<!--
  WORKFLOW-STATE 面包屑契约（编辑下面的 tag block 前请先阅读）

  ## Phase Index 中嵌入的 [workflow-state:STATUS] block 是每轮
  <workflow-state> 面包屑的唯一事实来源。所有支持的 AI 平台的
  UserPromptSubmit 等价 hook 都读取这些 block；`.codex/hooks/`
  下的 Python hook 只负责解析和包装，不复制另一套 status 文案。

  STATUS 只能使用 [A-Za-z0-9_-]+。找不到 tag 时，hook 会降级为通用的
  “请查阅 .trellis/workflow.md 确认当前步骤”，让用户能够及时发现损坏的 workflow.md。

  不变量（test/regression.test.ts）：
    每一个 walkthrough 中标记为 [required · once] 的步骤，都必须在所属阶段的
    [workflow-state:*] block 中有对应的 enforcement 行。面包屑是每轮唯一的注入
    通道；如果遗漏必需步骤，AI 会静默跳过它（Phase 1 planning gate 和 Phase 3.4
    commit gate 都曾因这个缺口而失效）。

  TAG 与 PHASE 的范围：
    [workflow-state:no_task]      → 没有活动任务；Phase 1 之前
    [workflow-state:planning]     → 整个 Phase 1（status='planning'）
    [workflow-state:planning-inline] → Codex inline 版 Phase 1
    [workflow-state:in_progress]  → Phase 2 + Phase 3.2-3.4
                                    （从 task.py start 到 task.py archive 期间
                                    status 保持 'in_progress'）
    [workflow-state:in_progress-inline] → Codex inline 版 Phase 2/3
    [workflow-state:completed]    → 当前实际不会触发：cmd_archive 在同一次调用中
                                    翻转 status 并移动目录，resolver 因而丢失指针
                                    （为未来明确的 in_progress→completed 转换保留该 block）

  编辑检查清单：
    - 修改 [workflow-state:STATUS] block 时，同时检查对应阶段的
      [required · once] walkthrough 步骤是否同步
    - 编辑后重新运行相关 get_context/hook 校验；本项目没有下游模板同步步骤
    - 完整运行时契约：
      .trellis/spec/guides/trellis-runtime-contract.md
-->


## Phase Index

**文档语言约定**：Trellis 管理的开发文档默认使用简体中文，包括任务规划、设计、执行计划、研究记录、规范和会话日志。命令、路径、代码符号、配置字段、协议名及用户指定的原文保持规范拼写。已有英文历史文档和上游公共模板不要求批量回译；实际修改时，新增内容遵循 .trellis/spec/guides/documentation-language.md。

~~~
Phase 1: Plan    → 分类请求、取得创建任务的同意，然后写入规划文档
Phase 2: Execute → 仅在任务 status 为 in_progress 后实现
Phase 3: Finish  → 验证、更新规范、提交并收尾
~~~

[workflow-state:planning]
当前任务处于规划阶段（`status=planning`）。只做需求探索、仓库研究和文档整理：保持 `prd.md` 只写需求/约束/验收标准；复杂任务补齐 `design.md`、`implement.md` 和 `research/`；在 sub-agent dispatch 模式下整理 `implement.jsonl`/`check.jsonl` 的真实 spec/research 条目。完成规划后先取得用户的实现确认，再运行 `python3 ./.trellis/scripts/task.py start <task-dir>`；在此之前不要修改产品代码或声称任务已进入实现。
[/workflow-state:planning]

[workflow-state:planning-inline]
当前任务处于规划阶段，且 Codex `dispatch_mode=inline`：在主 session 中完成需求探索、源码研究、`prd.md`/`design.md`/`implement.md`/`research/` 和 manifest 整理。`status=planning` 时不要实现产品代码；规划文档评审并取得用户确认后，才运行 `python3 ./.trellis/scripts/task.py start <task-dir>`。
[/workflow-state:planning-inline]

### 请求分流

- 简单问答或小任务：只询问本轮是否要创建 Trellis task。用户回答否时，本 session 跳过 Trellis。
- 复杂任务：询问是否允许创建 Trellis task 并进入规划阶段。用户回答否时，不做大范围 inline 实现；改为解释、澄清范围或建议拆小。
- 用户同意创建 task 不等于同意开始实现；仍必须先完成规划。

### 规划文档

- prd.md — 需求、约束和验收标准。不要在其中放技术设计或执行清单。
- design.md — 复杂任务的技术设计：边界、contract、数据流、权衡、兼容性、发布/回滚形态。
- implement.md — 复杂任务的执行计划：有序清单、验证命令、评审门和回滚点。
- implement.jsonl / check.jsonl — sub-agent 上下文使用的 spec/research manifest，不替代 implement.md。
- 轻量任务可以只有 prd.md；复杂任务在 task.py start 前必须有 prd.md、design.md 和 implement.md。

### 父子任务树

当一次请求包含多个可独立验证的交付物时，使用 parent task。父任务拥有源需求、任务地图、跨子任务验收标准和最终集成评审；除非父任务自身也有直接工作，否则不要把它作为实现目标。

子任务用于可以独立规划、实现、检查和归档的交付物。父子结构不是依赖系统：如果子任务 B 依赖子任务 A，必须在 B 的 prd.md / implement.md 中写明顺序，并让每个子任务的验收条件可测试。

使用 task.py create "<title>" --slug <name> --parent <parent-dir> 创建子任务；使用 task.py add-subtask <parent> <child> 关联已有任务，使用 task.py remove-subtask <parent> <child> 解除错误关联。

<!-- 无活动任务时显示的每轮 breadcrumb（Phase 1 之前） -->

[workflow-state:no_task]
没有活动任务。先分类当前请求，并在创建任何 Trellis task 前取得用户同意。
简单问答/小任务：只询问本轮是否创建 Trellis task；如果用户回答否，本 session 跳过 Trellis。
复杂任务：询问用户是否允许创建 Trellis task 并进入规划；如果用户回答否，解释、澄清范围或建议拆小。
[/workflow-state:no_task]

## Phase 1: Plan

目标：对请求分类，在需要时取得创建 task 的同意，并在实现前产出所需的规划文档。

#### 1.0 创建任务 [required · once]

只有在用户同意创建 task 后才创建任务目录。该命令会把 status 设为 planning、写入 task.json、创建默认 prd.md，并在有 session identity 时自动把新任务设为当前目标：

~~~bash
python3 ./.trellis/scripts/task.py create "<task title>" --slug <name>
~~~

--slug 只填写可读名称。不要包含 MM-DD- 日期前缀；task.py create 会自动添加。

对于任务树，先创建 parent task，再使用 --parent <parent-dir> 创建每个 child。不要因为存在子任务就启动 parent；应启动拥有下一个可独立验证交付物的 child。

命令成功后，每轮 breadcrumb 会自动切换到 [workflow-state:planning]，提示 AI 留在规划阶段。

这里只运行 create，不要同时运行 start。start 会把 status 切换为 in_progress，使 breadcrumb 在规划文档评审前就进入实现阶段；start 留到步骤 1.4。

如果 python3 ./.trellis/scripts/task.py current --source 已经指向任务，则跳过本步骤。

#### 1.1 需求探索 [required · repeatable]

加载 trellis-brainstorm skill，并按照该 skill 的规则与用户交互探索需求。

brainstorm skill 会引导你：

- 一次只问一个问题；
- 优先研究，而不是把可以从仓库得到的答案再问用户；
- 优先给出选项，而不是开放式提问；
- 在每次用户回答后立即更新 prd.md；
- 当交付物可以独立验证时，把大范围拆为 parent task + child tasks；
- 让 prd.md 只记录需求和验收标准；
- 对复杂任务，在实现开始前产出 design.md 和 implement.md。

考虑 parent/child 拆分时：

- 一次请求包含多个可独立验证的交付物时使用 parent task；
- parent task 拥有源需求、child-task 映射、跨 child 验收标准和最终集成评审；
- child task 拥有可独立规划、实现、检查和归档的实际交付物；
- parent/child 结构不是依赖系统。如果 child B 依赖 child A，必须在 B 的 prd.md / implement.md 中写明；
- 启动拥有下一个交付物的 child task。除非 parent 本身有直接实现工作，不要启动 parent。

需求变化时回到本步骤，修订对应文档。

#### 1.2 研究 [optional · repeatable]

研究可以在需求探索期间的任意时机进行，不限于本地代码。可以使用可用工具（MCP server、skill、web search 等）查询第三方库文档、行业实践、API reference 等外部信息。

[Claude Code, Cursor, OpenCode, codex-sub-agent, Kiro, Gemini, Qoder, CodeBuddy, Copilot, Droid, Pi, Oh My Pi, ZCode, Snow, Reasonix, Trae, Grok, Kimi Code]

启动 research sub-agent：

- **Agent 类型**：trellis-research
- **任务描述**：研究 <具体问题>
- **关键要求**：研究输出必须持久化到 {TASK_DIR}/research/

[/Claude Code, Cursor, OpenCode, codex-sub-agent, Kiro, Gemini, Qoder, CodeBuddy, Copilot, Droid, Pi, Oh My Pi, ZCode, Snow, Reasonix, Trae, Grok, Kimi Code]

[codex-inline, Kilo, Antigravity, Devin]

在主 session 中直接研究，并把发现写入 {TASK_DIR}/research/。codex-inline 是明确要求研究留在主 session 的模式。

[/codex-inline, Kilo, Antigravity, Devin]

**研究文档约定**：

- 每个研究主题一个文件（例如 research/auth-library-comparison.md）；
- 在文件中记录第三方库的使用示例、API reference 和版本约束；
- 记录为后续引用而发现的相关 spec 文件路径。

brainstorm 和 research 可以交错进行：可以暂停对话去研究技术问题，再回来继续讨论。

**核心原则**：研究结果必须写入文件，不能只留在聊天中。对话会被压缩，文件不会。

#### 1.3 配置上下文 [required · once]

[Claude Code, Cursor, OpenCode, codex-sub-agent, Kiro, Gemini, Qoder, CodeBuddy, Copilot, Droid, Pi, Oh My Pi, ZCode, Snow, Reasonix, Trae, Grok, Kimi Code]

整理 implement.jsonl 和 check.jsonl，使 Phase 2 sub-agent 得到正确的 spec/research 上下文。这两个文件在 task create 时会预置一行自描述的 _example；本步骤要把它们填写为真实条目。

**位置**：{TASK_DIR}/implement.jsonl 和 {TASK_DIR}/check.jsonl（文件已存在）。

**格式**：每行一个 JSON object：{"file": "<path>", "reason": "<原因>"}。路径相对于仓库根目录。

**应填写**：

- **Spec 文件**：与任务相关的 .trellis/spec/<package>/<layer>/index.md 和具体 guideline 文件（error-handling.md、conventions.md 等）；
- **Research 文件**：sub-agent 需要查阅的 {TASK_DIR}/research/*.md。

**不要填写**：

- 代码文件（src/**、packages/**/*.ts 等）——sub-agent 实现时自行读取；
- 即将修改的文件——理由相同。

**两个 manifest 的分工**：

- implement.jsonl → implement sub-agent 正确编码所需的 spec + research；
- check.jsonl → check sub-agent 所需的质量规范、检查约定和必要 research。

manifest 不替代 implement.md。implement.md 是复杂任务的人类可读执行计划；JSONL 只列出需要注入或加载的上下文文件。

**发现相关规范**：

~~~bash
python3 ./.trellis/scripts/get_context.py --mode packages
~~~

该命令列出每个 package、spec layer 及其路径；选择与任务领域相符的条目。

**追加条目**：

可以直接编辑 JSONL，也可以使用：

~~~bash
python3 ./.trellis/scripts/task.py add-context "$TASK_DIR" implement "<path>" "<reason>"
python3 ./.trellis/scripts/task.py add-context "$TASK_DIR" check "<path>" "<reason>"
~~~

真实条目存在后可以删除 _example 行（可选；consumer 会自动跳过它）。

准备门槛：task.py start 前，implement.jsonl 和 check.jsonl 都必须至少包含一个真实 {"file": "...", "reason": "..."} 条目；只有 _example 行不算准备完成。

仅当两个文件已经有真实整理条目时才跳过本步骤。

[/Claude Code, Cursor, OpenCode, codex-sub-agent, Kiro, Gemini, Qoder, CodeBuddy, Copilot, Droid, Pi, Oh My Pi, ZCode, Snow, Reasonix, Trae, Grok, Kimi Code]

[codex-inline, Kilo, Antigravity, Devin]

跳过本步骤。上下文会在 Phase 2 由 trellis-before-dev skill 直接加载。

[/codex-inline, Kilo, Antigravity, Devin]

#### 1.4 激活任务 [required · once]

完成文档评审后，将任务 status 切换为 in_progress：

~~~bash
python3 ./.trellis/scripts/task.py start <task-dir>
~~~

轻量任务可以只有 prd.md。复杂任务在 start 前必须有 prd.md、design.md 和 implement.md，并且这些文档已经评审。在 sub-agent-dispatch 平台上，implement.jsonl 和 check.jsonl 也必须各自有真实整理条目。运行时 consumer 为兼容性可以容忍缺失或只有 seed 的 manifest，但这不代表已经达到规划就绪状态。

命令成功后，breadcrumb 自动切换为 [workflow-state:in_progress]，随后进入 Phase 2 / 3。

如果 task.py start 找不到 session identity（hook input、TRELLIS_CONTEXT_ID 或平台原生 session env 中没有 context key），脚本会进入降级模式：仍把 status 写为 in_progress，但不持久化当前 session 的任务指针。需要完整 session tracking 时，在能提供 context key 的 session 中重试。

#### 1.5 完成标准

| 条件 | 必须 |
|------|:---:|
| prd.md 存在 | ✅ |
| 用户确认任务可以进入实现 | ✅ |
| 已运行 task.py start（status = in_progress） | ✅ |
| complex task 有 research/ 产物 | 建议 |
| complex task 有 design.md | ✅ |
| complex task 有 implement.md | ✅ |

[Claude Code, Cursor, OpenCode, codex-sub-agent, Kiro, Gemini, Qoder, CodeBuddy, Copilot, Droid, Pi, Oh My Pi, ZCode, Snow, Reasonix, Trae, Grok, Kimi Code]

| implement.jsonl 和 check.jsonl 各自包含至少一个真实整理条目（seed 行不算） | ✅ |

[/Claude Code, Cursor, OpenCode, codex-sub-agent, Kiro, Gemini, Qoder, CodeBuddy, Copilot, Droid, Pi, Oh My Pi, ZCode, Snow, Reasonix, Trae, Grok, Kimi Code]

---

## Phase 2: Execute

目标：把已经评审的规划文档转化为通过质量检查的代码。

[workflow-state:in_progress]
当前任务处于实现阶段（`status=in_progress`）。实现前加载相关 `.trellis/spec/`、任务文档和 `research/`；按 `implement.md` 逐项实现，保持 route/page/transformer/db 边界和既有协议语义。实现后运行聚焦测试、typecheck、必要的 build 与 `npm run repo:drift-check`，再进行一次覆盖完整变更范围的 `trellis-check`。检查通过后执行 Phase 3.2（如需复盘）、3.3（更新规范）和 3.4（拟定并等待一次性 commit 计划确认）；不要提交或推送未经确认的变更。
[/workflow-state:in_progress]

[workflow-state:in_progress-inline]
当前任务处于实现阶段，且 Codex `dispatch_mode=inline`：主 session 直接加载规范、实现和检查完整 diff；不得把局部绿色测试当作整体验收。实现后运行 focused/full tests、typecheck、build、drift 和 diff check，完成 Phase 3.2/3.3，并在 3.4 展示一次性 commit 计划后等待用户确认；不要提交或推送未经确认的变更。
[/workflow-state:in_progress-inline]

#### 2.1 实现 [required · repeatable]

[Claude Code, Cursor, OpenCode, codex-sub-agent, CodeBuddy, Droid, Pi, ZCode, Snow, Oh My Pi]

启动 implement sub-agent：

- **Agent 类型**：trellis-implement
- **任务描述**：实现已评审的任务文档，查阅 {TASK_DIR}/research/ 下的材料；结束前运行项目 lint 和 type-check
- **Dispatch prompt 守卫**：prompt 必须以 `Active task: <task path>` 开头，然后明确告知该 agent 已经是 trellis-implement sub-agent，应直接实现，不得再创建 trellis-implement / trellis-check。

平台 hook/plugin 自动负责：

- 读取 implement.jsonl，并把其中引用的 spec/research 文件注入 agent prompt；
- 注入 prd.md、存在时的 design.md 和 implement.md；
- 对 Codex，SubagentStart 提供原生上下文注入；agent profile 保留子 agent 侧加载作为 fallback。

[/Claude Code, Cursor, OpenCode, codex-sub-agent, CodeBuddy, Droid, Pi, ZCode, Snow, Oh My Pi]

[Gemini, Qoder, Copilot, Reasonix, Trae, Grok, Kimi Code]

启动 implement sub-agent：

- **Agent 类型**：trellis-implement
- **任务描述**：实现已评审的任务文档，查阅 {TASK_DIR}/research/ 下的材料；结束前运行项目 lint 和 type-check
- **Dispatch prompt 守卫**：prompt 必须以 `Active task: <task path>` 开头，然后明确该 agent 已经是 trellis-implement，必须直接实现，不得再创建 trellis-implement / trellis-check。

拉取式（pull）模式的 sub-agent 定义自动负责上下文加载：

- 通过 task.py current --source 解析活动任务，然后读取 prd.md、存在时的 design.md 和 implement.md；
- 读取 implement.jsonl，并要求 agent 在编码前加载其中引用的每个 spec/research 文件。

[/Gemini, Qoder, Copilot, Reasonix, Trae, Grok, Kimi Code]

[Kiro]

启动 implement sub-agent：

- **Agent 类型**：trellis-implement
- **任务描述**：实现已评审的任务文档，查阅 {TASK_DIR}/research/ 下的材料；结束前运行项目 lint 和 type-check
- **Dispatch prompt 守卫**：告知该 agent 已经是 trellis-implement，必须直接实现，不得再创建 trellis-implement / trellis-check。

平台 prelude 自动负责上下文加载：

- 读取 implement.jsonl，并注入其中引用的 spec/research 文件；
- 注入 prd.md、存在时的 design.md 和 implement.md。

[/Kiro]

[codex-inline, Kilo, Antigravity, Devin]

1. 加载 trellis-before-dev skill，读取项目规范；
2. 读取 {TASK_DIR}/prd.md，然后读取存在时的 design.md 和 implement.md；
3. 查阅 {TASK_DIR}/research/ 下的材料；
4. 按照已评审文档实现代码；
5. 运行项目 lint 和 type-check。

[/codex-inline, Kilo, Antigravity, Devin]

#### 2.2 质量检查 [required · repeatable]

[Claude Code, Cursor, OpenCode, codex-sub-agent, Kiro, Gemini, Qoder, CodeBuddy, Copilot, Droid, Pi, Oh My Pi, ZCode, Snow, Reasonix, Trae, Grok, Kimi Code]

启动 check sub-agent：

- **Agent 类型**：trellis-check
- **任务描述**：对照规范和任务文档评审所有代码变更；直接修复发现的问题；确保 lint 和 type-check 通过
- **Dispatch prompt 守卫**：prompt 必须以 `Active task: <task path>` 开头，然后明确该 agent 已经是 trellis-check，必须直接 review/fix，不得再创建 trellis-check / trellis-implement。

check agent 的职责：

- 对照 spec 评审代码变更；
- 对照 prd.md、存在时的 design.md 和 implement.md 评审代码变更；
- 自动修复发现的问题；
- 运行 lint 和 typecheck 验证。

[/Claude Code, Cursor, OpenCode, codex-sub-agent, Kiro, Gemini, Qoder, CodeBuddy, Copilot, Droid, Pi, Oh My Pi, ZCode, Snow, Reasonix, Trae, Grok, Kimi Code]

[codex-inline, Kilo, Antigravity, Devin]

加载 trellis-check skill，并按其规则验证代码：

- spec 合规性；
- lint / type-check / tests；
- 跨层一致性（变更跨越多个层时）。

如果发现问题 → 修复 → 重新检查，直到通过。

[/codex-inline, Kilo, Antigravity, Devin]

**最终检查（Phase 3.4 commit 前）**：任务最后一次 2.2 必须覆盖完整变更范围，不能只检查最新 implement 分块。使用 python3 ./.trellis/scripts/get_context.py --mode packages 列出所有受影响 package，然后加载每个 package 的规范索引中的“质量检查”部分。这样可以发现中途局部 2.2 无法发现的跨层/多 package 问题。

#### 2.3 回滚 [on demand]

- check 暴露 prd 缺陷 → 回到 Phase 1，修复 prd.md，再重新执行 2.1；
- 实现出错 → 回滚代码，再重新执行 2.1；
- 需要更多研究 → 按 Phase 1.2 的方式研究，并把发现写入 research/。

---

## Phase 3: Finish

目标：确保代码质量，记录经验并保存本次工作。

[workflow-state:completed]
任务已写入 `status=completed`，但目录可能尚未归档。先核对完整 diff、验证结果和规范同步，再运行 `python3 ./.trellis/scripts/task.py archive <task-dir>` 或按用户要求交由其手工归档；不要把 `task.py finish` 当作归档，也不要在没有 commit 计划确认时自动提交。
[/workflow-state:completed]

#### 3.2 调试复盘 [on demand]

如果本任务反复调试过同一个问题（同一问题被修复多次），加载 trellis-break-loop skill：

- 分类根因；
- 解释之前的修复为什么没有奏效；
- 提出预防措施。

目标是记录调试经验，避免同类问题再次出现。

#### 3.3 更新规范 [required · once]

加载 trellis-update-spec skill，检查本任务是否产生值得记录的新知识：

- 新发现的模式或约定；
- 遇到的陷阱；
- 新的技术决策。

相应更新 .trellis/spec/ 下的文档。即使结论是“无需更新”，也要完成这次判断。

#### 3.4 提交变更 [required · once]

**规范同步前置检查**：拟定 commit 前先问自己：本任务是否修复了 bug，或发现了应该写入 .trellis/spec/ 的非显然知识，以便未来自己或 AI 不再重复？如果是，先回到 Phase 3.3；规范写入必须与本任务的 commit 批次一起完成，不能遗忘到后续。

AI 负责把本任务的代码变更按批次提交，使 /finish-work 之后可以在 clean working tree 上运行。顺序是先提交工作代码，再提交 archive + journal 等 bookkeeping；两者绝不交错。

**步骤**：

1. **检查 dirty state**：
   ~~~bash
   git status --porcelain
   ~~~
   记录每一条 dirty path。如果工作树干净，跳到 3.5。

2. **从近期历史学习 commit 风格**（使拟定的 message 保持一致）：
   ~~~bash
   git log --oneline -5
   ~~~
   注意 prefix 约定（feat: / fix: / chore: / docs: 等）、语言（中文/English）和长度风格。

3. **把 dirty 文件分成两组**：
   - **本 session 由 AI 编辑** — 你在本 session 通过 Edit/Write/Bash tool 调用写入或修改的文件；你清楚其变更原因。
   - **无法识别** — 本 session 未触碰的 dirty 文件（可能是用户手工修改、之前留下的 WIP 或无关工作）。不要静默纳入。

4. **起草 commit 计划**。按逻辑 commit 分组本 session 编辑的文件（每个连贯变更单元一个 commit，不要每个文件一个 commit）。每项写明 <提交说明> + 文件列表；无法识别的文件单独列在底部。

5. **展示一次计划并取得一次性确认**。格式：

   ~~~text
   拟提交的批次（按顺序）：
     1. <提交说明>
        - <file>
        - <file>
     2. <提交说明>
        - <file>

   无法识别的 dirty 文件（不纳入任何提交，请确认是否包含/排除）：
     - <file>
     - <file>

   回复“ok”/“行”执行；回复修改意见，或“我自己来”/“manual”退出。
   ~~~

6. **获得确认后**：按每个批次运行 git add <files> + git commit -m "<msg>"。不要 amend，不要 push。

7. **用户拒绝时**（回复“不行”、“我自己来”、“manual”，或对计划有任何反对）：停止，不要再拟第二版计划。用户会手工提交；待用户确认后直接进入 3.5。

**规则**：

- 任何地方都禁止 git commit --amend——保持三阶段三 commit 流程（工作 commit → archive commit → journal commit）。
- 本步骤绝不 push 到 remote。
- 如果用户只希望修改提交说明文字且接受文件分组，修改后重新确认一次；如果用户拒绝分组，则进入手工模式。
- 批次计划只询问一次，不要每个 commit 单独询问。

#### 3.5 收尾提醒

完成上述步骤后，提醒用户可以运行 /finish-work 收尾（归档任务、记录 session）。

---

## 定制 Trellis（供 fork 使用）

本节面向希望修改 Trellis 工作流本身的开发者。所有定制都通过编辑本文件完成；脚本只负责解析。

### 修改步骤含义

编辑上方 Phase 1 / 2 / 3 中对应步骤的 walkthrough body。必须保持以下不变量：

- 没有活动任务时，先做请求分流，并在创建 Trellis task 前取得用户同意；
- 规划阶段必须区分轻量 PRD-only task 与复杂 task；复杂 task 在 start 前需要 prd.md、design.md 和 implement.md；
- 每条必需执行路径都必须能在 /trellis:finish-work 之前到达 Phase 3.4 commit reminder。

所有 tag block 都位于上方的 ## Phase Index 中，紧跟各阶段摘要：

| 范围 | 对应 tag |
|---|---|
| 没有活动任务（Phase 1 之前） | [workflow-state:no_task]（Phase Index ASCII 图之后） |
| 整个 Phase 1（创建 task → 可以实现） | [workflow-state:planning]（Phase 1 摘要之后） |
| Codex inline Phase 1 | [workflow-state:planning-inline] |
| Phase 2 + Phase 3.2–3.4（实现 + 检查 + 收尾） | [workflow-state:in_progress]（Phase 2 摘要之后） |
| Codex inline Phase 2 + Phase 3.2–3.4 | [workflow-state:in_progress-inline] |
| Phase 3.5 之后（已归档） | [workflow-state:completed]（Phase 3 摘要之后；当前实际不会触发） |

### 修改每轮 prompt 文本

直接编辑对应 [workflow-state:STATUS] block 的 body。编辑自己的项目时，完成后重启 AI session；模板维护者则运行 trellis update。无需修改脚本。

### 添加自定义 status

添加一个新 block：

~~~text
[workflow-state:my-status]
这里填写该状态下每轮需要执行的中文提示。
[/workflow-state:my-status]
~~~

约束：

- STATUS 只能使用 [A-Za-z0-9_-]+（允许下划线和连字符，例如 in-review、blocked-by-team）；
- lifecycle hook 必须把 task.json.status 写成自定义值，否则永远不会读取该 tag；
- lifecycle hook 位于 task.json.hooks.after_*，并绑定 after_create / after_start / after_finish / after_archive 之一。

### 添加生命周期 hook

在 task.json 中增加 hooks 字段：

~~~json
{
  "hooks": {
    "after_finish": [
      "your-script-or-command-here"
    ]
  }
}
~~~

支持的事件：after_create / after_start / after_finish / after_archive。注意 after_finish 不等于 status 变化（它只清除活动任务指针）；如果要表示“task 已完成”的通知，应使用 after_archive。

### 完整 contract

关于 workflow 状态机的运行时 contract、所有 status writer 的位置、伪 status（no_task / stale_<source_type>）、hook 可达性矩阵和其他深层细节，参见：

- .trellis/spec/guides/trellis-runtime-contract.md — runtime contract、writer 表和测试不变量
- .codex/hooks/inject-workflow-state.py — 实际 parser（只读取 workflow.md，并在缺失 tag 时给出中文通用提示）
