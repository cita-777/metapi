#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多平台 Sub-Agent 上下文注入 Hook。

启动 sub-agent（implement、check、research）时注入任务专属上下文。

核心设计原则：
- Hook 负责注入完整上下文，sub-agent 获得足够信息后自主工作；
- 每个 agent 使用独立 JSONL 文件声明上下文；
- 不需要 resume 或分段，行为由代码而不是 prompt 控制。

触发事件：PreToolUse（调用 Task 工具之前）

上下文来源：Trellis active task resolver 指向的任务目录
- implement.jsonl - Implement agent 专属上下文
- check.jsonl     - Check agent 专属上下文
- prd.md          - 需求文档
- design.md       - 复杂任务技术设计
- implement.md    - 复杂任务执行计划
- codex-review-output.txt - Code Review 结果
"""
from __future__ import annotations

# 重要：先屏蔽所有 warning
import warnings
warnings.filterwarnings("ignore")

import json
import os
import sys
from pathlib import Path
from typing import Any

# Hook host 无论进程 locale 如何都发送 UTF-8 JSON。
_stdin_reconfigure = getattr(sys.stdin, "reconfigure", None)
if callable(_stdin_reconfigure):
    try:
        _stdin_reconfigure(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        pass

# 重要：Windows 上强制 stdout 使用 UTF-8，避免输出非 ASCII 字符时出现 UnicodeEncodeError。
if sys.platform.startswith("win"):
    import io as _io
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    elif hasattr(sys.stdout, "detach"):
        sys.stdout = _io.TextIOWrapper(sys.stdout.detach(), encoding="utf-8", errors="replace")  # type: ignore[union-attr]


# =============================================================================
# 路径常量（如需重命名目录，在此处统一修改）
# =============================================================================

DIR_WORKFLOW = ".trellis"
DIR_SPEC = "spec"
FILE_TASK_JSON = "task.json"

# =============================================================================
# Subagent 常量（如需重命名角色，在此处统一修改）
# =============================================================================

AGENT_IMPLEMENT = "trellis-implement"
AGENT_CHECK = "trellis-check"
AGENT_RESEARCH = "trellis-research"

# 需要任务目录的 agent
AGENTS_REQUIRE_TASK = (AGENT_IMPLEMENT, AGENT_CHECK)
# 当前支持的全部 agent
AGENTS_ALL = (AGENT_IMPLEMENT, AGENT_CHECK, AGENT_RESEARCH)


def find_repo_root(start_path: str) -> str | None:
    """
    从 start_path 向上查找 Git 仓库根目录。

    返回：
        仓库根目录路径；找不到时返回 None。
    """
    current = Path(start_path).resolve()
    while current != current.parent:
        if (current / ".git").exists():
            return str(current)
        current = current.parent
    return None


def _detect_platform(input_data: dict) -> str | None:
    if _hook_event_name(input_data) == "SubagentStart":
        return "codex"
    if isinstance(input_data.get("cursor_version"), str):
        return "cursor"
    # CLAUDE_PROJECT_DIR 是多个 host 共用的兼容别名，必须最后检查，避免
    # 覆盖更具体的厂商变量（与 per-turn hook 保持一致）。
    env_map = {
        "ZCODE_PROJECT_DIR": "zcode",
        "CURSOR_PROJECT_DIR": "cursor",
        "CODEBUDDY_PROJECT_DIR": "codebuddy",
        "FACTORY_PROJECT_DIR": "droid",
        "GEMINI_PROJECT_DIR": "gemini",
        "QODER_PROJECT_DIR": "qoder",
        "KIRO_PROJECT_DIR": "kiro",
        "COPILOT_PROJECT_DIR": "copilot",
        "CLAUDE_PROJECT_DIR": "claude",
    }
    for env_name, platform in env_map.items():
        if os.environ.get(env_name):
            return platform
    script_parts = set(Path(sys.argv[0]).parts)
    if ".claude" in script_parts:
        return "claude"
    if ".cursor" in script_parts:
        return "cursor"
    if ".gemini" in script_parts:
        return "gemini"
    if ".qoder" in script_parts:
        return "qoder"
    if ".codebuddy" in script_parts:
        return "codebuddy"
    if ".factory" in script_parts:
        return "droid"
    if ".kiro" in script_parts:
        return "kiro"
    if ".zcode" in script_parts:
        return "zcode"
    return None


def get_current_task(
    repo_root: str,
    input_data: dict,
    *,
    platform: str | None = None,
    allow_single_session_fallback: bool = True,
    allow_environment_context: bool = True,
    require_existing: bool = False,
) -> str | None:
    """通过统一的活动任务解析器解析当前任务目录。"""
    scripts_dir = Path(repo_root) / DIR_WORKFLOW / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from common.active_task import resolve_active_task  # type: ignore[import-not-found]
    except Exception:
        return None

    active = resolve_active_task(
        Path(repo_root),
        input_data,
        platform=platform or _detect_platform(input_data),
        allow_single_session_fallback=allow_single_session_fallback,
        allow_environment_context=allow_environment_context,
    )
    if require_existing and active.stale:
        return None
    return active.task_path


# =============================================================================
# 上下文注入限制（issue #441）
#
# 本仓库当前只有这一份 Python 实现；如果以后增加其他平台镜像，修改提示文案时
# 必须同步对应镜像，避免不同 host 的上下文行为分叉。
# =============================================================================

DEFAULT_MAX_FILE_BYTES = 32768
DEFAULT_MAX_ARTIFACT_BYTES = 65536
DEFAULT_MAX_TOTAL_BYTES = 131072

DEFAULT_LIMITS: dict[str, int] = {
    "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
    "max_artifact_bytes": DEFAULT_MAX_ARTIFACT_BYTES,
    "max_total_bytes": DEFAULT_MAX_TOTAL_BYTES,
}


def _get_limits(repo_root: str) -> dict[str, int]:
    """从 config.yaml 读取上下文注入字节上限，失败时使用安全默认值。"""
    scripts_dir = Path(repo_root) / DIR_WORKFLOW / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from common.config import get_context_injection_limits  # type: ignore[import-not-found]

        return get_context_injection_limits(Path(repo_root))
    except Exception:
        return dict(DEFAULT_LIMITS)


def truncate_utf8(data: bytes, cap: int) -> bytes:
    """将 ``data`` 截断到最多 ``cap`` 字节，且不拆分 UTF-8 多字节序列。

    ``cap <= 0`` 表示“不限制”，原样返回 ``data``。
    """
    if cap <= 0 or len(data) <= cap:
        return data

    truncated = data[:cap]
    i = len(truncated)
    # 跳过 UTF-8 continuation byte（10xxxxxx），找到起始字节。
    while i > 0 and (truncated[i - 1] & 0xC0) == 0x80:
        i -= 1
    if i == 0:
        return b""

    lead = truncated[i - 1]
    if lead & 0x80:
        if (lead & 0xE0) == 0xC0:
            seq_len = 2
        elif (lead & 0xF0) == 0xE0:
            seq_len = 3
        elif (lead & 0xF8) == 0xF0:
            seq_len = 4
        else:
            seq_len = 1
        # 如果完整序列放不下，连起始字节也丢弃。
        if (i - 1) + seq_len > len(truncated):
            i -= 1

    return truncated[:i]


class _Budget:
    """跟踪写入 sub-agent 上下文的累计字节数。"""

    def __init__(self, max_total_bytes: int) -> None:
        self.max_total_bytes = max_total_bytes
        self.used = 0

    def has_room(self, size: int) -> bool:
        if self.max_total_bytes <= 0:
            return True
        return self.used + size <= self.max_total_bytes

    def add(self, size: int) -> None:
        self.used += size


def _read_file_bytes(base_path: str, file_path: str) -> bytes | None:
    """读取原始文件字节；文件不存在时返回 None。"""
    full_path = os.path.join(base_path, file_path)
    if os.path.exists(full_path) and os.path.isfile(full_path):
        try:
            with open(full_path, "rb") as f:
                return f.read()
        except Exception:
            return None
    return None


def _truncate_notice(path: str, cap: int) -> str:
    return f"\n[Trellis：已截断到 {cap} 字节——请阅读 {path} 获取完整内容]"


def _is_binary_content(data: bytes) -> bool:
    """判断原始字节是否不应解码到模型上下文。"""
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return True
    return False


def _binary_notice(path: str, size: int, reason: str) -> str:
    return (
        f"[Trellis：未内联（二进制文件）——{path}（{size} 字节）：{reason}]"
    )


def _index_notice(path: str, size: int, reason: str) -> str:
    return (
        f"[Trellis：未内联（已达到上下文总上限）——{path}（{size} 字节）：{reason}]"
    )


def _budgeted_block(
    budget: _Budget,
    header: str,
    plain_path: str,
    content: str,
    reason: str,
    size_for_index: int,
) -> str:
    """返回内联的 ``=== header ===`` 块；上下文总预算耗尽时退化为索引提示。"""
    block = f"=== {header} ===\n{content}"
    block_bytes = len(block.encode("utf-8"))
    if not budget.has_room(block_bytes):
        notice = _index_notice(plain_path, size_for_index, reason)
        budget.add(len(notice.encode("utf-8")))
        return notice
    budget.add(block_bytes)
    return block


def _materialize_file(
    base_path: str,
    file_path: str,
    reason: str,
    limits: dict[str, int],
    budget: _Budget,
) -> str | None:
    """读取 JSONL 引用的文件，应用单文件上限并计入预算。"""
    data = _read_file_bytes(base_path, file_path)
    if data is None:
        return None

    size = len(data)
    if _is_binary_content(data):
        notice = _binary_notice(file_path, size, reason)
        budget.add(len(notice.encode("utf-8")))
        return notice

    cap = limits["max_file_bytes"]
    truncated_bytes = truncate_utf8(data, cap)
    content = truncated_bytes.decode("utf-8", errors="replace")
    if len(truncated_bytes) < size:
        content += _truncate_notice(file_path, cap)

    return _budgeted_block(budget, file_path, file_path, content, reason, size)


def _materialize_directory(
    base_path: str,
    dir_path: str,
    reason: str,
    limits: dict[str, int],
    budget: _Budget,
    max_files: int = 20,
) -> list[str]:
    """读取目录中的所有 .md 文件，应用与单文件 JSONL 条目相同的单文件和总量上限。"""
    full_path = os.path.join(base_path, dir_path)
    if not os.path.exists(full_path) or not os.path.isdir(full_path):
        return []

    blocks: list[str] = []
    try:
        md_files = sorted(
            f
            for f in os.listdir(full_path)
            if f.endswith(".md") and os.path.isfile(os.path.join(full_path, f))
        )
        for filename in md_files[:max_files]:
            relative_path = os.path.join(dir_path, filename)
            block = _materialize_file(base_path, relative_path, reason, limits, budget)
            if block:
                blocks.append(block)
    except Exception:
        pass

    return blocks


def read_jsonl_entries(base_path: str, jsonl_path: str) -> list[dict]:
    """
    解析 JSONL 上下文文件引用的所有文件/目录条目。

    Schema:
        {"file": "path/to/file.md", "reason": "..."}
        {"file": "path/to/dir/", "type": "directory", "reason": "..."}
        {"_example": "..."}          # seed 行——跳过（没有 `file` 字段）

    没有 ``file`` 字段的行（例如 agent 整理条目前由 ``task.py create`` 写入的
    自描述 seed 行）会静默跳过。如果最终条目为空，会向 stderr 输出警告，便于
    操作者排查缺失的上下文。

    返回：
        [{"file": path, "type": "file" | "directory", "reason": reason}, ...]
    """
    full_path = os.path.join(base_path, jsonl_path)
    if not os.path.exists(full_path):
        print(
            f"[inject-subagent-context] 警告：找不到 {jsonl_path}——"
            f"sub-agent 只会收到任务产物",
            file=sys.stderr,
        )
        return []

    entries: list[dict] = []
    saw_real_entry = False
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    file_path = item.get("file") or item.get("path")

                    if not file_path:
                        # seed / 注释行：静默跳过。
                        continue

                    saw_real_entry = True
                    entries.append(
                        {
                            "file": file_path,
                            "type": item.get("type", "file"),
                            "reason": item.get("reason") or "-",
                        }
                    )
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass

    if not saw_real_entry:
        print(
            f"[inject-subagent-context] 警告：{jsonl_path} 没有整理后的条目（仅有 seed 或为空）——"
            f"sub-agent 只会收到任务产物。请查阅 workflow.md 的规划产物说明。",
            file=sys.stderr,
        )

    return entries


def _materialize_jsonl_entries(
    base_path: str, jsonl_path: str, limits: dict[str, int], budget: _Budget
) -> list[str]:
    """将 JSONL 上下文文件的每个条目展开为上下文块，并应用单文件和总量上限。"""
    blocks: list[str] = []
    for entry in read_jsonl_entries(base_path, jsonl_path):
        if entry["type"] == "directory":
            blocks.extend(
                _materialize_directory(
                    base_path, entry["file"], entry["reason"], limits, budget
                )
            )
        else:
            block = _materialize_file(
                base_path, entry["file"], entry["reason"], limits, budget
            )
            if block:
                blocks.append(block)
    return blocks


def get_agent_context(
    repo_root: str,
    task_dir: str,
    agent_type: str,
    limits: dict[str, int],
    budget: _Budget,
) -> str:
    """
    获取指定 agent 的 {agent_type}.jsonl 上下文。
    只读取任务系统创建的 implement.jsonl 或 check.jsonl。
    """
    agent_jsonl = f"{task_dir}/{agent_type}.jsonl"
    blocks = _materialize_jsonl_entries(repo_root, agent_jsonl, limits, budget)
    return "\n\n".join(blocks)


def _materialize_artifact(
    base_path: str,
    file_path: str,
    header_label: str,
    reason: str,
    limits: dict[str, int],
    budget: _Budget,
) -> str | None:
    """读取任务产物（prd/design/implement.md），应用单文件上限并计入预算。"""
    data = _read_file_bytes(base_path, file_path)
    if data is None:
        return None

    size = len(data)
    cap = limits["max_artifact_bytes"]
    truncated_bytes = truncate_utf8(data, cap)
    content = truncated_bytes.decode("utf-8", errors="replace")
    if len(truncated_bytes) < size:
        content += _truncate_notice(file_path, cap)

    return _budgeted_block(budget, header_label, file_path, content, reason, size)


def get_implement_context(repo_root: str, task_dir: str) -> str:
    """
    Implement Agent 的完整上下文。

    读取顺序：
    1. implement.jsonl 中的所有文件（spec/research manifest）；
    2. prd.md（需求）；
    3. design.md（如存在，技术设计）；
    4. implement.md（如存在，执行计划）。
    """
    limits = _get_limits(repo_root)
    budget = _Budget(limits["max_total_bytes"])
    context_parts = []

    # 1. 读取 implement.jsonl
    base_context = get_agent_context(repo_root, task_dir, "implement", limits, budget)
    if base_context:
        context_parts.append(base_context)

    # 2. 需求文档
    prd_block = _materialize_artifact(
        repo_root,
        f"{task_dir}/prd.md",
        f"{task_dir}/prd.md（需求）",
        "需求文档",
        limits,
        budget,
    )
    if prd_block:
        context_parts.append(prd_block)

    # 3. 复杂任务的技术设计
    design_block = _materialize_artifact(
        repo_root,
        f"{task_dir}/design.md",
        f"{task_dir}/design.md（技术设计）",
        "技术设计文档",
        limits,
        budget,
    )
    if design_block:
        context_parts.append(design_block)

    # 4. 复杂任务的执行计划
    implement_plan_block = _materialize_artifact(
        repo_root,
        f"{task_dir}/implement.md",
        f"{task_dir}/implement.md（执行计划）",
        "执行计划文档",
        limits,
        budget,
    )
    if implement_plan_block:
        context_parts.append(implement_plan_block)

    return "\n\n".join(context_parts)


def get_check_context(repo_root: str, task_dir: str) -> str:
    """
    Check Agent 的上下文：check.jsonl 加任务产物。
    """
    limits = _get_limits(repo_root)
    budget = _Budget(limits["max_total_bytes"])
    context_parts = []

    base_context = get_agent_context(repo_root, task_dir, "check", limits, budget)
    if base_context:
        context_parts.append(base_context)

    prd_block = _materialize_artifact(
        repo_root,
        f"{task_dir}/prd.md",
        f"{task_dir}/prd.md（需求）",
        "需求文档",
        limits,
        budget,
    )
    if prd_block:
        context_parts.append(prd_block)

    design_block = _materialize_artifact(
        repo_root,
        f"{task_dir}/design.md",
        f"{task_dir}/design.md（技术设计）",
        "技术设计文档",
        limits,
        budget,
    )
    if design_block:
        context_parts.append(design_block)

    implement_plan_block = _materialize_artifact(
        repo_root,
        f"{task_dir}/implement.md",
        f"{task_dir}/implement.md（执行计划）",
        "执行计划文档",
        limits,
        budget,
    )
    if implement_plan_block:
        context_parts.append(implement_plan_block)

    return "\n\n".join(context_parts)


def get_finish_context(repo_root: str, task_dir: str) -> str:
    """
    Finish 阶段的上下文：复用 check.jsonl 和任务产物。
    Finish 是最终检查，使用同一上下文来源。
    """
    return get_check_context(repo_root, task_dir)



def build_implement_prompt(original_prompt: str, context: str) -> str:
    """构建 Implement 的完整 prompt。"""
    return f"""<!-- trellis-hook-injected -->
# Implement Agent 任务

你是 Multi-Agent Pipeline 中的 Implement Agent。

## 上下文

所需信息已准备如下：

{context}

---

## 任务

{original_prompt}

---

## 工作流

1. **理解规范**——理解上方注入的所有开发规范；
2. **理解任务产物**——阅读需求，以及存在时的技术设计和执行计划；
3. **实现功能**——遵循规范和任务产物实现；
4. **自检**——依据 check 规范确认代码质量。

## 重要约束

- 不要执行 git commit，只修改代码；
- 遵循上方注入的全部开发规范；
- 完成后报告修改/创建的文件列表。"""


def build_check_prompt(original_prompt: str, context: str) -> str:
    """构建 Check 的完整 prompt。"""
    return f"""<!-- trellis-hook-injected -->
# Check Agent 任务

你是 Multi-Agent Pipeline 中的 Check Agent（代码和跨层检查器）。

## 上下文

所需的 check 规范和开发规范如下：

{context}

---

## 任务

{original_prompt}

---

## 工作流

1. **获取变更**——运行 `git diff --name-only` 和 `git diff` 查看代码变更；
2. **对照规范**——逐项检查上方规范；
3. **自行修复**——直接修复问题，不只报告；
4. **运行验证**——运行项目的 lint 和 typecheck 命令。

## 重要约束

- 自行修复问题，不只报告；
- 必须执行 check 规范中的完整清单；
- 特别注意影响半径分析（L1-L5）。"""


def build_finish_prompt(original_prompt: str, context: str) -> str:
    """构建 Finish 的完整 prompt（创建 PR 前的最终检查）。"""
    return f"""<!-- trellis-hook-injected -->
# Finish Agent 任务

你正在执行创建 PR 前的最终检查。

## 上下文

Finish 清单和要求如下：

{context}

---

## 任务

{original_prompt}

---

## 工作流

1. **审查变更**——运行 `git diff --name-only` 查看所有变更文件；
2. **核对任务产物**——检查 prd.md；存在时同时检查 design.md / implement.md；
3. **同步规范**——判断变更是否引入新的模式、契约或约定：
   - 发现新模式/约定：先读目标规范，再更新该规范，必要时更新 index.md；
   - 基础设施/跨层变更：遵循 update-spec.md 的 7 节必需模板；
   - 纯代码修复且没有新模式：跳过此步；
4. **运行最终检查**——执行 lint 和 typecheck；
5. **确认就绪**——确认代码可创建 PR。

## 重要约束

- 发现缺口时可以更新规范（以 update-spec.md 为指南）；
- 编辑前必须先阅读目标规范（避免重复内容）；
- 不要因为错别字、格式或显而易见的修复更新规范；
- 发现关键代码问题时要明确报告（修规范，不代替修代码）；
- 核对 prd.md 中的全部验收标准；
- 存在 design.md / implement.md 时核对其中约束。"""



def get_research_context(repo_root: str, task_dir: str | None) -> str:
    """
    返回 Research Agent 的上下文——规范目录的项目结构概览。

    保留 `task_dir` 参数以与 get_implement_context / get_check_context 的签名一致，
    使调度器可以统一调用。
    """
    _ = task_dir
    context_parts = []

    # 1. 项目结构概览（动态发现规范目录）
    spec_path = f"{DIR_WORKFLOW}/{DIR_SPEC}"
    spec_root = Path(repo_root) / DIR_WORKFLOW / DIR_SPEC

    # 动态构建规范目录树
    tree_lines = [f"{spec_path}/"]
    if spec_root.is_dir():
        pkg_dirs = sorted(d for d in spec_root.iterdir() if d.is_dir())
        for i, pkg_dir in enumerate(pkg_dirs):
            is_last = i == len(pkg_dirs) - 1
            prefix = "└── " if is_last else "├── "
            layers = sorted(d.name for d in pkg_dir.iterdir() if d.is_dir())
            layer_info = f" ({', '.join(layers)})" if layers else ""
            tree_lines.append(f"{prefix}{pkg_dir.name}/{layer_info}")

    spec_tree = "\n".join(tree_lines)

    project_structure = f"""## 项目规范目录结构

```
{spec_tree}
```

如需结构化 package 信息，请运行：`python3 ./{DIR_WORKFLOW}/scripts/get_context.py --mode packages`

## 搜索提示

- 规范文件：`{spec_path}/**/*.md`
- 代码搜索：使用 Glob 和 Grep 工具
- 技术资料：使用 mcp__exa__web_search_exa 或 mcp__exa__get_code_context_exa"""

    context_parts.append(project_structure)

    return "\n\n".join(context_parts)


def build_research_prompt(original_prompt: str, context: str) -> str:
    """构建 Research 的完整 prompt。"""
    return f"""# Research Agent 任务（研究代理）

你是 Multi-Agent Pipeline 中的 Research Agent（搜索研究员）。

## 核心原则

**你只做一件事：查找并解释信息。**

你是记录者，不是评审者。

## 项目信息

{context}

---

## 任务

{original_prompt}

---

## 工作流

1. **理解查询**——确定搜索类型（内部/外部）和范围；
2. **规划搜索**——复杂查询列出搜索步骤；
3. **执行搜索**——并行执行多个相互独立的搜索；
4. **整理结果**——输出结构化报告。

## 搜索工具

| 工具 | 用途 |
|------|---------|
| Glob | 按文件名模式搜索 |
| Grep | 按内容搜索 |
| Read | 读取文件内容 |
| mcp__exa__web_search_exa | 外部网页搜索 |
| mcp__exa__get_code_context_exa | 外部代码/文档搜索 |

## 严格边界

**只允许**：描述存在什么、位于何处以及如何工作。

**禁止**（除非用户明确要求）：
- 提出改进建议；
- 批评实现；
- 推荐重构；
- 修改任何文件。

## 报告格式

提供结构化搜索结果，包括：
- 找到的文件列表（含路径）；
- 代码模式分析（如适用）；
- 相关规范文档；
- 外部参考（如有）。"""


def _string_value(value: Any) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped
    return ""


def _text_value(value: Any) -> str:
    """读取文本字段但保留 prompt 的原始空白；非字符串值按空值处理。"""
    return value if isinstance(value, str) else ""


def _hook_event_name(input_data: dict) -> str:
    """从约定的 snake_case/camelCase 字段读取 hook 事件名称。"""
    return _string_value(
        input_data.get("hook_event_name") or input_data.get("hookEventName")
    )


def _codex_subagent_type(input_data: dict) -> str:
    """仅在原生启动事件中读取 Trellis Codex agent 类型。"""
    if _hook_event_name(input_data) != "SubagentStart":
        return ""
    agent_type = _string_value(
        input_data.get("agent_type") or input_data.get("agentType")
    )
    return agent_type if agent_type in AGENTS_ALL else ""


def build_codex_subagent_context(
    subagent_type: str,
    task_dir: str,
    context: str,
) -> str:
    """为已由 Codex 原生 dispatch 的角色构建开发者上下文。"""
    role = subagent_type.removeprefix("trellis-")
    return f"""<!-- trellis-hook-injected -->
# Trellis 原生 {role.title()} Subagent

你是本任务已 dispatch 的 `{subagent_type}` 角色。请直接执行该角色；不要遵循主
session 的 dispatch 或等待指令，也不要再创建 Trellis subagent。

活动任务：{task_dir}

## 已整理上下文

{context}"""


def _handle_codex_subagent_start(input_data: dict) -> None:
    """为识别出的 Trellis 原生 Codex subagent 输出开发者上下文。

    事件会提供父 session id。这里必须禁用通用的单 session 回退：原生启动绝不能在
    父 id 缺失或过期时借用另一个 Codex 窗口的任务。
    """
    subagent_type = _codex_subagent_type(input_data)
    parent_session_id = _string_value(input_data.get("session_id"))
    if not subagent_type or not parent_session_id:
        return

    # 优先使用 payload cwd，再使用当前进程 cwd；某些 host（CodeBuddy IDE 4.10.4）
    # 会为每个 hook 事件报告 "/"。详见 inject-workflow-state.py。
    repo_root = None
    for candidate in (_string_value(input_data.get("cwd")), os.getcwd()):
        if not candidate:
            continue
        repo_root = find_repo_root(candidate)
        if repo_root:
            break
    if not repo_root:
        return

    task_dir = get_current_task(
        repo_root,
        {"session_id": parent_session_id},
        platform="codex",
        allow_single_session_fallback=False,
        allow_environment_context=False,
        require_existing=True,
    )
    if not task_dir:
        return

    if subagent_type in AGENTS_REQUIRE_TASK:
        task_dir_full = Path(repo_root) / task_dir
        if not task_dir_full.is_dir():
            return

    if subagent_type == AGENT_IMPLEMENT:
        context = get_implement_context(repo_root, task_dir)
    elif subagent_type == AGENT_CHECK:
        context = get_check_context(repo_root, task_dir)
    else:
        context = get_research_context(repo_root, task_dir)

    if not context:
        return

    output = {
        "hookSpecificOutput": {
            "hookEventName": "SubagentStart",
            "additionalContext": build_codex_subagent_context(
                subagent_type, task_dir, context
            ),
        }
    }
    print(json.dumps(output, ensure_ascii=False))


def _extract_subagent_name(value: Any) -> str:
    """从常见的平台编码中提取 sub-agent 名称。

    Cursor 原生 Task 参数会把自定义 sub-agent 编码为 protobuf oneof，在 hook JSON
    中可能表现为 ``{"custom": {"name": "..."}}`` 或
    ``{"type": {"case": "custom", "value": {"name": "..."}}}``。
    """
    direct = _string_value(value)
    if direct:
        return direct

    if not isinstance(value, dict):
        return ""

    for key in ("name", "subagent_type_name", "subagentTypeName"):
        direct = _string_value(value.get(key))
        if direct:
            return direct

    custom = value.get("custom")
    if isinstance(custom, dict):
        custom_name = _string_value(custom.get("name"))
        if custom_name:
            return custom_name

    oneof = value.get("type")
    if isinstance(oneof, dict):
        case_name = _string_value(oneof.get("case"))
        if case_name == "custom":
            nested_value = oneof.get("value")
            if isinstance(nested_value, dict):
                custom_name = _string_value(nested_value.get("name"))
                if custom_name:
                    return custom_name
        if case_name:
            return case_name

    case_name = _string_value(value.get("case"))
    if case_name == "custom":
        nested_value = value.get("value")
        if isinstance(nested_value, dict):
            custom_name = _string_value(nested_value.get("name"))
            if custom_name:
                return custom_name
    if case_name:
        return case_name

    for agent_name in AGENTS_ALL:
        if agent_name in value:
            return agent_name

    return ""


def _extract_subagent_type(tool_input: dict) -> str:
    for key in (
        "subagent_type",
        "subagentType",
        "subagent_type_name",
        "subagentTypeName",
        "agent_type",
        "agentType",
        "name",
    ):
        agent_name = _extract_subagent_name(tool_input.get(key))
        if agent_name:
            return agent_name
    return ""


def _parse_hook_input(input_data: dict) -> tuple[str, str, dict]:
    """解析不同平台格式的 hook 输入。

    返回 ``(subagent_type, original_prompt, tool_input)``。
    支持：
    - Claude Code / Qoder / CodeBuddy / Droid：tool_name=Task|Agent，tool_input.subagent_type
    - Cursor：tool_name=Task|Subagent，tool_input.subagent_type
    - Copilot CLI：toolName=task（camelCase 键，小写值）
    - ZCode：toolName=Agent，toolInput/tool_input.subagent_type
    - Gemini CLI：tool_name 就是 agent 名称（BeforeTool matcher 已完成过滤）
    - Kiro：agentSpawn hook，顶层的 agent_name 字段
    """
    tool_input = input_data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = input_data.get("toolInput", {})
    if not isinstance(tool_input, dict):
        tool_input = {}

    # 标准格式：带 subagent_type 的 Task/Agent 工具。
    tool_name = _text_value(input_data.get("tool_name"))
    if not tool_name:
        tool_name = _text_value(input_data.get("toolName"))
    if tool_name.lower() in ("task", "agent", "subagent"):
        return (
            _extract_subagent_type(tool_input),
            _text_value(tool_input.get("prompt")),
            tool_input,
        )

    # Kiro：agentSpawn hook 将 agent_name 放在顶层。
    agent_name = _string_value(input_data.get("agent_name"))
    if agent_name:
        prompt = _text_value(tool_input.get("prompt"))
        if not prompt:
            prompt = _text_value(input_data.get("prompt"))
        return agent_name, prompt, tool_input

    # Gemini CLI：BeforeTool 的 tool_name 就是 agent 名称
    #（matcher 已确认它属于受支持的 agent）。
    if tool_name in AGENTS_ALL:
        return tool_name, _text_value(tool_input.get("prompt")), tool_input

    # Copilot CLI：toolName 字段（camelCase），值可能就是 agent 名称。
    tool_name_camel = _text_value(input_data.get("toolName"))
    if tool_name_camel in AGENTS_ALL:
        return tool_name_camel, _text_value(input_data.get("toolArgs")), tool_input

    return "", "", tool_input


def main():
    if os.environ.get("TRELLIS_HOOKS") == "0" or os.environ.get("TRELLIS_DISABLE_HOOKS") == "1":
        sys.exit(0)

    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)
    if not isinstance(input_data, dict):
        sys.exit(0)

    if _hook_event_name(input_data) == "SubagentStart":
        try:
            _handle_codex_subagent_start(input_data)
        except Exception:
            # 原生上下文 hook 绝不能因为运行时状态不可用或过期而阻止 Codex
            # 启动请求的子 agent。
            pass
        sys.exit(0)

    subagent_type, original_prompt, tool_input = _parse_hook_input(input_data)
    cwd_value = input_data.get("cwd")
    cwd = cwd_value if isinstance(cwd_value, str) and cwd_value else os.getcwd()

    # 只处理受支持的 subagent 类型。
    if subagent_type not in AGENTS_ALL:
        sys.exit(0)

    # 查找仓库根目录。
    repo_root = find_repo_root(cwd)
    if not repo_root:
        sys.exit(0)

    # 获取当前任务目录（research 不要求任务目录）
    task_dir = get_current_task(repo_root, input_data)

    # implement/check 需要任务目录。
    if subagent_type in AGENTS_REQUIRE_TASK:
        if not task_dir:
            sys.exit(0)
        # 确认任务目录存在。
        task_dir_full = os.path.join(repo_root, task_dir)
        if not os.path.exists(task_dir_full):
            sys.exit(0)

    # 检查 prompt 中的 [finish] 标记（带收尾上下文的 check agent）。
    is_finish_phase = "[finish]" in original_prompt.lower()

    # 按 subagent 类型获取上下文并构建 prompt
    if subagent_type == AGENT_IMPLEMENT:
        assert task_dir is not None  # 上方已完成校验。
        context = get_implement_context(repo_root, task_dir)
        new_prompt = build_implement_prompt(original_prompt, context)
    elif subagent_type == AGENT_CHECK:
        assert task_dir is not None  # 上方已完成校验。
        if is_finish_phase:
            # Finish 阶段使用更轻量、聚焦最终验证的上下文。
            context = get_finish_context(repo_root, task_dir)
            new_prompt = build_finish_prompt(original_prompt, context)
        else:
            # 普通检查阶段：使用 check context（完整规范，用于自修复循环）。
            context = get_check_context(repo_root, task_dir)
            new_prompt = build_check_prompt(original_prompt, context)
    elif subagent_type == AGENT_RESEARCH:
        # Research 可以不依赖任务目录。
        context = get_research_context(repo_root, task_dir)
        new_prompt = build_research_prompt(original_prompt, context)
    else:
        sys.exit(0)

    if not context:
        sys.exit(0)

    # 返回更新后的输入。多数平台会忽略未知字段，因此同时提供多种格式。
    # ZCode 更严格；实测确认下面的 Claude 兼容嵌套形状可以到达 sub-agent prompt。
    updated = {**tool_input, "prompt": new_prompt}
    if _detect_platform(input_data) == "zcode":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": updated,
            }
        }
    else:
        output = {
            # Claude Code / Qoder / CodeBuddy / Droid 格式。
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": updated,
            },
            # Cursor 格式。
            "permission": "allow",
            "updated_input": updated,
            # Gemini 格式。
            "updatedInput": updated,
        }

    print(json.dumps(output, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
