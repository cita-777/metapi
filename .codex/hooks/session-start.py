#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex SessionStart Hook：向 Codex session 注入 Trellis 上下文。

输出遵循 Codex hook 协议：
  stdout JSON → { hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: "..." } }
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import warnings
from io import StringIO
from pathlib import Path

# 在 Windows 上强制 stdin/stdout/stderr 使用 UTF-8。默认 codepage 可能是
# cp936 / cp1252 等；stdin 的 host CLI hook payload 和 stdout 的注入块含有中文
# 任务名、PRD 片段时，否则会触发 UnicodeDecodeError / UnicodeEncodeError。
# 这等价于 `python -X utf8`，但按 stream 应用，不依赖 host CLI 的命令接线。
if sys.platform.startswith("win"):
    import io as _io
    for _stream_name in ("stdin", "stdout", "stderr"):
        _stream = getattr(sys, _stream_name, None)
        if _stream is None:
            continue
        if hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
            except Exception:
                pass  # Windows stream 设置失败时保持 hook 启动不中断。
        elif hasattr(_stream, "detach"):
            try:
                setattr(sys, _stream_name, _io.TextIOWrapper(_stream.detach(), encoding="utf-8", errors="replace"))
            except Exception:
                pass  # Windows stream 设置失败时保持 hook 启动不中断。


def _normalize_windows_shell_path(path_str: str) -> str:
    """将 Unix 风格 shell 路径归一化为真实 Windows 路径。

    在 Windows 上，Git Bash / MSYS2 / Cygwin 可能报告 `/d/Users/...` 或
    `/cygdrive/d/Users/...`。`Path.resolve()` 会将其误解为 D 盘上的
    `D:/d/Users...`（或类似路径），导致仓库根目录探测失败。

    本函数有意保持保守，只改写明确表示盘符挂载的模式。
    """
    if not isinstance(path_str, str) or not path_str:
        return path_str

    # 只在 Windows 上生效，其他平台保持原值。
    if not sys.platform.startswith("win"):
        return path_str

    p = path_str.strip()

    # 已经是 Windows 盘符路径（C:\... 或 C:/...）。
    if re.match(r"^[A-Za-z]:[\/]", p):
        return p

    # MSYS/Git-Bash 风格：/c/Users/... 或 /d/Work/...。
    m = re.match(r"^/([A-Za-z])/(.*)", p)
    if m:
        drive, rest = m.group(1).upper(), m.group(2)
        rest = rest.replace('/', '\\')
        return f"{drive}:\\{rest}"

    # Cygwin 风格：/cygdrive/c/Users/...。
    m = re.match(r"^/cygdrive/([A-Za-z])/(.*)", p)
    if m:
        drive, rest = m.group(1).upper(), m.group(2)
        rest = rest.replace('/', '\\')
        return f"{drive}:\\{rest}"

    # WSL 挂载盘（有时会泄漏到环境变量）：/mnt/c/Users/...。
    m = re.match(r"^/mnt/([A-Za-z])/(.*)", p)
    if m:
        drive, rest = m.group(1).upper(), m.group(2)
        rest = rest.replace('/', '\\')
        return f"{drive}:\\{rest}"

    return path_str


warnings.filterwarnings("ignore")

FIRST_REPLY_NOTICE = """<first-reply-notice>
在本 session 第一条对用户可见的 assistant 回复中，简短确认 Trellis SessionStart 上下文已加载。
语言规则：默认使用简体中文；如果用户本轮明确要求其他语言，遵循用户要求。
确认后直接继续处理用户请求，不要让确认语句改变后续回答的语言。
此提示只生效一次：本 session 后续回复不要重复确认。
</first-reply-notice>"""


def should_skip_injection() -> bool:
    if os.environ.get("TRELLIS_HOOKS") == "0":
        return True
    if os.environ.get("TRELLIS_DISABLE_HOOKS") == "1":
        return True
    return os.environ.get("CODEX_NON_INTERACTIVE") == "1"


def configure_project_encoding(project_dir: Path) -> None:
    """在输出 JSON 前复用 Trellis 共享的 Windows stdio 编码辅助函数。"""
    scripts_dir = project_dir / ".trellis" / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    try:
        from common import configure_encoding  # type: ignore[import-not-found]

        configure_encoding()
    except Exception:
        pass  # 编码辅助函数为可选项，host 默认编码仍可用。


def _has_curated_jsonl_entry(jsonl_path: Path) -> bool:
    """判断 JSONL 是否至少包含一行带 ``file`` 字段的真实条目。

    新生成的 JSONL 只有一行 ``{"_example": ...}``（没有 ``file`` 键），这不代表
    “已就绪”。就绪状态至少需要一条整理后的真实条目。这里与
    ``inject-subagent-context.py`` 使用同一契约。
    """
    try:
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("file"):
                return True
    except (OSError, UnicodeDecodeError):
        return False
    return False


def read_file(path: Path, fallback: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return fallback


def _resolve_context_key(project_dir: Path, hook_input: dict) -> str | None:
    scripts_dir = project_dir / ".trellis" / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from common.active_task import resolve_context_key  # type: ignore[import-not-found]
    except Exception:
        return None
    return resolve_context_key(hook_input, platform="codex")


def _resolve_active_task(trellis_dir: Path, hook_input: dict):
    scripts_dir = trellis_dir / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from common.active_task import resolve_active_task  # type: ignore[import-not-found]

    return resolve_active_task(trellis_dir.parent, hook_input, platform="codex")


def run_script(script_path: Path, context_key: str | None = None) -> str:
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        if context_key:
            env["TRELLIS_CONTEXT_ID"] = context_key
        cmd = [sys.executable, "-W", "ignore", str(script_path)]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            cwd=str(script_path.parent.parent.parent),
            env=env,
        )
        return result.stdout if result.returncode == 0 else "暂无可用上下文。"
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return "暂无可用上下文。"


def _normalize_task_ref(task_ref: str) -> str:
    normalized = task_ref.strip()
    if not normalized:
        return ""

    path_obj = Path(normalized)
    if path_obj.is_absolute():
        return str(path_obj)

    normalized = normalized.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]

    if normalized.startswith("tasks/"):
        return f".trellis/{normalized}"

    return normalized


def _resolve_task_dir(trellis_dir: Path, task_ref: str) -> Path:
    normalized = _normalize_task_ref(task_ref)
    path_obj = Path(normalized)
    if path_obj.is_absolute():
        return path_obj
    if normalized.startswith(".trellis/"):
        return trellis_dir.parent / path_obj
    return trellis_dir / "tasks" / path_obj


def _get_task_status(trellis_dir: Path, hook_input: dict) -> str:
    active = _resolve_active_task(trellis_dir, hook_input)
    if not active.task_path:
        return (
            "状态：NO ACTIVE TASK\n"
            "下一步：先判断当前请求类型；创建 Trellis task 前先取得用户同意。"
        )

    task_ref = active.task_path
    task_dir = _resolve_task_dir(trellis_dir, task_ref)
    if active.stale or not task_dir.is_dir():
        return (
            f"状态：STALE POINTER\n任务：{task_ref}\n"
            "下一步：找不到任务目录。请运行：python3 ./.trellis/scripts/task.py finish"
        )

    task_json_path = task_dir / "task.json"
    task_data: dict = {}
    if task_json_path.is_file():
        try:
            task_data = json.loads(task_json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, PermissionError):
            pass  # 可选任务 metadata 读取失败时回退到通用状态。

    task_title = task_data.get("title", task_ref)
    task_status = task_data.get("status", "unknown")

    if task_status == "completed":
        return (
            f"状态：COMPLETED\n任务：{task_title}\n"
            f"下一步：使用 `python3 ./.trellis/scripts/task.py archive {task_dir.name}` 归档，"
            "或开始新任务。"
        )

    has_prd = (task_dir / "prd.md").is_file()
    has_design = (task_dir / "design.md").is_file()
    has_implement = (task_dir / "implement.md").is_file()
    present = [
        name
        for name in ("prd.md", "design.md", "implement.md", "implement.jsonl", "check.jsonl")
        if (task_dir / name).is_file()
    ]
    present_line = ", ".join(present) if present else "无"

    if not has_prd:
        return (
            f"状态：PLANNING\n任务：{task_title}\n已有产物：{present_line}\n"
            "下一步：加载 trellis-brainstorm 并编写 prd.md；保持 planning 状态。"
        )

    if task_status == "planning":
        if has_design and has_implement:
            next_action = "先与用户评审规划产物，再运行 `task.py start`。"
        else:
            next_action = (
                "轻量任务可仅凭 PRD 请求开始评审；复杂任务必须在 `task.py start` 前补充 "
                "design.md 和 implement.md。"
            )
        return (
            f"状态：PLANNING\n任务：{task_title}\n已有产物：{present_line}\n"
            f"下一步：{next_action}"
        )

    return (
        f"状态：{task_status.upper()}\n任务：{task_title}\n已有产物：{present_line}\n"
        "下一步：遵循匹配的每轮 workflow-state。上下文顺序为 JSONL 条目、prd.md、"
        "（如有）design.md、（如有）implement.md。"
    )


def _run_git(repo_root: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            cwd=str(repo_root),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _format_git_state(repo_root: Path) -> str:
    branch = _run_git(repo_root, ["branch", "--show-current"]) or "(detached)"
    dirty_lines = [
        line for line in _run_git(repo_root, ["status", "--porcelain"]).splitlines()
        if line.strip()
    ]
    dirty_text = "工作目录干净" if not dirty_lines else f"有 {len(dirty_lines)} 个未提交路径"
    return f"Git：分支 {branch}；{dirty_text}。"


def _repo_relative(repo_root: Path, path: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


def _collect_spec_index_paths(trellis_dir: Path) -> list[str]:
    paths: list[str] = []
    guides_index = trellis_dir / "spec" / "guides" / "index.md"
    if guides_index.is_file():
        paths.append(".trellis/spec/guides/index.md")

    spec_dir = trellis_dir / "spec"
    if not spec_dir.is_dir():
        return paths

    for sub in sorted(spec_dir.iterdir()):
        if not sub.is_dir() or sub.name.startswith(".") or sub.name == "guides":
            continue
        index_file = sub / "index.md"
        if index_file.is_file():
            paths.append(f".trellis/spec/{sub.name}/index.md")
            continue
        for nested in sorted(sub.iterdir()):
            if not nested.is_dir():
                continue
            nested_index = nested / "index.md"
            if nested_index.is_file():
                paths.append(f".trellis/spec/{sub.name}/{nested.name}/index.md")

    return paths


def _build_compact_current_state(
    trellis_dir: Path,
    hook_input: dict,
    spec_index_paths: list[str],
) -> str:
    repo_root = trellis_dir.parent
    lines: list[str] = []

    try:
        from common.paths import get_active_journal_file, get_developer, get_tasks_dir, count_lines  # type: ignore[import-not-found]
        from common.tasks import iter_active_tasks  # type: ignore[import-not-found]
    except Exception:
        get_active_journal_file = None  # type: ignore[assignment]
        get_developer = None  # type: ignore[assignment]
        get_tasks_dir = None  # type: ignore[assignment]
        count_lines = None  # type: ignore[assignment]
        iter_active_tasks = None  # type: ignore[assignment]

    developer = get_developer(repo_root) if get_developer else None
    lines.append(f"开发者：{developer or '（未初始化）'}")
    lines.append(_format_git_state(repo_root))

    active = _resolve_active_task(trellis_dir, hook_input)
    if active.task_path:
        task_dir = _resolve_task_dir(trellis_dir, active.task_path)
        status = "unknown"
        task_json = task_dir / "task.json"
        if task_json.is_file():
            try:
                data = json.loads(task_json.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    status = str(data.get("status") or "unknown")
            except (json.JSONDecodeError, OSError):
                pass  # 可选任务 metadata 读取失败时回退到通用状态。
        lines.append(f"当前任务：{_repo_relative(repo_root, task_dir)}；status={status}。")
    else:
        lines.append("当前任务：无。")

    if get_tasks_dir and iter_active_tasks:
        try:
            task_count = sum(1 for _ in iter_active_tasks(get_tasks_dir(repo_root)))
            lines.append(
                f"活动任务：共 {task_count} 个；如有需要再运行 `python3 ./.trellis/scripts/task.py list --mine`。"
            )
        except Exception:
            pass  # 可选任务汇总失败时仍保留精简状态。

    if get_active_journal_file and count_lines:
        journal = get_active_journal_file(repo_root)
        if journal:
            lines.append(
                f"日志：{_repo_relative(repo_root, journal)}，{count_lines(journal)} / 2000 行。"
            )

    if spec_index_paths:
        lines.append(f"规范索引：有 {len(spec_index_paths)} 个可用。")

    return "\n".join(lines)


def _extract_range(content: str, start_header: str, end_header: str) -> str:
    """提取从 `## start_header` 开始、到（不含）`## end_header` 的行。"""
    lines = content.splitlines()
    start: "int | None" = None
    end: int = len(lines)
    start_match = f"## {start_header}"
    end_match = f"## {end_header}"
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start is None and stripped == start_match:
            start = i
            continue
        if start is not None and stripped == end_match:
            end = i
            break
    if start is None:
        return ""
    return "\n".join(lines[start:end]).rstrip()


_BREADCRUMB_TAG_RE = re.compile(
    r"\[workflow-state:([A-Za-z0-9_-]+)\]\s*\n.*?\n\s*\[/workflow-state:\1\]",
    re.DOTALL,
)


def _strip_breadcrumb_tag_blocks(content: str) -> str:
    stripped = _BREADCRUMB_TAG_RE.sub("", content)
    stripped = re.sub(r"<!--.*?-->", "", stripped, flags=re.DOTALL)
    stripped = re.sub(r"^\[(?!/?workflow-state:)/?[^\]\n]+\]\s*\n?", "", stripped, flags=re.MULTILINE)
    return re.sub(r"\n{3,}", "\n\n", stripped).strip()


def _build_workflow_toc(workflow_path: Path) -> str:
    """只为 SessionStart 注入精简的 Phase Index 摘要。"""
    content = read_file(workflow_path)
    if not content:
        return "找不到 workflow.md。"

    out_lines = [
        "# 开发工作流——Session 摘要",
        "完整指南：.trellis/workflow.md；步骤详情：`python3 ./.trellis/scripts/get_context.py --mode phase --step <X.Y>`。",
        "",
    ]

    phases = _extract_range(content, "Phase Index", "Phase 1: Plan")
    if phases:
        out_lines.append(_strip_breadcrumb_tag_blocks(phases).rstrip())

    return "\n".join(out_lines).rstrip()


def main() -> None:
    if should_skip_injection():
        sys.exit(0)

    # 从 stdin 读取 hook 输入
    try:
        hook_input = json.loads(sys.stdin.read())
        if not isinstance(hook_input, dict):
            hook_input = {}
        project_dir = Path(_normalize_windows_shell_path(hook_input.get("cwd", "."))).resolve()
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        hook_input = {}
        project_dir = Path(".").resolve()

    configure_project_encoding(project_dir)

    trellis_dir = project_dir / ".trellis"
    # SessionStart 可能在未初始化 Trellis 的工作目录中触发；此时静默退出，避免
    # 后续导入项目内 common.active_task 失败并阻断宿主 session。
    if not trellis_dir.is_dir():
        return
    spec_index_paths = _collect_spec_index_paths(trellis_dir)

    output = StringIO()

    output.write("""<session-context>
Trellis 的精简 SessionStart 上下文。用于定位当前 session；需要时再加载详细内容。
</session-context>

""")
    output.write(FIRST_REPLY_NOTICE)
    output.write("\n\n")

    output.write("<current-state>\n")
    output.write(_build_compact_current_state(trellis_dir, hook_input, spec_index_paths))
    output.write("\n</current-state>\n\n")

    output.write("<trellis-workflow>\n")
    output.write(_build_workflow_toc(trellis_dir / "workflow.md"))
    output.write("\n</trellis-workflow>\n\n")

    output.write("<guidelines>\n")
    output.write(
        "实现/检查的任务上下文顺序：JSONL 条目 -> `prd.md` -> "
        "（如有）`design.md` ->（如有）`implement.md`。轻量任务会跳过缺失的可选产物。\n\n"
    )

    if spec_index_paths:
        output.write("## 可用规范索引（按需阅读）\n")
        for p in spec_index_paths:
            output.write(f"- {p}\n")
        output.write("\n")

    output.write(
        "如需更多信息，请运行："
        "`python3 ./.trellis/scripts/get_context.py --mode packages`\n"
    )
    output.write("</guidelines>\n\n")

    task_status = _get_task_status(trellis_dir, hook_input)
    output.write(f"<task-status>\n{task_status}\n</task-status>\n\n")

    output.write("""<ready>
上下文已加载。请遵循 <task-status>；仅在需要时加载 workflow/spec/task 详情。
</ready>""")

    context = output.getvalue()
    result = {
        "suppressOutput": True,
        "systemMessage": f"已注入 Trellis 上下文（{len(context)} 个字符）",
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        },
    }

    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
