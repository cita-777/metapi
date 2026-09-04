#!/usr/bin/env python3
"""
生成 session 上下文（default + record 模式）。

提供：
    get_context_json          - default 模式的 JSON 输出
    get_context_text          - default 模式的文本输出
    get_context_record_json   - record 模式的 JSON 输出
    get_context_text_record   - record 模式的文本输出
    output_json               - 输出 JSON
    output_text               - 输出文本
    get_update_hint           - 每个 session 最多显示一次的更新提示
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .active_task import resolve_context_key
from .config import get_git_packages
from .git import run_git
from .packages_context import get_packages_section
from .tasks import iter_active_tasks, load_task, get_all_statuses, children_progress
from .paths import (
    DIR_SCRIPTS,
    DIR_SPEC,
    DIR_TASKS,
    DIR_WORKFLOW,
    DIR_WORKSPACE,
    count_lines,
    get_active_journal_file,
    get_current_task,
    get_current_task_source,
    get_developer,
    get_repo_root,
    get_tasks_dir,
)


# =============================================================================
# 辅助函数
# =============================================================================

_PACKAGE_NAME = "@mindfoldhq/trellis"
_UPDATE_CHECK_TIMEOUT_SECONDS = 1.0
_VERSION_RE = re.compile(
    r"^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?\s*$"
)
_VERSION_TOKEN_RE = re.compile(r"\b\d+(?:\.\d+){1,2}(?:-[0-9A-Za-z.-]+)?\b")
_POLYREPO_IGNORED_DIRS = {
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "bin",
    "obj",
    "vendor",
    "coverage",
    "tmp",
    "__pycache__",
}
_POLYREPO_SCAN_MAX_DEPTH = 2
_POLYREPO_SCAN_MAX_REPOS = 8
_GIT_PROBE_TIMEOUT_SECONDS = 2.0


def _is_git_worktree(path: Path) -> bool:
    """判断路径是否位于 Git worktree 内。"""
    rc, out, _ = run_git(
        ["rev-parse", "--is-inside-work-tree"],
        cwd=path,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )
    return rc == 0 and out.strip().lower() == "true"


def _parse_recent_commits(log_output: str) -> list[dict]:
    """将 `git log --oneline` 输出解析为结构化提交条目。"""
    commits = []
    for line in log_output.splitlines():
        if not line.strip():
            continue
        parts = line.split(" ", 1)
        if len(parts) >= 2:
            commits.append({"hash": parts[0], "message": parts[1]})
        elif len(parts) == 1:
            commits.append({"hash": parts[0], "message": ""})
    return commits


def _collect_git_repo_info(name: str, rel_path: str, repo_dir: Path) -> dict | None:
    """收集一个已知仓库目录的 Git 状态。"""
    if not (repo_dir / ".git").exists():
        return None

    status_rc, status_out, _ = run_git(
        ["status", "--porcelain"],
        cwd=repo_dir,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )
    if status_rc != 0:
        return None
    changes = len([line for line in status_out.splitlines() if line.strip()])

    _, branch_out, _ = run_git(
        ["branch", "--show-current"],
        cwd=repo_dir,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )
    branch = branch_out.strip() or "unknown"

    _, log_out, _ = run_git(
        ["log", "--oneline", "-5"],
        cwd=repo_dir,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )

    return {
        "name": name,
        "path": rel_path,
        "branch": branch,
        "isClean": changes == 0,
        "uncommittedChanges": changes,
        "recentCommits": _parse_recent_commits(log_out),
    }


def _collect_root_git_info(repo_root: Path) -> dict:
    """收集根目录 Git 信息；根目录不是 Git 仓库时不得伪装成干净状态。"""
    if not _is_git_worktree(repo_root):
        return {
            "isRepo": False,
            "branch": "",
            "isClean": False,
            "uncommittedChanges": 0,
            "recentCommits": [],
        }

    _, branch_out, _ = run_git(
        ["branch", "--show-current"],
        cwd=repo_root,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )
    branch = branch_out.strip() or "unknown"

    status_rc, status_out, _ = run_git(
        ["status", "--porcelain"],
        cwd=repo_root,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )
    status_lines = [line for line in status_out.splitlines() if line.strip()]

    _, short_out, _ = run_git(
        ["status", "--short"],
        cwd=repo_root,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )

    _, log_out, _ = run_git(
        ["log", "--oneline", "-5"],
        cwd=repo_root,
        timeout=_GIT_PROBE_TIMEOUT_SECONDS,
    )

    return {
        "isRepo": True,
        "branch": branch,
        "isClean": status_rc == 0 and len(status_lines) == 0,
        "uncommittedChanges": len(status_lines),
        "statusShort": short_out.splitlines(),
        "recentCommits": _parse_recent_commits(log_out),
    }


def _discover_child_git_repos(repo_root: Path) -> list[tuple[str, str]]:
    """使用初始化时的 polyrepo 启发式发现子 Git 仓库。"""
    found: list[str] = []
    overflow = False

    def is_candidate_dir(path: Path) -> bool:
        name = path.name
        return not name.startswith(".") and name not in _POLYREPO_IGNORED_DIRS

    def scan(rel_dir: Path, depth: int) -> None:
        nonlocal overflow
        if overflow:
            return
        if depth >= _POLYREPO_SCAN_MAX_DEPTH:
            return
        abs_dir = repo_root / rel_dir
        try:
            children = sorted(abs_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            return

        for child in children:
            if not child.is_dir() or not is_candidate_dir(child):
                continue

            child_rel = (
                rel_dir / child.name if rel_dir != Path(".") else Path(child.name)
            )
            if (child / ".git").exists():
                if len(found) >= _POLYREPO_SCAN_MAX_REPOS:
                    overflow = True
                    return
                found.append(child_rel.as_posix())
                continue
            scan(child_rel, depth + 1)

    scan(Path("."), 0)
    if overflow:
        print(
            "警告：发现超过 "
            f"{_POLYREPO_SCAN_MAX_REPOS} 个子 Git 仓库；"
            "已跳过自动 Git 状态收集。请在 .trellis/config.yaml 中配置带 path 和 git: true 的 packages 条目。",
            file=sys.stderr,
        )
        return []
    if len(found) < 2:
        return []
    return [(path.replace("/", "_"), path) for path in sorted(found)]


def _collect_package_git_info(
    repo_root: Path,
    discover_unconfigured: bool = False,
) -> list[dict]:
    """收集独立 package 仓库的 Git 状态。

    config.yaml 中标记为 ``git: true`` 的 package 是权威配置。
    如果 Trellis 根目录不是 Git 仓库且没有可用的已配置 package 仓库，
    可选地回退到有边界的 polyrepo 子仓库扫描。

    返回：
        字典列表，字段包括 name、path、branch、isClean、
        uncommittedChanges 和 recentCommits。
        未配置 Git 仓库型 package 时返回空列表。
    """
    git_pkgs = get_git_packages(repo_root)
    result = []
    for pkg_name, pkg_path in git_pkgs.items():
        pkg_dir = repo_root / pkg_path
        info = _collect_git_repo_info(pkg_name, pkg_path, pkg_dir)
        if info is not None:
            result.append(info)

    if result or not discover_unconfigured:
        return result

    discovered = []
    for pkg_name, pkg_path in _discover_child_git_repos(repo_root):
        info = _collect_git_repo_info(pkg_name, pkg_path, repo_root / pkg_path)
        if info is not None:
            discovered.append(info)
    return discovered


def _append_root_git_context(lines: list[str], root_git_info: dict) -> None:
    """追加根目录 Git 状态，避免把非 Git 根目录误报为 clean。"""
    lines.append("## Git 状态（GIT STATUS）")
    if not root_git_info["isRepo"]:
        lines.append("根目录不是 Git 仓库。")
        lines.append("请在下方列出的 package 仓库路径中运行 Git 命令。")
    else:
        lines.append(f"分支：{root_git_info['branch']}")
        if root_git_info["isClean"]:
            lines.append("工作目录：干净")
        else:
            lines.append(
                f"工作目录：{root_git_info['uncommittedChanges']} 个未提交变更"
            )
            lines.append("")
            lines.append("变更：")
            for line in root_git_info.get("statusShort", [])[:10]:
                lines.append(line)
    lines.append("")

    lines.append("## 最近提交（RECENT COMMITS）")
    if not root_git_info["isRepo"]:
        lines.append(
            "根目录不是 Git 仓库，因此没有 Git 提交历史。"
        )
    elif root_git_info["recentCommits"]:
        for commit in root_git_info["recentCommits"]:
            lines.append(f"{commit['hash']} {commit['message']}")
    else:
        lines.append("（没有提交）")
    lines.append("")


def _append_package_git_context(lines: list[str], package_git_info: list[dict]) -> None:
    """追加 package 仓库的 Git 状态和最近提交。"""
    for pkg in package_git_info:
        lines.append(f"## Git 状态（GIT STATUS：{pkg['name']}：{pkg['path']}）")
        lines.append(f"分支：{pkg['branch']}")
        if pkg["isClean"]:
            lines.append("工作目录：干净")
        else:
            lines.append(
                f"工作目录：{pkg['uncommittedChanges']} 个未提交变更"
            )
        lines.append("")
        lines.append(f"## 最近提交（RECENT COMMITS：{pkg['name']}：{pkg['path']}）")
        if pkg["recentCommits"]:
            for commit in pkg["recentCommits"]:
                lines.append(f"{commit['hash']} {commit['message']}")
        else:
            lines.append("（没有提交）")
        lines.append("")


def _read_project_version(repo_root: Path) -> str | None:
    try:
        version = (repo_root / DIR_WORKFLOW / ".version").read_text(
            encoding="utf-8"
        ).strip()
    except OSError:
        return None
    return version or None


def _fetch_trellis_version_output() -> str | None:
    try:
        result = subprocess.run(
            ["trellis", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_UPDATE_CHECK_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError, TimeoutError):
        return None

    if result.returncode != 0:
        return None
    output = f"{result.stdout}\n{result.stderr}".strip()
    return output or None


def _extract_available_update_version(output: str) -> str | None:
    update_match = re.search(
        r"Trellis update available:\s*"
        r"(?P<current>\S+)\s*(?:→|->)\s*(?P<latest>\S+)",
        output,
    )
    if update_match:
        return update_match.group("latest").strip()
    candidates = _VERSION_TOKEN_RE.findall(output)
    return candidates[-1] if candidates else None


def _resolve_available_update_version() -> str | None:
    output = _fetch_trellis_version_output()
    if not output:
        return None
    return _extract_available_update_version(output)


def _parse_version(version: str) -> tuple[tuple[int, int, int], tuple[str, ...] | None] | None:
    match = _VERSION_RE.match(version)
    if not match:
        return None
    major, minor, patch, prerelease = match.groups()
    numbers = (int(major), int(minor or "0"), int(patch or "0"))
    prerelease_parts = tuple(prerelease.split(".")) if prerelease else None
    return numbers, prerelease_parts


def _compare_prerelease(
    left: tuple[str, ...] | None,
    right: tuple[str, ...] | None,
) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        return 1
    if right is None:
        return -1

    for left_part, right_part in zip(left, right):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            left_int = int(left_part)
            right_int = int(right_part)
            return (left_int > right_int) - (left_int < right_int)
        if left_numeric:
            return -1
        if right_numeric:
            return 1
        return (left_part > right_part) - (left_part < right_part)

    return (len(left) > len(right)) - (len(left) < len(right))


def _compare_versions(left: str, right: str) -> int | None:
    parsed_left = _parse_version(left)
    parsed_right = _parse_version(right)
    if parsed_left is None or parsed_right is None:
        return None

    left_numbers, left_prerelease = parsed_left
    right_numbers, right_prerelease = parsed_right
    if left_numbers != right_numbers:
        return (left_numbers > right_numbers) - (left_numbers < right_numbers)
    return _compare_prerelease(left_prerelease, right_prerelease)


def _update_marker_path(repo_root: Path, context_key: str | None = None) -> Path:
    """返回用于限制每个 session 只检查一次更新的 marker 路径。

    已解析 session identity 的调用方可以传入 `context_key`；SessionStart hook
    从 stdin 的 hook 输入读取 session id，比本函数仅依赖环境变量的回退链更可靠。
    shell 入口传入 None，保持既有行为。
    """
    if not context_key:
        context_key = resolve_context_key()
    if not context_key:
        terminal_key = os.environ.get("TERM_SESSION_ID", "").strip()
        context_key = terminal_key or f"ppid-{os.getppid()}"
    safe_key = re.sub(r"[^A-Za-z0-9._-]+", "_", context_key).strip("._-")
    if not safe_key:
        safe_key = "session"
    return (
        repo_root
        / DIR_WORKFLOW
        / ".runtime"
        / f"update-check-{safe_key[:160]}.marker"
    )


def _mark_update_check_attempted(
    repo_root: Path,
    context_key: str | None = None,
) -> bool:
    marker_path = _update_marker_path(repo_root, context_key)
    if marker_path.exists():
        return False
    try:
        marker_path.parent.mkdir(parents=True, exist_ok=True)
        marker_path.write_text("checked\n", encoding="utf-8")
    except OSError:
        pass
    return True


def get_update_hint(repo_root: Path, context_key: str | None = None) -> str | None:
    """返回本 session 最多一次的“有可用更新”提示。

    该函数需要公开，因为 SessionStart hook 会导入它。过去只有文本 CLI 路径
    (`get_context.py`) 调用，因此由 hook 驱动的平台（包括 Claude Code）看不到提醒。
    """
    marker_path = _update_marker_path(repo_root, context_key)
    if marker_path.exists():
        return None

    current_version = _read_project_version(repo_root)
    if not current_version:
        return None

    latest_version = _resolve_available_update_version()
    if not latest_version:
        return None

    _mark_update_check_attempted(repo_root, context_key)
    comparison = _compare_versions(current_version, latest_version)
    if comparison is None or comparison >= 0:
        return None

    return (
        f"Trellis 有可用更新：{current_version} -> {latest_version}，请运行 trellis update"
    )


# =============================================================================
# JSON 输出
# =============================================================================

def get_context_json(repo_root: Path | None = None) -> dict:
    """以字典形式获取上下文。

    参数：
        repo_root：仓库根目录；省略时自动探测。

    返回：
        上下文字典。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    developer = get_developer(repo_root)
    tasks_dir = get_tasks_dir(repo_root)
    journal_file = get_active_journal_file(repo_root)

    journal_lines = 0
    journal_relative = ""
    if journal_file and developer:
        journal_lines = count_lines(journal_file)
        journal_relative = (
            f"{DIR_WORKFLOW}/{DIR_WORKSPACE}/{developer}/{journal_file.name}"
        )

    root_git_info = _collect_root_git_info(repo_root)

    # 任务。
    tasks = [
        {
            "dir": t.dir_name,
            "name": t.name,
            "status": t.status,
            "children": list(t.children),
            "parent": t.parent,
        }
        for t in iter_active_tasks(tasks_dir)
    ]

    # package Git 仓库（独立子仓库）。
    pkg_git_info = _collect_package_git_info(
        repo_root,
        discover_unconfigured=not root_git_info["isRepo"],
    )

    result = {
        "developer": developer or "",
        "git": {
            "isRepo": root_git_info["isRepo"],
            "branch": root_git_info["branch"],
            "isClean": root_git_info["isClean"],
            "uncommittedChanges": root_git_info["uncommittedChanges"],
            "recentCommits": root_git_info["recentCommits"],
        },
        "tasks": {
            "active": tasks,
            "directory": f"{DIR_WORKFLOW}/{DIR_TASKS}",
        },
        "journal": {
            "file": journal_relative,
            "lines": journal_lines,
            "nearLimit": journal_lines > 1800,
        },
    }

    if pkg_git_info:
        result["packageGit"] = pkg_git_info

    return result


def output_json(repo_root: Path | None = None) -> None:
    """以 JSON 格式输出上下文。

    参数：
        repo_root：仓库根目录；省略时自动探测。
    """
    context = get_context_json(repo_root)
    print(json.dumps(context, indent=2, ensure_ascii=False))


# =============================================================================
# 文本输出
# =============================================================================

def get_context_text(repo_root: Path | None = None) -> str:
    """获取格式化的文本上下文。

    参数：
        repo_root：仓库根目录；省略时自动探测。

    返回：
        格式化后的文本上下文。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    lines = []
    lines.append("========================================")
    lines.append("会话上下文（SESSION CONTEXT）")
    lines.append("========================================")
    lines.append("")

    developer = get_developer(repo_root)

    # 开发者部分。
    lines.append("## 开发者（DEVELOPER）")
    if not developer:
        lines.append(
            f"错误：尚未初始化。请运行：python3 ./{DIR_WORKFLOW}/{DIR_SCRIPTS}/init_developer.py <name>"
        )
        return "\n".join(lines)

    lines.append(f"名称：{developer}")
    lines.append("")

    root_git_info = _collect_root_git_info(repo_root)
    _append_root_git_context(lines, root_git_info)

    # package Git 仓库（独立子仓库）。
    _append_package_git_context(
        lines,
        _collect_package_git_info(
            repo_root,
            discover_unconfigured=not root_git_info["isRepo"],
        ),
    )

    # 当前任务。
    lines.append("## 当前任务（CURRENT TASK）")
    current_task = get_current_task(repo_root)
    if current_task:
        current_task_dir = repo_root / current_task
        source_type, context_key, _ = get_current_task_source(repo_root)
        lines.append(f"路径：{current_task}")
        lines.append(
            f"来源：{source_type}" + (f":{context_key}" if context_key else "")
        )

        ct = load_task(current_task_dir)
        if ct:
            lines.append(f"名称：{ct.name}")
            lines.append(f"状态：{ct.status}")
            lines.append(f"创建时间：{ct.raw.get('createdAt', '未知')}")
            if ct.description:
                lines.append(f"描述：{ct.description}")

        # 检查 prd.md。
        prd_file = current_task_dir / "prd.md"
        if prd_file.is_file():
            lines.append("")
            lines.append("[!] 此任务包含 prd.md，请阅读以了解任务详情。")
    else:
        lines.append("（无）")
    lines.append("")

    # 活动任务。
    lines.append("## 活动任务（ACTIVE TASKS）")
    tasks_dir = get_tasks_dir(repo_root)
    task_count = 0

    # 收集任务树所需的全部数据。
    all_tasks = {t.dir_name: t for t in iter_active_tasks(tasks_dir)}
    all_statuses = {name: t.status for name, t in all_tasks.items()}

    def _print_task_tree(name: str, indent: int = 0) -> None:
        nonlocal task_count
        t = all_tasks[name]
        progress = children_progress(t.children, all_statuses)
        prefix = "  " * indent
        lines.append(f"{prefix}- {name}/ ({t.status}){progress} @{t.assignee or '-'}")
        task_count += 1
        for child in t.children:
            if child in all_tasks:
                _print_task_tree(child, indent + 1)

    for dir_name in sorted(all_tasks.keys()):
        if not all_tasks[dir_name].parent:
            _print_task_tree(dir_name)

    if task_count == 0:
        lines.append("（没有活动任务）")
    lines.append(f"总计：{task_count} 个活动任务")
    lines.append("")

    # 我的任务。
    lines.append("## 我的任务（MY TASKS，分配给我）")
    my_task_count = 0

    for t in all_tasks.values():
        if t.assignee == developer and t.status != "done":
            progress = children_progress(t.children, all_statuses)
            lines.append(f"- [{t.priority}] {t.title} ({t.status}){progress}")
            my_task_count += 1

    if my_task_count == 0:
        lines.append("（没有分配给你的任务）")
    lines.append("")

    # 日志文件。
    lines.append("## 日志文件（JOURNAL FILE）")
    journal_file = get_active_journal_file(repo_root)
    if journal_file:
        journal_lines = count_lines(journal_file)
        relative = f"{DIR_WORKFLOW}/{DIR_WORKSPACE}/{developer}/{journal_file.name}"
        lines.append(f"活动文件：{relative}")
        lines.append(f"行数：{journal_lines} / 2000")
        if journal_lines > 1800:
            lines.append("[!] 警告：接近 2000 行上限！")
    else:
        lines.append("找不到日志文件。")
    lines.append("")

    # package 信息。
    packages_text = get_packages_section(repo_root)
    if packages_text:
        lines.append(packages_text)
        lines.append("")

    # 路径。
    lines.append("## 路径（PATHS）")
    lines.append(f"workspace：{DIR_WORKFLOW}/{DIR_WORKSPACE}/{developer}/")
    lines.append(f"任务：{DIR_WORKFLOW}/{DIR_TASKS}/")
    lines.append(f"规范：{DIR_WORKFLOW}/{DIR_SPEC}/")
    lines.append("")

    lines.append("========================================")

    return "\n".join(lines)


# =============================================================================
# record 模式
# =============================================================================

def get_context_record_json(repo_root: Path | None = None) -> dict:
    """以字典形式获取 record 模式上下文。

    重点显示：我的活动任务、Git 状态和当前任务。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    developer = get_developer(repo_root)
    tasks_dir = get_tasks_dir(repo_root)

    root_git_info = _collect_root_git_info(repo_root)

    # 我的任务（单次遍历，收集 status 并按 assignee 过滤）。
    all_tasks_list = list(iter_active_tasks(tasks_dir))
    all_statuses = {t.dir_name: t.status for t in all_tasks_list}

    my_tasks = []
    for t in all_tasks_list:
        if t.assignee == developer:
            done = sum(
                1 for c in t.children
                if all_statuses.get(c) in ("completed", "done")
            )
            my_tasks.append({
                "dir": t.dir_name,
                "title": t.title,
                "status": t.status,
                "priority": t.priority,
                "children": list(t.children),
                "childrenDone": done,
                "parent": t.parent,
                "meta": t.meta,
            })

    # 当前任务。
    current_task_info = None
    current_task = get_current_task(repo_root)
    if current_task:
        source_type, context_key, _ = get_current_task_source(repo_root)
        ct = load_task(repo_root / current_task)
        if ct:
            current_task_info = {
                "path": current_task,
                "name": ct.name,
                "status": ct.status,
                "source": source_type,
                "contextKey": context_key,
            }

    # package Git 仓库。
    pkg_git_info = _collect_package_git_info(
        repo_root,
        discover_unconfigured=not root_git_info["isRepo"],
    )

    result = {
        "developer": developer or "",
        "git": {
            "isRepo": root_git_info["isRepo"],
            "branch": root_git_info["branch"],
            "isClean": root_git_info["isClean"],
            "uncommittedChanges": root_git_info["uncommittedChanges"],
            "recentCommits": root_git_info["recentCommits"],
        },
        "myTasks": my_tasks,
        "currentTask": current_task_info,
    }

    if pkg_git_info:
        result["packageGit"] = pkg_git_info

    return result


def get_context_text_record(repo_root: Path | None = None) -> str:
    """获取 record-session 模式的格式化文本上下文。

    输出重点：先显示带 [!!!] 强调的我的活动任务，再显示 Git 状态、最近提交和当前任务。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    lines: list[str] = []
    lines.append("========================================")
    lines.append("会话上下文（SESSION CONTEXT，RECORD MODE）")
    lines.append("========================================")
    lines.append("")

    developer = get_developer(repo_root)
    if not developer:
        lines.append(
            f"错误：尚未初始化。请运行：python3 ./{DIR_WORKFLOW}/{DIR_SCRIPTS}/init_developer.py <name>"
        )
        return "\n".join(lines)

    # 我的活动任务：优先且醒目地显示。
    lines.append(f"## [!!!] 我的活动任务（MY ACTIVE TASKS，分配给 {developer}）")
    lines.append("[!] 记录本 session 前，请检查是否有任务应当归档。")
    lines.append("")

    tasks_dir = get_tasks_dir(repo_root)
    my_task_count = 0

    # 单次遍历：收集所有任务并按 assignee 过滤。
    all_statuses = get_all_statuses(tasks_dir)

    for t in iter_active_tasks(tasks_dir):
        if t.assignee == developer:
            progress = children_progress(t.children, all_statuses)
            lines.append(f"- [{t.priority}] {t.title} ({t.status}){progress} — {t.dir_name}")
            my_task_count += 1

    if my_task_count == 0:
        lines.append("（没有分配给你的活动任务）")
    lines.append("")

    root_git_info = _collect_root_git_info(repo_root)
    _append_root_git_context(lines, root_git_info)

    # package Git 仓库（独立子仓库）。
    _append_package_git_context(
        lines,
        _collect_package_git_info(
            repo_root,
            discover_unconfigured=not root_git_info["isRepo"],
        ),
    )

    # 当前任务。
    lines.append("## 当前任务（CURRENT TASK）")
    current_task = get_current_task(repo_root)
    if current_task:
        source_type, context_key, _ = get_current_task_source(repo_root)
        lines.append(f"路径：{current_task}")
        lines.append(
            f"来源：{source_type}" + (f":{context_key}" if context_key else "")
        )
        ct = load_task(repo_root / current_task)
        if ct:
            lines.append(f"名称：{ct.name}")
            lines.append(f"状态：{ct.status}")
    else:
        lines.append("（无）")
    lines.append("")

    lines.append("========================================")

    return "\n".join(lines)


def output_text(repo_root: Path | None = None) -> None:
    """以文本格式输出上下文。

    参数：
        repo_root：仓库根目录；省略时自动探测。
    """
    if repo_root is None:
        repo_root = get_repo_root()
    update_hint = get_update_hint(repo_root)
    if update_hint:
        print(update_hint)
        print("")
    print(get_context_text(repo_root))
