#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trellis 任务管理脚本。

用法：
    python3 task.py create "<title>" [--slug <name>] [--assignee <dev>] [--priority P0|P1|P2|P3] [--parent <dir>] [--package <pkg>] [--no-start]
    python3 task.py add-context <dir> <file> <path> [reason] # 添加 JSONL 条目
    python3 task.py validate <dir>              # 校验 JSONL 文件
    python3 task.py list-context <dir>          # 列出 JSONL 条目
    python3 task.py start <dir>                 # 设置活动任务
    python3 task.py current [--source] [--json] # 显示活动任务
    python3 task.py finish                      # 清除活动任务
    python3 task.py set-branch <dir> <branch>   # 设置 Git 分支
    python3 task.py set-base-branch <dir> <branch>  # 设置 PR 目标分支
    python3 task.py set-scope <dir> <scope>     # 设置 PR 标题范围
    python3 task.py set-meta <dir> <key> <value>  # 设置任务 metadata
    python3 task.py archive <task-dir>          # 归档已完成任务
    python3 task.py list                        # 列出活动任务
    python3 task.py list-archive [month]        # 列出已归档任务
    python3 task.py add-subtask <parent-dir> <child-dir>     # 关联子任务与父任务
    python3 task.py remove-subtask <parent-dir> <child-dir>  # 解除子任务与父任务关联
"""

from __future__ import annotations

import argparse
import json
import sys

from common.log import Colors, colored
from common.paths import (
    DIR_WORKFLOW,
    DIR_TASKS,
    FILE_TASK_JSON,
    get_repo_root,
    get_developer,
    get_tasks_dir,
    get_current_task,
)
from common.active_task import (
    clear_active_task,
    resolve_active_task,
    resolve_context_key,
    set_active_task,
)
from common.io import read_json, write_json
from common.task_utils import resolve_task_dir, run_task_hooks
from common.tasks import iter_active_tasks, children_progress

# 从拆分模块导入命令处理器（同时为 plan.py 提供兼容性 re-export）。
from common.task_store import (
    cmd_create,
    cmd_archive,
    cmd_set_branch,
    cmd_set_base_branch,
    cmd_set_scope,
    cmd_set_meta,
    cmd_add_subtask,
    cmd_remove_subtask,
)
from common.task_context import (
    cmd_add_context,
    cmd_validate,
    cmd_list_context,
)


# =============================================================================
# 命令：start / finish
# =============================================================================

def cmd_start(args: argparse.Namespace) -> int:
    """设置活动任务。"""
    repo_root = get_repo_root()
    task_input = args.dir

    if not task_input:
        print(colored("错误：必须提供任务目录或名称。", Colors.RED))
        return 1

    # 解析任务目录（支持任务名称、相对路径或绝对路径）。
    full_path = resolve_task_dir(task_input, repo_root)

    if not full_path.is_dir():
        print(colored(f"错误：找不到任务：{task_input}。", Colors.RED))
        print("提示：可使用任务名称（例如 'my-task'）或完整路径（例如 '.trellis/tasks/01-31-my-task'）。")
        return 1

    # 转换为相对路径后存储。
    try:
        task_dir = full_path.relative_to(repo_root).as_posix()
    except ValueError:
        task_dir = str(full_path)

    task_json_path = full_path / FILE_TASK_JSON

    if not resolve_context_key():
        # 降级模式：没有可用的 session identity。
        # Hook 没有注入 TRELLIS_CONTEXT_ID（Windows + Claude Code、--continue 恢复路径、
        # fork 分发、关闭 hooks 等情况都可能发生）。跳过按 session 写入指针，AI 依据对话
        # 上下文继续工作。
        print(colored(
            "ℹ 当前没有可用的 session identity；本 session 不会持久化活动任务指针（降级模式）。"
            "AI 将依据当前对话上下文继续。",
            Colors.YELLOW,
        ))
        print(colored(
            "提示：请在能提供 session identity 的 AI IDE/session 中运行，"
            "或在执行 task.py start 前设置 TRELLIS_CONTEXT_ID。",
            Colors.YELLOW,
        ))

        # 仍然切换 task.json status：planning → in_progress，使后续阶段可以继续。
        if task_json_path.is_file():
            data = read_json(task_json_path)
            if data and data.get("status") == "planning":
                data["status"] = "in_progress"
                if write_json(task_json_path, data):
                    print(colored("✓ 状态：planning → in_progress（降级模式）", Colors.GREEN))
            run_task_hooks("after_start", task_json_path, repo_root)
        return 0

    active = set_active_task(task_dir, repo_root)
    if active:
        print(colored(f"✓ 已设置活动任务：{task_dir}", Colors.GREEN))
        print(f"来源：{active.source}")

        if task_json_path.is_file():
            data = read_json(task_json_path)
            if data and data.get("status") == "planning":
                data["status"] = "in_progress"
                if write_json(task_json_path, data):
                    print(colored("✓ 状态：planning → in_progress", Colors.GREEN))

        print()
        print(colored("Hook 现在会从该任务的 JSONL 文件注入上下文。", Colors.BLUE))

        run_task_hooks("after_start", task_json_path, repo_root)
        return 0
    else:
        print(colored("错误：设置活动任务失败。", Colors.RED))
        return 1


def cmd_finish(args: argparse.Namespace) -> int:
    """清除活动任务。"""
    repo_root = get_repo_root()
    active = clear_active_task(repo_root)
    current = active.task_path

    if not current:
        print(colored("尚未设置活动任务。", Colors.YELLOW))
        return 0

    # 清除前先解析 task.json 路径。
    task_json_path = repo_root / current / FILE_TASK_JSON

    print(colored(f"✓ 已清除活动任务（原任务：{current}）", Colors.GREEN))
    print(f"来源：{active.source}")

    if task_json_path.is_file():
        run_task_hooks("after_finish", task_json_path, repo_root)
    return 0


def cmd_current(args: argparse.Namespace) -> int:
    """显示活动任务。"""
    repo_root = get_repo_root()
    active = resolve_active_task(repo_root)

    if getattr(args, "json", False):
        task_obj = None
        if active.task_path:
            data = read_json(repo_root / active.task_path / FILE_TASK_JSON) or {}
            task_obj = {
                "dir": active.task_path,
                "id": data.get("id") or data.get("name"),
                "title": data.get("title"),
                "status": data.get("status"),
                "parent": data.get("parent"),
                "children": data.get("children", []),
                "branch": data.get("branch"),
                "base_branch": data.get("base_branch"),
            }
        print(json.dumps({
            "current_task": task_obj,
            "source": active.source,
            "stale": active.stale,
        }, ensure_ascii=False))
        return 0 if active.task_path else 1

    if args.source:
        print(f"活动任务：{active.task_path or '（无）'}")
        print(f"来源：{active.source}")
        if active.stale:
            print("状态：stale")
        return 0 if active.task_path else 1

    if active.task_path:
        print(active.task_path)
        return 0

    return 1


# =============================================================================
# 命令：list
# =============================================================================

def _display_status(t, all_statuses: dict) -> str:
    """返回 `list` 输出中显示的任务状态标签。

    父任务的存储状态会一直保持为 "planning"，直到有人直接对父任务运行
    `task.py start`；即使子任务正在执行，列表中也容易造成误解（#399 item 3）。
    当至少一个子任务已离开 planning 时显示 "active"；不修改 task.json 中的存储状态。
    """
    if t.status == "planning" and t.children:
        child_in_flight = any(
            all_statuses.get(c) not in (None, "planning") for c in t.children
        )
        if child_in_flight:
            return "active"
    return t.status


def cmd_list(args: argparse.Namespace) -> int:
    """列出活动任务。"""
    repo_root = get_repo_root()
    tasks_dir = get_tasks_dir(repo_root)
    current_task = get_current_task(repo_root)
    developer = get_developer(repo_root)
    filter_mine = args.mine
    filter_status = args.status
    as_json = getattr(args, "json", False)

    # 单次遍历：通过共享 iterator 收集所有任务。
    all_tasks = {t.dir_name: t for t in iter_active_tasks(tasks_dir)}
    all_statuses = {name: t.status for name, t in all_tasks.items()}

    if as_json:
        if filter_mine and not developer:
            print(json.dumps({"error": "未设置开发者身份"}, ensure_ascii=False), file=sys.stderr)
            return 1

        items = []
        for dir_name in sorted(all_tasks.keys()):
            t = all_tasks[dir_name]
            if filter_mine and (t.assignee or "-") != developer:
                continue
            if filter_status and t.status != filter_status:
                continue
            items.append({
                "dir": f"{DIR_WORKFLOW}/{DIR_TASKS}/{dir_name}",
                "id": t.raw.get("id") or dir_name,
                "title": t.title,
                "status": t.status,
                "display_status": _display_status(t, all_statuses),
                "priority": t.priority,
                "assignee": t.assignee or None,
                "parent": t.parent,
                "children": list(t.children),
                "package": t.package,
            })
        print(json.dumps({"tasks": items}, ensure_ascii=False))
        return 0

    if filter_mine:
        if not developer:
            print(colored("错误：尚未设置开发者身份。请先运行 init_developer.py。", Colors.RED), file=sys.stderr)
            return 1
        print(colored(f"我的任务（assignee：{developer}）：", Colors.BLUE))
    else:
        print(colored("全部活动任务：", Colors.BLUE))
    print()

    # 按层级展示任务。
    count = 0

    def _print_task(dir_name: str, indent: int = 0) -> None:
        nonlocal count
        t = all_tasks[dir_name]

        # 应用 --mine 过滤。
        if filter_mine and (t.assignee or "-") != developer:
            return

        # 应用 --status 过滤。
        if filter_status and t.status != filter_status:
            return

        relative_path = f"{DIR_WORKFLOW}/{DIR_TASKS}/{dir_name}"
        marker = ""
        if relative_path == current_task:
            marker = f" {colored('<- current', Colors.GREEN)}"

        # 子任务进度。
        progress = children_progress(t.children, all_statuses)
        status_label = _display_status(t, all_statuses)

        # package 标签。
        pkg_tag = f" @{t.package}" if t.package else ""

        prefix = "  " * indent + "  - "

        if filter_mine:
            print(f"{prefix}{dir_name}/ ({status_label}){pkg_tag}{progress}{marker}")
        else:
            print(f"{prefix}{dir_name}/ ({status_label}){pkg_tag}{progress} [{colored(t.assignee or '-', Colors.CYAN)}]{marker}")
        count += 1

        # 缩进输出子任务。
        for child_name in t.children:
            if child_name in all_tasks:
                _print_task(child_name, indent + 1)

    # 只展示顶层任务：没有 parent 的任务，以及记录的 parent 不在（或已不在）活动集合中
    # 的孤儿任务。悬空 parent ref 仍应以扁平形式渲染，不能直接消失。
    for dir_name in sorted(all_tasks.keys()):
        parent = all_tasks[dir_name].parent
        if not parent or parent not in all_tasks:
            _print_task(dir_name)

    if count == 0:
        if filter_mine:
            print("  （没有分配给你的任务）")
        else:
            print("  （没有活动任务）")

    print()
    print(f"总计：{count} 个任务")
    return 0


# =============================================================================
# 命令：list-archive
# =============================================================================

def cmd_list_archive(args: argparse.Namespace) -> int:
    """列出已归档任务。"""
    repo_root = get_repo_root()
    tasks_dir = get_tasks_dir(repo_root)
    archive_dir = tasks_dir / "archive"
    month = args.month

    print(colored("已归档任务：", Colors.BLUE))
    print()

    if month:
        month_dir = archive_dir / month
        if month_dir.is_dir():
            print(f"[{month}]")
            for d in sorted(month_dir.iterdir()):
                if d.is_dir():
                    print(f"  - {d.name}/")
        else:
            print(f"  {month} 没有归档任务")
    else:
        if archive_dir.is_dir():
            for month_dir in sorted(archive_dir.iterdir()):
                if month_dir.is_dir():
                    month_name = month_dir.name
                    count = sum(1 for d in month_dir.iterdir() if d.is_dir())
                    print(f"[{month_name}] - {count} 个任务")

    return 0


# =============================================================================
# 帮助
# =============================================================================

def show_usage() -> None:
    """显示用法帮助。"""
    print("""Trellis 任务管理脚本

用法：
  python3 task.py create <title>                     创建任务目录
  python3 task.py create <title> --package <pkg>     为指定 package 创建任务
  python3 task.py create <title> --parent <dir>      创建父任务的子任务
  python3 task.py create <title> --no-start          创建任务但不在本 session 激活
  python3 task.py add-context <dir> <jsonl> <path> [reason]  添加 JSONL 条目
  python3 task.py validate <dir>                     校验 JSONL 文件
  python3 task.py list-context <dir>                 列出 JSONL 条目
  python3 task.py start <dir>                        设置活动任务
  python3 task.py current [--source]                 显示活动任务
  python3 task.py finish                             清除活动任务
  python3 task.py set-branch <dir> <branch>          设置 Git 分支
  python3 task.py set-base-branch <dir> <branch>     设置 PR 目标分支
  python3 task.py set-scope <dir> <scope>            设置 PR 标题范围
  python3 task.py set-meta <dir> <key> <value>       设置/覆盖任务 metadata
  python3 task.py archive <task-dir>                 归档已完成任务
  python3 task.py add-subtask <parent> <child>       关联子任务与父任务
  python3 task.py remove-subtask <parent> <child>    解除子任务与父任务关联
  python3 task.py list [--mine] [--status <status>] [--json]  列出任务
  python3 task.py list-archive [YYYY-MM]             列出已归档任务

Monorepo 选项（多包项目）：
  --package <pkg>      package 名称（依据 config.yaml 的 packages 校验）

列表选项：
  --mine, -m           只显示分配给当前开发者的任务
  --status, -s <s>     按 status 筛选（planning、in_progress、review、completed）
  --json               输出机器可读 JSON（`current` 也支持）

示例：
  python3 task.py create "添加登录功能" --slug add-login
  python3 task.py create "添加登录功能" --slug add-login --package cli
  python3 task.py create "添加登录功能" --meta linear=ENG-123 --meta epic=auth
  python3 task.py create "子任务" --slug child --parent .trellis/tasks/01-21-parent
  python3 task.py add-context <dir> implement .trellis/spec/cli/backend/auth.md "认证规范"
  python3 task.py set-branch <dir> task/add-login
  python3 task.py start .trellis/tasks/01-21-add-login
  python3 task.py current --source
  python3 task.py finish
  python3 task.py archive add-login
  python3 task.py add-subtask parent-task child-task  # 关联已有任务
  python3 task.py remove-subtask parent-task child-task
  python3 task.py list                               # 列出全部活动任务
  python3 task.py list --mine                        # 只列出我的任务
  python3 task.py list --mine --status in_progress   # 列出我的进行中任务
""")


# =============================================================================
# 主入口
# =============================================================================

def main() -> int:
    """CLI 入口。"""
    # 兼容性提示：`init-context` 已在 v0.5.0-beta.12 移除。
    # 提前检测，避免 argparse 用笼统的 "invalid choice" 错误掩盖真实原因。
    if len(sys.argv) >= 2 and sys.argv[1] == "init-context":
        print(
            colored(
                "错误：`task.py init-context` 已在 v0.5.0-beta.12 移除。",
                Colors.RED,
            ),
            file=sys.stderr,
        )
        print(
            "现在，支持 sub-agent 的平台会在 `task.py create` 时生成 implement.jsonl / check.jsonl；",
            file=sys.stderr,
        )
        print(
            "需要时由 AI 在规划阶段整理真实条目。",
            file=sys.stderr,
        )
        print("请查阅 .trellis/workflow.md 的规划产物说明，或运行：", file=sys.stderr)
        print(
            "  python3 ./.trellis/scripts/get_context.py --mode phase --step 1",
            file=sys.stderr,
        )
        print(
            "使用 `task.py add-context <dir> implement|check <path> <reason>` 追加条目。",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser(
        description="Trellis 任务管理脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="命令")

    # create
    p_create = subparsers.add_parser("create", help="创建新任务")
    p_create.add_argument("title", help="任务标题")
    p_create.add_argument("--slug", "-s", help="不含 MM-DD 日期前缀的任务 slug")
    p_create.add_argument("--assignee", "-a", help="负责开发者")
    p_create.add_argument("--priority", "-p", default="P2", help="优先级（P0-P3）")
    p_create.add_argument("--description", "-d", help="任务描述")
    p_create.add_argument("--parent", help="父任务目录（建立子任务关联）")
    p_create.add_argument("--package", help="monorepo 项目的 package 名称")
    p_create.add_argument(
        "--base-branch",
        help="PR 目标分支（覆盖 origin/HEAD 探测和当前检出分支回退）",
    )
    p_create.add_argument(
        "--meta",
        action="append",
        help="任务 metadata key=value（可重复）",
    )
    p_create.add_argument(
        "--no-start",
        action="store_true",
        help="创建任务但不在本 session 激活",
    )

    # add-context
    p_add = subparsers.add_parser("add-context", help="添加上下文条目")
    p_add.add_argument("dir", help="任务目录")
    p_add.add_argument("file", help="JSONL 文件（implement|check）")
    p_add.add_argument("path", help="要添加的文件路径")
    p_add.add_argument("reason", nargs="?", help="添加原因")

    # validate
    p_validate = subparsers.add_parser("validate", help="校验上下文文件")
    p_validate.add_argument("dir", help="任务目录")

    # list-context
    p_listctx = subparsers.add_parser("list-context", help="列出上下文条目")
    p_listctx.add_argument("dir", help="任务目录")

    # start
    p_start = subparsers.add_parser("start", help="设置活动任务")
    p_start.add_argument("dir", help="任务目录")

    # current
    p_current = subparsers.add_parser("current", help="显示活动任务")
    p_current.add_argument("--source", action="store_true",
                           help="显示活动任务来源")
    p_current.add_argument("--json", action="store_true",
                           help="输出机器可读 JSON")

    # finish
    subparsers.add_parser("finish", help="清除活动任务")

    # set-branch
    p_branch = subparsers.add_parser("set-branch", help="设置 Git 分支")
    p_branch.add_argument("dir", help="任务目录")
    p_branch.add_argument("branch", help="分支名称")

    # set-base-branch
    p_base = subparsers.add_parser("set-base-branch", help="设置 PR 目标分支")
    p_base.add_argument("dir", help="任务目录")
    p_base.add_argument("base_branch", help="基础分支名称（PR 目标）")

    # set-scope
    p_scope = subparsers.add_parser("set-scope", help="设置范围")
    p_scope.add_argument("dir", help="任务目录")
    p_scope.add_argument("scope", help="范围名称")

    # set-meta
    p_setmeta = subparsers.add_parser("set-meta", help="设置/覆盖任务 metadata")
    p_setmeta.add_argument("dir", help="任务目录")
    p_setmeta.add_argument("key", help="metadata 键")
    p_setmeta.add_argument("value", help="metadata 值")

    # archive
    p_archive = subparsers.add_parser("archive", help="归档任务")
    p_archive.add_argument("name", help="任务目录或名称")
    p_archive.add_argument("--no-commit", action="store_true", help="归档后跳过 Git 自动提交")

    # list
    p_list = subparsers.add_parser("list", help="列出任务")
    p_list.add_argument("--mine", "-m", action="store_true", help="只显示我的任务")
    p_list.add_argument("--status", "-s", help="按 status 筛选")
    p_list.add_argument("--json", action="store_true", help="输出机器可读 JSON")

    # add-subtask
    p_addsub = subparsers.add_parser("add-subtask", help="关联子任务与父任务")
    p_addsub.add_argument("parent_dir", help="父任务目录")
    p_addsub.add_argument("child_dir", help="子任务目录")

    # remove-subtask
    p_rmsub = subparsers.add_parser("remove-subtask", help="解除子任务与父任务关联")
    p_rmsub.add_argument("parent_dir", help="父任务目录")
    p_rmsub.add_argument("child_dir", help="子任务目录")

    # list-archive
    p_listarch = subparsers.add_parser("list-archive", help="列出已归档任务")
    p_listarch.add_argument("month", nargs="?", help="月份（YYYY-MM）")

    args = parser.parse_args()

    if not args.command:
        show_usage()
        return 1

    commands = {
        "create": cmd_create,
        "add-context": cmd_add_context,
        "validate": cmd_validate,
        "list-context": cmd_list_context,
        "start": cmd_start,
        "current": cmd_current,
        "finish": cmd_finish,
        "set-branch": cmd_set_branch,
        "set-base-branch": cmd_set_base_branch,
        "set-scope": cmd_set_scope,
        "set-meta": cmd_set_meta,
        "archive": cmd_archive,
        "add-subtask": cmd_add_subtask,
        "remove-subtask": cmd_remove_subtask,
        "list": cmd_list,
        "list-archive": cmd_list_archive,
    }

    if args.command in commands:
        return commands[args.command](args)
    else:
        show_usage()
        return 1


if __name__ == "__main__":
    sys.exit(main())
