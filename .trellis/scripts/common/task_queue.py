#!/usr/bin/env python3
"""
任务队列工具函数。

提供：
    list_tasks_by_status   - 按 status 列出任务
    list_pending_tasks     - 列出 planning 状态任务
    list_tasks_by_assignee - 按 assignee 列出任务
    list_my_tasks          - 列出分配给当前开发者的任务
    get_task_stats         - 获取 P0/P1/P2/P3 数量
"""

from __future__ import annotations

from pathlib import Path

from .paths import (
    get_repo_root,
    get_developer,
    get_tasks_dir,
)
from .tasks import iter_active_tasks


# =============================================================================
# 内部辅助函数
# =============================================================================

def _task_to_dict(t) -> dict:
    """将 TaskInfo 转换为调用方需要的 dict 格式。"""
    return {
        "priority": t.priority,
        "id": t.raw.get("id", ""),
        "title": t.title,
        "status": t.status,
        "assignee": t.assignee or "-",
        "dir": t.dir_name,
        "children": list(t.children),
        "parent": t.parent,
    }


# =============================================================================
# 公共函数
# =============================================================================

def list_tasks_by_status(
    filter_status: str | None = None,
    repo_root: Path | None = None
) -> list[dict]:
    """按 status 列出任务。

    参数：
        filter_status：可选 status 过滤条件。
        repo_root：仓库根路径；默认自动检测。

    返回：
        任务信息 dict 列表，包含 priority、id、title、status、assignee 等键。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    tasks_dir = get_tasks_dir(repo_root)
    results = []

    for t in iter_active_tasks(tasks_dir):
        if filter_status and t.status != filter_status:
            continue
        results.append(_task_to_dict(t))

    return results


def list_pending_tasks(repo_root: Path | None = None) -> list[dict]:
    """列出 planning 状态任务。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        任务信息 dict 列表。
    """
    return list_tasks_by_status("planning", repo_root)


def list_tasks_by_assignee(
    assignee: str,
    filter_status: str | None = None,
    repo_root: Path | None = None
) -> list[dict]:
    """列出分配给指定开发者的任务。

    参数：
        assignee：开发者名称。
        filter_status：可选 status 过滤条件。
        repo_root：仓库根路径；默认自动检测。

    返回：
        任务信息 dict 列表。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    tasks_dir = get_tasks_dir(repo_root)
    results = []

    for t in iter_active_tasks(tasks_dir):
        if (t.assignee or "-") != assignee:
            continue
        if filter_status and t.status != filter_status:
            continue
        results.append(_task_to_dict(t))

    return results


def list_my_tasks(
    filter_status: str | None = None,
    repo_root: Path | None = None
) -> list[dict]:
    """列出分配给当前开发者的任务。

    参数：
        filter_status：可选 status 过滤条件。
        repo_root：仓库根路径；默认自动检测。

    返回：
        任务信息 dict 列表。

    异常：
        ValueError：未设置开发者时抛出。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    developer = get_developer(repo_root)
    if not developer:
        raise ValueError("未设置开发者")

    return list_tasks_by_assignee(developer, filter_status, repo_root)


def get_task_stats(repo_root: Path | None = None) -> dict[str, int]:
    """获取任务统计。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        包含 P0、P1、P2、P3、Total 键的 dict。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    tasks_dir = get_tasks_dir(repo_root)
    stats = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "Total": 0}

    for t in iter_active_tasks(tasks_dir):
        if t.priority in stats:
            stats[t.priority] += 1
        stats["Total"] += 1

    return stats


def format_task_stats(stats: dict[str, int]) -> str:
    """将任务统计格式化为字符串。

    参数：
        stats：get_task_stats 返回的统计 dict。

    返回：
        类似 "P0:0 P1:1 P2:2 P3:0 Total:3" 的格式化字符串。
    """
    return f"P0:{stats['P0']} P1:{stats['P1']} P2:{stats['P2']} P3:{stats['P3']} Total:{stats['Total']}"


# =============================================================================
# 主入口（用于测试）
# =============================================================================

if __name__ == "__main__":
    stats = get_task_stats()
    print(format_task_stats(stats))
    print()
    print("规划中的任务：")
    for task in list_pending_tasks():
        print(f"  {task['priority']}|{task['id']}|{task['title']}|{task['status']}|{task['assignee']}")
