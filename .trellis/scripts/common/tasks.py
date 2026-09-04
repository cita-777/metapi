"""
任务数据访问层。

加载和遍历任务目录的唯一事实来源，替代散落在 9 个以上文件中的 task.json 解析。

提供：
    load_task          — 按目录路径加载单个任务
    iter_active_tasks  — 按排序遍历所有未归档任务
    get_all_statuses   — 获取用于子任务进度的 {dir_name: status} 映射
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from .io import read_json
from .paths import FILE_TASK_JSON
from .types import TaskInfo


def load_task(task_dir: Path) -> TaskInfo | None:
    """从包含 task.json 的目录加载任务。

    参数：
        task_dir：任务目录的绝对路径。

    返回：
        task.json 存在且有效时返回 TaskInfo，否则返回 None。
    """
    task_json = task_dir / FILE_TASK_JSON
    if not task_json.is_file():
        return None

    data = read_json(task_json)
    if not data:
        return None

    return TaskInfo(
        dir_name=task_dir.name,
        directory=task_dir,
        title=data.get("title") or data.get("name") or "unknown",
        status=data.get("status", "unknown"),
        assignee=data.get("assignee", ""),
        priority=data.get("priority", "P2"),
        children=tuple(data.get("children", [])),
        parent=data.get("parent"),
        package=data.get("package"),
        raw=data,
    )


def iter_active_tasks(tasks_dir: Path) -> Iterator[TaskInfo]:
    """按目录名称排序遍历所有活动（未归档）任务。

    跳过 "archive" 目录和不包含有效 task.json 的目录。

    参数：
        tasks_dir：tasks 目录路径。

    生成：
        每个有效任务的 TaskInfo。
    """
    if not tasks_dir.is_dir():
        return

    for d in sorted(tasks_dir.iterdir()):
        if not d.is_dir() or d.name == "archive":
            continue
        info = load_task(d)
        if info is not None:
            yield info


def get_all_statuses(tasks_dir: Path) -> dict[str, str]:
    """获取所有活动任务的 {dir_name: status} 映射。

    可在不加载完整 TaskInfo 的情况下计算子任务进度。

    参数：
        tasks_dir：tasks 目录路径。

    返回：
        目录名称到 status 字符串的映射。
    """
    return {t.dir_name: t.status for t in iter_active_tasks(tasks_dir)}


def children_progress(
    children: tuple[str, ...] | list[str],
    all_statuses: dict[str, str],
) -> str:
    """将子任务进度格式化为类似 " [2/3 done]" 的字符串。

    参数：
        children：子任务目录名称列表。
        all_statuses：get_all_statuses() 返回的 status 映射。

    返回：
        格式化字符串；没有子任务时返回 ""。
    """
    if not children:
        return ""
    # active statuses 中缺失的子任务已被归档（cmd_archive 移动目录前会将 status 设为
    # completed）。将其计为完成，避免归档子任务后父任务进度倒退。
    done = sum(
        1 for c in children
        if c not in all_statuses or all_statuses.get(c) in ("completed", "done")
    )
    return f" [{done}/{len(children)} done]"
