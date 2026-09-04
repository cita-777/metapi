#!/usr/bin/env python3
"""
Trellis workflow 的通用路径工具。

提供：
    get_repo_root          - 获取仓库根目录
    get_developer          - 获取开发者名称
    get_workspace_dir      - 获取开发者工作区目录
    get_tasks_dir          - 获取 tasks 目录
    get_active_journal_file - 获取当前 journal 文件
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path


# =============================================================================
# 路径常量（如需重命名目录，在此处修改）
# =============================================================================

# 目录名称
DIR_WORKFLOW = ".trellis"
DIR_WORKSPACE = "workspace"
DIR_TASKS = "tasks"
DIR_ARCHIVE = "archive"
DIR_SPEC = "spec"
DIR_SCRIPTS = "scripts"

# 文件名称
FILE_DEVELOPER = ".developer"
FILE_CURRENT_TASK = ".current-task"
FILE_TASK_JSON = "task.json"
FILE_JOURNAL_PREFIX = "journal-"


# =============================================================================
# Repository Root
# =============================================================================

def get_repo_root(start_path: Path | None = None) -> Path:
    """查找最近的、包含 .trellis/ 目录的目录。

    正确处理嵌套 git 仓库（例如一个仓库中的测试项目）。

    参数：
        start_path：开始搜索的目录；默认使用当前目录。

    返回：
        仓库根目录路径；找不到 .trellis/ 时返回当前目录。
    """
    current = (start_path or Path.cwd()).resolve()

    while current != current.parent:
        if (current / DIR_WORKFLOW).is_dir():
            return current
        current = current.parent

    # 找不到 .trellis/ 时回退到当前目录。
    return Path.cwd().resolve()


# =============================================================================
# Developer
# =============================================================================

def get_developer(repo_root: Path | None = None) -> str | None:
    """从 .developer 文件获取开发者名称。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        开发者名称；未初始化时返回 None。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    dev_file = repo_root / DIR_WORKFLOW / FILE_DEVELOPER

    if not dev_file.is_file():
        return None

    try:
        content = dev_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.startswith("name="):
                return line.split("=", 1)[1].strip()
    except (OSError, IOError):
        pass

    return None


def check_developer(repo_root: Path | None = None) -> bool:
    """检查开发者身份是否已初始化。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        开发者已初始化时返回 True。
    """
    return get_developer(repo_root) is not None


# =============================================================================
# Tasks 目录
# =============================================================================

def get_tasks_dir(repo_root: Path | None = None) -> Path:
    """获取 tasks 目录路径。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        tasks 目录路径。
    """
    if repo_root is None:
        repo_root = get_repo_root()
    return repo_root / DIR_WORKFLOW / DIR_TASKS


# =============================================================================
# Workspace 目录
# =============================================================================

def get_workspace_dir(repo_root: Path | None = None) -> Path | None:
    """获取开发者工作区目录。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        工作区目录路径；未设置开发者时返回 None。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    developer = get_developer(repo_root)
    if developer:
        return repo_root / DIR_WORKFLOW / DIR_WORKSPACE / developer
    return None


# =============================================================================
# Journal 文件
# =============================================================================

def get_active_journal_file(repo_root: Path | None = None) -> Path | None:
    """获取当前活动 journal 文件。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        活动 journal 文件路径；找不到时返回 None。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    workspace_dir = get_workspace_dir(repo_root)
    if workspace_dir is None or not workspace_dir.is_dir():
        return None

    latest: Path | None = None
    highest = 0

    for f in workspace_dir.glob(f"{FILE_JOURNAL_PREFIX}*.md"):
        if not f.is_file():
            continue

        # 从文件名提取编号。
        name = f.stem  # 例如 "journal-1"
        match = re.search(r"(\d+)$", name)
        if match:
            num = int(match.group(1))
            if num > highest:
                highest = num
                latest = f

    return latest


def count_lines(file_path: Path) -> int:
    """统计文件行数。

    参数：
        file_path：文件路径。

    返回：
        行数；文件不存在时返回 0。
    """
    if not file_path.is_file():
        return 0

    try:
        return len(file_path.read_text(encoding="utf-8").splitlines())
    except (OSError, IOError):
        return 0


# =============================================================================
# 当前任务管理
# =============================================================================

def normalize_task_ref(task_ref: str) -> str:
    """归一化 task ref，保证 runtime 存储稳定。

    存储的 ref 应优先使用类似 `.trellis/tasks/03-27-my-task` 的仓库相对 POSIX 路径，
    即使运行在 Windows 上也一样。绝对路径保持不变，除非调用方之后可以将其转换回
    仓库相对形式。
    """
    normalized = task_ref.strip()
    if not normalized:
        return ""

    path_obj = Path(normalized)
    if path_obj.is_absolute():
        return str(path_obj)

    normalized = normalized.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]

    if normalized.startswith(f"{DIR_TASKS}/"):
        return f"{DIR_WORKFLOW}/{normalized}"

    return normalized


def resolve_task_ref(task_ref: str, repo_root: Path | None = None) -> Path | None:
    """将 task ref 解析为绝对任务目录路径。"""
    if repo_root is None:
        repo_root = get_repo_root()

    normalized = normalize_task_ref(task_ref)
    if not normalized:
        return None

    path_obj = Path(normalized)
    if path_obj.is_absolute():
        return path_obj

    if normalized.startswith(f"{DIR_WORKFLOW}/"):
        return repo_root / path_obj

    return repo_root / DIR_WORKFLOW / DIR_TASKS / path_obj


def get_current_task(
    repo_root: Path | None = None,
    platform_input: dict | None = None,
    platform: str | None = None,
) -> str | None:
    """获取当前任务目录路径（相对于 repo_root）。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        当前任务目录的相对路径；没有时返回 None。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    from .active_task import resolve_active_task

    return resolve_active_task(repo_root, platform_input, platform).task_path


def get_current_task_abs(
    repo_root: Path | None = None,
    platform_input: dict | None = None,
    platform: str | None = None,
) -> Path | None:
    """获取当前任务目录的绝对路径。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        当前任务目录的绝对路径；没有时返回 None。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    relative = get_current_task(repo_root, platform_input, platform)
    if relative:
        return resolve_task_ref(relative, repo_root)
    return None


def get_current_task_source(
    repo_root: Path | None = None,
    platform_input: dict | None = None,
    platform: str | None = None,
) -> tuple[str, str | None, str | None]:
    """以 (`source`, `context_key`, `task_path`) 返回活动任务来源。"""
    if repo_root is None:
        repo_root = get_repo_root()

    from .active_task import get_current_task_source as _get_source

    return _get_source(repo_root, platform_input, platform)


def set_current_task(
    task_path: str,
    repo_root: Path | None = None,
    platform_input: dict | None = None,
    platform: str | None = None,
) -> bool:
    """在 session 作用域设置当前任务。

    参数：
        task_path：任务目录路径（相对于 repo_root）。
        repo_root：仓库根路径；默认自动检测。

    返回：
        成功返回 True，出错返回 False。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    from .active_task import set_active_task

    return set_active_task(
        task_path,
        repo_root,
        platform_input=platform_input,
        platform=platform,
    ) is not None


def clear_current_task(
    repo_root: Path | None = None,
    platform_input: dict | None = None,
    platform: str | None = None,
) -> bool:
    """在 session 作用域清除当前任务。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        成功返回 True。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    from .active_task import clear_active_task

    clear_active_task(
        repo_root,
        platform_input=platform_input,
        platform=platform,
    )
    return True


def has_current_task(repo_root: Path | None = None) -> bool:
    """检查是否存在当前任务。

    参数：
        repo_root：仓库根路径；默认自动检测。

    返回：
        已设置当前任务时返回 True。
    """
    return get_current_task(repo_root) is not None


# =============================================================================
# Task ID 生成
# =============================================================================

def generate_task_date_prefix() -> str:
    """按日期生成 task ID 前缀（MM-DD 格式）。

    返回：
        日期前缀字符串（例如 "01-21"）。
    """
    return datetime.now().strftime("%m-%d")


# =============================================================================
# Monorepo / Package 路径
# =============================================================================


def get_spec_dir(package: str | None = None, repo_root: Path | None = None) -> Path:
    """获取 spec 目录路径。

    单仓库项目：.trellis/spec。
    带 package 的 monorepo：.trellis/spec/<package>。

    使用 lazy import，避免与 config.py 产生循环依赖。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    from .config import get_spec_base

    base = get_spec_base(package, repo_root)
    return repo_root / DIR_WORKFLOW / base


def get_package_path(package: str, repo_root: Path | None = None) -> Path | None:
    """从配置获取 package 源码目录的绝对路径。

    返回：
        package 目录的绝对路径；找不到时返回 None。
    """
    if repo_root is None:
        repo_root = get_repo_root()

    from .config import get_packages

    packages = get_packages(repo_root)
    if not packages or package not in packages:
        return None

    info = packages[package]
    if isinstance(info, dict):
        rel_path = info.get("path", package)
    else:
        rel_path = str(info)

    return repo_root / rel_path


# =============================================================================
# 主入口（用于测试）
# =============================================================================

if __name__ == "__main__":
    repo = get_repo_root()
    print(f"仓库根目录：{repo}")
    print(f"开发者：{get_developer(repo)}")
    print(f"任务目录：{get_tasks_dir(repo)}")
    print(f"workspace 目录：{get_workspace_dir(repo)}")
    print(f"日志文件：{get_active_journal_file(repo)}")
    print(f"当前任务：{get_current_task(repo)}")
