"""
Trellis workflow script 的通用工具。

本模块提供其他 Trellis script 共用的功能。
"""

import io
import sys

# =============================================================================
# Windows 编码修复（必须位于文件顶部、任何输出之前）。
# =============================================================================
# Windows 上 stdout 默认使用系统 code page（通常是 GBK/CP936），打印非 ASCII 字符时
# 会触发 UnicodeEncodeError。
#
# 任何从 common 导入的 script 都会自动获得此修复。
# =============================================================================


def _configure_stream(stream: object) -> object:
    """在 Windows 上将 stream 配置为 UTF-8 编码。"""
    # 优先尝试 reconfigure()（Python 3.7+，更可靠）。
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        return stream
    # 回退：detach 后使用 TextIOWrapper 重新包装。
    elif hasattr(stream, "detach"):
        return io.TextIOWrapper(
            stream.detach(),  # type: ignore[union-attr]
            encoding="utf-8",
            errors="replace",
        )
    return stream


if sys.platform == "win32":
    sys.stdout = _configure_stream(sys.stdout)  # type: ignore[assignment]
    sys.stderr = _configure_stream(sys.stderr)  # type: ignore[assignment]
    sys.stdin = _configure_stream(sys.stdin)  # type: ignore[assignment]


def configure_encoding() -> None:
    """
    在 Windows 上将 stdout/stderr/stdin 配置为 UTF-8。

    从 common 导入时会自动调用；不导入 common 的 script 也可以手动调用。
    可安全重复调用。
    """
    global sys
    if sys.platform == "win32":
        sys.stdout = _configure_stream(sys.stdout)  # type: ignore[assignment]
        sys.stderr = _configure_stream(sys.stderr)  # type: ignore[assignment]
        sys.stdin = _configure_stream(sys.stdin)  # type: ignore[assignment]


from .paths import (
    DIR_WORKFLOW,
    DIR_WORKSPACE,
    DIR_TASKS,
    DIR_ARCHIVE,
    DIR_SPEC,
    DIR_SCRIPTS,
    FILE_DEVELOPER,
    FILE_CURRENT_TASK,
    FILE_TASK_JSON,
    FILE_JOURNAL_PREFIX,
    get_repo_root,
    get_developer,
    check_developer,
    get_tasks_dir,
    get_workspace_dir,
    get_active_journal_file,
    count_lines,
    get_current_task,
    get_current_task_abs,
    normalize_task_ref,
    resolve_task_ref,
    set_current_task,
    clear_current_task,
    has_current_task,
    generate_task_date_prefix,
)

from .active_task import (
    ActiveTask,
    clear_active_task,
    resolve_active_task,
    resolve_context_key,
    set_active_task,
)
