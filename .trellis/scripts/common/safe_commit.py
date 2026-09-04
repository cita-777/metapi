"""
Trellis 管理路径的安全 git-add 辅助函数。

为什么需要此模块
----------------------
真实事故：某项目的 `.gitignore` 列出了 `.trellis/`（公司模板或个人习惯）。
当 `add_session.py` 和 `task.py archive` 执行自动提交、`git add` 因
`ignored by .gitignore` 失败时，驱动 workflow 的 AI agent 曾用
`git add -f .trellis/` 重试“修复”——这会递归包含所有被忽略的子目录
（`.trellis/.backup-*/`、`.trellis/worktrees/`、`.trellis/.template-hashes.json`、
`.trellis/.runtime/`），最终提交了 548 个文件、83,474 行缓存/备份。

设计
------
- 脚本只 stage 明确的产品路径（journal 文件、index.md、当前任务目录和归档目录），
  绝不 stage 整个 `.trellis/` 树。
- 如果普通 `git add <specific>` 因“ignored by”失败，**不要**使用 ``-f`` 重试。
  `.gitignore` 中存在 `.trellis/` 被视为用户意图（“仅在本地保留 .trellis/”）。
  脚本会警告并跳过自动提交；需要自动 stage 时，用户应修正 `.gitignore`，或设置
  ``session_auto_commit: false`` 后自行管理 Git。
- 警告包含反例 ``不要使用 `git add -f .trellis/`……``，避免 AI 重读日志时再次引入该 bug。

历史说明：0.5.10 曾对指定路径自动重试 ``git add -f``，0.5.11 已撤销——即使路径
列表很窄，向用户明确 gitignore 的目录自动强制写入仍违背用户意图。宽范围的禁用命令
继续禁止，窄范围自动 ``-f`` 也已移除。
"""

from __future__ import annotations

import sys
from pathlib import Path

from .git import run_git
from .paths import (
    DIR_ARCHIVE,
    DIR_TASKS,
    DIR_WORKFLOW,
    DIR_WORKSPACE,
    FILE_JOURNAL_PREFIX,
    get_developer,
)


# .trellis/ 下绝不能自动暂存的路径。列出这些具体子路径，便于向用户提示逐项
# 忽略，而不是把整个 `.trellis/` 树一并忽略。
TRELLIS_IGNORED_SUBPATHS = (
    ".trellis/.backup-*",
    ".trellis/worktrees/",
    ".trellis/.template-hashes.json",
    ".trellis/.runtime/",
    ".trellis/.cache/",
)


def safe_trellis_paths_to_add(
    repo_root: Path,
    task_name: str | None = None,
) -> list[str]:
    """返回自动提交应暂存的仓库相对路径列表。

    只包含磁盘上存在的路径，避免向 git 传入不存在的参数；调用方负责随后检查
    `git diff --cached`。

    包含：
      - .trellis/workspace/<developer>/journal-*.md
      - .trellis/workspace/<developer>/index.md
      - .trellis/tasks/<task_name>/（传入 ``task_name`` 时仅包含当前任务目录；如果任务
        已位于 archive/ 下，同时包含其归档位置）

    明确排除（不得暂存）：
      - .trellis/.backup-*, .trellis/worktrees/,
        .trellis/.template-hashes.json, .trellis/.runtime/, .trellis/.cache/

    范围契约（见 #303 / break-loop 分析）：传入 ``task_name`` 时，任务部分只暂存该
    任务目录，不会通过 ``tasks_dir.iterdir()`` 遍历所有活动任务。这与
    :func:`safe_archive_paths_to_add` 一致，避免并行窗口中 OTHER 任务目录的脏改动
    被打包进 session 自动提交。

    向后兼容：未传 ``task_name`` 时保留旧的宽范围行为，遍历所有活动任务目录及
    archive 子树。新调用方应始终传入 ``task_name``。
    """
    paths: list[str] = []

    # 工作区 journal 文件和 index.md。
    developer = get_developer(repo_root)
    if developer:
        ws = repo_root / DIR_WORKFLOW / DIR_WORKSPACE / developer
        if ws.is_dir():
            for f in sorted(ws.glob(f"{FILE_JOURNAL_PREFIX}*.md")):
                if f.is_file():
                    paths.append(
                        f"{DIR_WORKFLOW}/{DIR_WORKSPACE}/{developer}/{f.name}"
                    )
            index_md = ws / "index.md"
            if index_md.is_file():
                paths.append(
                    f"{DIR_WORKFLOW}/{DIR_WORKSPACE}/{developer}/index.md"
                )

    tasks_dir = repo_root / DIR_WORKFLOW / DIR_TASKS
    if not tasks_dir.is_dir():
        return paths

    if task_name is not None:
        # 窄范围：只处理当前任务目录（活动或已归档）。绝不遍历全部任务；并行窗口
        # 中其他任务目录的脏改动不得泄漏到 session 自动提交。
        active_task = tasks_dir / task_name
        if active_task.is_dir():
            paths.append(f"{DIR_WORKFLOW}/{DIR_TASKS}/{task_name}")
        archived_task = tasks_dir / DIR_ARCHIVE / task_name
        if archived_task.is_dir():
            paths.append(
                f"{DIR_WORKFLOW}/{DIR_TASKS}/{DIR_ARCHIVE}/{task_name}"
            )
        return paths

    # 旧的宽范围行为（未传 task_name）：处理 tasks/ 下除 archive 外的每个直接子目录，
    # 以及整个 archive 子树。
    for child in sorted(tasks_dir.iterdir()):
        if not child.is_dir():
            continue
        if child.name == DIR_ARCHIVE:
            continue
        paths.append(f"{DIR_WORKFLOW}/{DIR_TASKS}/{child.name}")

    archive_dir = tasks_dir / DIR_ARCHIVE
    if archive_dir.is_dir():
        paths.append(f"{DIR_WORKFLOW}/{DIR_TASKS}/{DIR_ARCHIVE}")

    return paths


def safe_archive_paths_to_add(
    repo_root: Path,
    task_name: str | None = None,
    modified_children: list[str] | None = None,
) -> list[str]:
    """返回执行 `task.py archive` 后应暂存的路径。

    范围严格限制为归档操作实际触碰的路径：

      - 归档子树（刚移动的任务所在位置）；
      - 源任务目录（用于记录源端删除；调用方需配合 `git rm --cached`，因为工作树中
        已不存在的路径无法由 `git add` 暂存删除）；
      - `task.json` 被编辑以移除已归档父任务的所有子任务目录（更新 parent/children 关系）。

    这种窄范围可避免“范围蔓延”：其他活动任务目录（并行窗口改动）的脏变更不会
    被打包进归档提交。调用方应在各自的提交边界处理不同类型的变化。

    向后兼容：不传参数时保留旧行为，遍历整个 `.trellis/tasks/` 子树（活动任务和
    archive）。新调用方应始终传入 ``task_name``。
    """
    paths: list[str] = []
    tasks_dir = repo_root / DIR_WORKFLOW / DIR_TASKS
    if not tasks_dir.is_dir():
        return paths

    archive_dir = tasks_dir / DIR_ARCHIVE

    if task_name is not None:
        # 窄范围：只返回磁盘上仍存在的路径（避免 `git add` 因源目录已移动而失败）。
        # 源目录删除由调用方显式使用 `git rm --cached` 处理。
        if archive_dir.is_dir():
            paths.append(
                f"{DIR_WORKFLOW}/{DIR_TASKS}/{DIR_ARCHIVE}"
            )
        for child_name in modified_children or []:
            paths.append(f"{DIR_WORKFLOW}/{DIR_TASKS}/{child_name}")
        return paths

    # 旧的宽范围行为（未传 task_name）：保留兼容性，供尚未更新的调用方继续使用。
    if archive_dir.is_dir():
        paths.append(f"{DIR_WORKFLOW}/{DIR_TASKS}/{DIR_ARCHIVE}")
    for child in sorted(tasks_dir.iterdir()):
        if not child.is_dir():
            continue
        if child.name == DIR_ARCHIVE:
            continue
        paths.append(f"{DIR_WORKFLOW}/{DIR_TASKS}/{child.name}")
    return paths


def _stderr_indicates_ignored(stderr: str) -> bool:
    """判断 git add 错误是否表示路径被 .gitignore 排除。"""
    if not stderr:
        return False
    lowered = stderr.lower()
    return "ignored by" in lowered


def safe_git_add(
    paths: list[str], repo_root: Path
) -> tuple[bool, bool, str]:
    """对明确路径执行 `git add`，绝不使用 ``-f`` 重试。

    返回 ``(success, used_force, stderr)``。``used_force`` 为兼容 0.5.10 实现而保留，
    但始终为 ``False``，因为脚本不会自动强制添加。

    行为：
      - 未传路径 → 成功、不强制、stderr 为空；
      - 普通 ``git add -- <paths>`` 成功 → 返回成功；
      - 普通添加因任意原因失败（被忽略或其他原因）→ 返回失败和 stderr。调用方应
        检查 stderr（参见 :func:`print_gitignore_warning`）并跳过自动提交。
    """
    if not paths:
        return True, False, ""

    rc, _, err = run_git(["add", "--", *paths], cwd=repo_root)
    if rc == 0:
        return True, False, ""
    return False, False, err


def print_gitignore_warning(paths: list[str]) -> None:
    """向用户（以及阅读日志的 AI）说明应采取的操作。

    重要：包含反例 ``不要使用 `git add -f .trellis/` ``；已知 agent 可能会重造该命令，
    从而递归加入被忽略的缓存和备份。
    """
    print(
        "[WARN] git add 失败：.trellis/ 路径被 .gitignore 忽略。",
        file=sys.stderr,
    )
    print(
        "[WARN] 跳过自动提交；journal/task 文件仍已写入磁盘。",
        file=sys.stderr,
    )
    print(
        "[WARN] 未操作 Git。",
        file=sys.stderr,
    )
    print("[WARN]", file=sys.stderr)
    print(
        "[WARN] Trellis 管理以下明确路径，建议将它们纳入跟踪：",
        file=sys.stderr,
    )
    if paths:
        for p in paths:
            print(f"[WARN]   {p}", file=sys.stderr)
    else:
        print(
            "[WARN]   .trellis/workspace/<developer>/{journal-*.md,index.md}",
            file=sys.stderr,
        )
        print(
            "[WARN]   .trellis/tasks/<task-dir>/",
            file=sys.stderr,
        )
        print(
            "[WARN]   .trellis/tasks/archive/",
            file=sys.stderr,
        )
    print("[WARN]", file=sys.stderr)
    print(
        "[WARN] 建议：将 .gitignore 中的 `.trellis/` 改为需要忽略的具体",
        file=sys.stderr,
    )
    print(
        "[WARN] 子路径，例如：",
        file=sys.stderr,
    )
    for sub in TRELLIS_IGNORED_SUBPATHS:
        print(f"[WARN]   {sub}", file=sys.stderr)
    print("[WARN]", file=sys.stderr)
    print(
        "[WARN] 或者，如果你有意只在本地保留 .trellis/，请在以下位置设置：",
        file=sys.stderr,
    )
    print(
        "[WARN] .trellis/config.yaml:",
        file=sys.stderr,
    )
    print(
        "[WARN]   session_auto_commit: false",
        file=sys.stderr,
    )
    print(
        "[WARN] 这样脚本会完全跳过 Git，由你自行审阅/提交",
        file=sys.stderr,
    )
    print(
        "[WARN] 由你使用 `git status` / `git add` / `git commit` 手动完成。",
        file=sys.stderr,
    )
    print("[WARN]", file=sys.stderr)
    print(
        "[WARN] 不要使用 `git add -f .trellis/`——它会加入备份、worktree、",
        file=sys.stderr,
    )
    print(
        "[WARN] 以及不应提交的 runtime 缓存。",
        file=sys.stderr,
    )
