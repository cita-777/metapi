"""
Git command 执行工具。

所有 Trellis script 运行 git command 的唯一事实来源。
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def run_git(
    args: list[str],
    cwd: Path | None = None,
    timeout: float | None = None,
) -> tuple[int, str, str]:
    """运行 git command，并返回 (returncode, stdout, stderr)。

    使用 `-c i18n.logOutputEncoding=UTF-8` 和 UTF-8 编码，确保 Windows、macOS、Linux
    上的输出一致。调用方可以为尽力而为的探测提供 timeout；普通 Git 操作默认不设上限。
    """
    try:
        git_args = ["git", "-c", "i18n.logOutputEncoding=UTF-8"] + args
        result = subprocess.run(
            git_args,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)


def resolve_default_branch(repo_root: Path) -> str | None:
    """解析仓库默认 branch（origin/HEAD 目标）。

    先尝试本地 `refs/remotes/origin/HEAD` symbolic ref（不访问网络），再回退到
    `git remote show origin`（可能访问网络，也能修复缺失或过期的 symbolic-ref）。两者
    都无法解析时返回 None，由调用方回退到原有行为。
    """
    rc, out, _ = run_git(["symbolic-ref", "refs/remotes/origin/HEAD"], cwd=repo_root)
    if rc == 0 and out.strip():
        return out.strip().rsplit("/", 1)[-1]

    rc, out, _ = run_git(["remote", "show", "origin"], cwd=repo_root)
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("HEAD branch:"):
                branch = line.split(":", 1)[1].strip()
                if branch and branch != "(unknown)":
                    return branch

    return None


def branch_exists_locally(branch: str, repo_root: Path) -> bool:
    """检查仓库中是否存在本地 branch ref。"""
    if not branch:
        return False
    rc, _, _ = run_git(
        ["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"],
        cwd=repo_root,
    )
    return rc == 0
