#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
向 journal 文件追加一次会话，并更新 index.md。

用法：
    python3 add_session.py --title "标题" --commit "hash" --summary "摘要" [--package cli]
    python3 add_session.py --title "标题" --branch "feat/my-branch"

    # 通过 stdin 传入详细内容（必须显式使用 --stdin）：
    cat << 'EOF' | python3 add_session.py --stdin --title "标题" --summary "摘要"
    <会话内容>
    EOF

    # 结构化内容（可重复；没有条目的 section 会省略）：
    python3 add_session.py --title "标题" --change "完成某项变更" --test "运行某项测试" --next-step "继续某项工作"

分支解析顺序：
    1. --branch CLI 参数（显式值）
    2. 当前任务的 task.json branch 字段（仍存在时）
    3. git branch --show-current（自动探测）
    4. None（安全省略）
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

from common.paths import (
    DIR_TASKS,
    DIR_WORKFLOW,
    FILE_JOURNAL_PREFIX,
    get_repo_root,
    get_current_task,
    get_developer,
    get_workspace_dir,
)
from common.developer import ensure_developer
from common.git import run_git
from common.log import Colors, colored
from common.safe_commit import (
    print_gitignore_warning,
    safe_git_add,
    safe_trellis_paths_to_add,
)
from common.tasks import load_task
from common.types import TaskInfo
from common.config import (
    get_packages,
    get_session_auto_commit,
    get_session_commit_message,
    get_max_journal_lines,
    is_monorepo,
    resolve_package,
    validate_package,
)


# =============================================================================
# 辅助函数
# =============================================================================

def get_latest_journal_info(dev_dir: Path) -> tuple[Path | None, int, int]:
    """获取最新 journal 文件信息。

    返回：
        `(file_path, file_number, line_count)` 元组。
    """
    latest_file: Path | None = None
    latest_num = -1

    for f in dev_dir.glob(f"{FILE_JOURNAL_PREFIX}*.md"):
        if not f.is_file():
            continue

        match = re.search(r"(\d+)$", f.stem)
        if match:
            num = int(match.group(1))
            if num > latest_num:
                latest_num = num
                latest_file = f

    if latest_file:
        lines = len(latest_file.read_text(encoding="utf-8").splitlines())
        return latest_file, latest_num, lines

    return None, 0, 0


def get_current_session(index_file: Path) -> int:
    """从 index.md 获取当前 session 编号。"""
    if not index_file.is_file():
        return 0

    content = index_file.read_text(encoding="utf-8")
    for line in content.splitlines():
        if "Total Sessions" in line or "会话总数" in line:
            match = re.search(r":\s*(\d+)", line)
            if match:
                return int(match.group(1))
    return 0


def _extract_journal_num(filename: str) -> int:
    """从文件名提取 journal 编号，用于排序。"""
    match = re.search(r"(\d+)", filename)
    return int(match.group(1)) if match else 0


def count_journal_files(dev_dir: Path, active_num: int) -> str:
    """统计 journal 文件并返回表格行。"""
    active_file = f"{FILE_JOURNAL_PREFIX}{active_num}.md"
    result_lines = []

    files = sorted(
        [f for f in dev_dir.glob(f"{FILE_JOURNAL_PREFIX}*.md") if f.is_file()],
        key=lambda f: _extract_journal_num(f.stem),
        reverse=True
    )

    for f in files:
        filename = f.name
        lines = len(f.read_text(encoding="utf-8").splitlines())
        status = "活动" if filename == active_file else "已归档"
        result_lines.append(f"| `{filename}` | ~{lines} | {status} |")

    return "\n".join(result_lines)


def get_current_git_branch(repo_root: Path) -> str | None:
    """返回当前检出的 branch；detached 或非 git 状态返回 None。"""
    rc, branch_out, _ = run_git(["branch", "--show-current"], cwd=repo_root)
    if rc != 0:
        return None
    detected = branch_out.strip()
    return detected or None


def branch_ref_exists(repo_root: Path, branch: str) -> bool:
    """branch 在本地或本地 origin ref 中存在时返回 True。"""
    for ref in (f"refs/heads/{branch}", f"refs/remotes/origin/{branch}"):
        rc, _, _ = run_git(["show-ref", "--verify", "--quiet", ref], cwd=repo_root)
        if rc == 0:
            return True
    return False


def resolve_session_branch(
    repo_root: Path,
    cli_branch: str | None,
    task_data: TaskInfo | None,
) -> str | None:
    """解析 journal branch，不盲信过期的 task.json branch 字段。"""
    if cli_branch:
        return cli_branch

    current_branch = get_current_git_branch(repo_root)
    raw_task_branch = task_data.raw.get("branch") if task_data else None
    task_branch = raw_task_branch.strip() if isinstance(raw_task_branch, str) else ""
    if not task_branch:
        return current_branch

    if branch_ref_exists(repo_root, task_branch):
        return task_branch

    if current_branch:
        print(
            f"警告：task.json 中的 branch '{task_branch}' 在本地和 origin/{task_branch} 均不存在；改用当前分支 '{current_branch}'。",
            file=sys.stderr,
        )
        return current_branch

    print(
        f"警告：task.json 中的 branch '{task_branch}' 在本地和 origin/{task_branch} 均不存在；本次日志省略分支。",
        file=sys.stderr,
    )
    return None


def is_git_worktree(repo_root: Path) -> bool:
    """repo_root 是链接 worktree（而非主工作树）时返回 True。

    标准判断方式：将 `git rev-parse --git-dir`（每个 worktree 独立）和
    `git rev-parse --git-common-dir`（所有 worktree 共享）解析为绝对路径后比较；
    在主工作树中两者相同。
    """
    rc_dir, git_dir, _ = run_git(["rev-parse", "--git-dir"], cwd=repo_root)
    rc_common, git_common_dir, _ = run_git(
        ["rev-parse", "--git-common-dir"], cwd=repo_root
    )
    if rc_dir != 0 or rc_common != 0:
        return False

    git_dir_path = (repo_root / git_dir.strip()).resolve()
    git_common_dir_path = (repo_root / git_common_dir.strip()).resolve()
    return git_dir_path != git_common_dir_path


def warn_if_parallel_worktree(repo_root: Path) -> None:
    """输出非阻塞提示：并行 worktree/branch 的 index.md 冲突是预期且安全的。

    仅在启用 `session_auto_commit` 的链接 git worktree（不是主工作树）中输出
    （#415 quick-fix tier）。
    """
    if not get_session_auto_commit(repo_root):
        return
    if not is_git_worktree(repo_root):
        return
    print(
        colored(
            "[提示] 当前在启用 session_auto_commit 的 git worktree 中运行："
            "journal-*.md 会通过 .gitattributes 自动合并；并行 worktree/branch 的 "
            "index.md 冲突属于预期情况，可任选一侧解决（任务状态在 task.json，"
            "不在 index.md）。详见 .trellis/spec/backend/directory-structure.md。",
            Colors.YELLOW,
        ),
        file=sys.stderr,
    )


def create_new_journal_file(
    dev_dir: Path, num: int, developer: str, today: str, max_lines: int = 2000,
) -> Path:
    """创建新的 journal 文件。"""
    prev_num = num - 1
    new_file = dev_dir / f"{FILE_JOURNAL_PREFIX}{num}.md"

    content = f"""# 开发日志 - {developer}（第 {num} 部分）

> 接续 `{FILE_JOURNAL_PREFIX}{prev_num}.md`（该文件在约 {max_lines} 行时归档）
> 开始日期：{today}

---

"""
    new_file.write_text(content, encoding="utf-8")
    return new_file


def _render_bullet_section(header: str, items: list[str], bullet_prefix: str = "- ") -> str:
    """将 Markdown section 渲染为项目符号；无内容时返回 ""。

    没有值的 section 会从渲染结果中完全省略，不会回退到占位字符串。
    """
    if not items:
        return ""
    bullets = "\n".join(f"{bullet_prefix}{item}" for item in items)
    return f"\n\n### {header}\n\n{bullets}"


def _render_main_changes(changes: list[str], extra_content: str | None) -> str:
    """根据 --change 项目或自由文本渲染“主要变更”section。"""
    if changes:
        return _render_bullet_section("主要变更", changes)
    if extra_content:
        return f"\n\n### 主要变更\n\n{extra_content}"
    return ""


def generate_session_content(
    session_num: int,
    title: str,
    commit: str,
    summary: str,
    today: str,
    package: str | None = None,
    branch: str | None = None,
    changes: list[str] | None = None,
    extra_content: str | None = None,
    tests: list[str] | None = None,
    next_steps: list[str] | None = None,
) -> str:
    """生成 session 内容。"""
    if commit and commit != "-":
        commit_table = """| 哈希 | 提交说明 |
|------|---------|"""
        for c in commit.split(","):
            c = c.strip()
            commit_table += f"\n| `{c}` |（参见 git log）|"
    else:
        commit_table = "（无提交 - 规划会话）"

    package_line = f"\n**包**：{package}" if package else ""
    branch_line = f"\n**分支**：`{branch}`" if branch else ""

    main_changes_section = _render_main_changes(changes or [], extra_content)
    testing_section = _render_bullet_section("测试", tests or [], bullet_prefix="- [OK] ")
    next_steps_section = _render_bullet_section("后续步骤", next_steps or [])

    return f"""

## 会话 {session_num}：{title}

**日期**：{today}
**任务**：{title}{package_line}{branch_line}

### 摘要

{summary}{main_changes_section}

### Git 提交

{commit_table}{testing_section}

### 状态

[OK] **已完成**{next_steps_section}
"""


def update_index(
    index_file: Path,
    dev_dir: Path,
    title: str,
    commit: str,
    new_session: int,
    active_file: str,
    today: str,
    branch: str | None = None,
) -> bool:
    """用新的 session 信息更新 index.md。"""
    # 格式化 commit 以便展示。
    commit_display = "-"
    if commit and commit != "-":
        commit_display = re.sub(r"([a-f0-9]{7,})", r"`\1`", commit.replace(",", ", "))

    # 从 active_file 名称获取文件编号。
    match = re.search(r"(\d+)", active_file)
    active_num = int(match.group(1)) if match else 0
    files_table = count_journal_files(dev_dir, active_num)

    print(f"正在更新 index.md（会话 {new_session}）……")
    print(f"  标题：{title}")
    print(f"  提交：{commit_display}")
    print(f"  活动文件：{active_file}")
    print()

    content = index_file.read_text(encoding="utf-8")

    if "@@@auto:current-status" not in content:
        print("错误：index.md 中找不到受管 marker，请确认 marker 未被删除。", file=sys.stderr)
        return False

    # 处理各个 section。
    lines = content.splitlines()
    new_lines = []

    in_current_status = False
    in_active_documents = False
    in_session_history = False
    header_written = False

    for line in lines:
        if "@@@auto:current-status" in line:
            new_lines.append(line)
            in_current_status = True
            new_lines.append(f"- **活动文件**：`{active_file}`")
            new_lines.append(f"- **会话总数**：{new_session}")
            new_lines.append(f"- **最近活动**：{today}")
            continue

        if "@@@/auto:current-status" in line:
            in_current_status = False
            new_lines.append(line)
            continue

        if "@@@auto:active-documents" in line:
            new_lines.append(line)
            in_active_documents = True
            new_lines.append("| 文件 | 行数 | 状态 |")
            new_lines.append("|------|-------|--------|")
            new_lines.append(files_table)
            continue

        if "@@@/auto:active-documents" in line:
            in_active_documents = False
            new_lines.append(line)
            continue

        if "@@@auto:session-history" in line:
            new_lines.append(line)
            in_session_history = True
            header_written = False
            continue

        if "@@@/auto:session-history" in line:
            in_session_history = False
            new_lines.append(line)
            continue

        if in_current_status:
            continue

        if in_active_documents:
            continue

        if in_session_history:
            # 将旧的 4/6 列表头迁移为仅含 Branch 的 5 列历史表。
            if re.match(
                r"^\|\s*#\s*\|\s*Date\s*\|\s*Title\s*\|\s*Commits\s*\|\s*Branch\s*\|\s*Base Branch\s*\|\s*$",
                line,
            ):
                new_lines.append("| # | Date | Title | Commits | Branch |")
                continue
            if re.match(r"^\|\s*#\s*\|\s*Date\s*\|\s*Title\s*\|\s*Commits\s*\|\s*Branch\s*\|\s*$", line):
                new_lines.append("| # | Date | Title | Commits | Branch |")
                continue
            if re.match(r"^\|\s*#\s*\|\s*Date\s*\|\s*Title\s*\|\s*Commits\s*\|\s*$", line):
                new_lines.append("| # | Date | Title | Commits | Branch |")
                continue
            if re.match(
                r"^\|\s*#\s*\|\s*日期\s*\|\s*标题\s*\|\s*提交\s*\|\s*分支\s*\|\s*$",
                line,
            ):
                new_lines.append("| # | 日期 | 标题 | 提交 | 分支 |")
                continue
            if re.match(r"^\|[-| ]+\|\s*$", line) and not header_written:
                new_lines.append("|---|------|-------|---------|--------|")
                new_lines.append(f"| {new_session} | {today} | {title} | {commit_display} | `{branch or '-'}` |")
                header_written = True
                continue
            new_lines.append(line)
            continue

        new_lines.append(line)

    index_file.write_text("\n".join(new_lines), encoding="utf-8")
    print("[OK] index.md 更新成功！")
    return True


# =============================================================================
# 主函数
# =============================================================================

def _auto_commit_workspace(repo_root: Path) -> None:
    """stage 并提交 Trellis 所有的 workspace 和当前任务路径。

    路径范围严格限制为：当前开发者的 journal 文件和 index.md，以及仅当前任务目录
    （通过 ``get_current_task`` 解析）。绝不对整个 `.trellis/` 执行 `git add`，也不遍历
    所有活动任务目录（#303：并行窗口中的脏任务目录不能被打包进 session 自动提交）。
    如果 `.gitignore` 阻止了具体路径，则警告并跳过，绝不使用 ``-f`` 重试。

    遵循 ``.trellis/config.yaml`` 中的 ``session_auto_commit``：设置为 ``false`` 时立即
    返回，不触碰 git（journal/index 文件仍由调用方写入磁盘）。
    """
    if not get_session_auto_commit(repo_root):
        print(
            "[OK] session_auto_commit: false — 跳过 Git stage/commit。",
            file=sys.stderr,
        )
        return

    commit_msg = get_session_commit_message(repo_root)
    # 解析当前任务，使 stage 范围仅限该目录。ref 是 ``.trellis/tasks/<name>``（或
    # archive/ 下的路径），这里传入不带前缀的名称。
    current = get_current_task(repo_root)
    if current:
        task_name = Path(current).name
        paths = safe_trellis_paths_to_add(repo_root, task_name=task_name)
    else:
        # 当前任务未知（0 个或至少 2 个并行 session，正是 #303 讨论的并行窗口情况）。
        # 不要回退到宽泛的 `tasks_dir.iterdir()` 扫描，否则其他任务的脏目录会再次泄漏
        # 到 session commit。这里只 stage 开发者的 journal/index，跳过所有任务目录。
        paths = [
            p
            for p in safe_trellis_paths_to_add(repo_root, task_name=None)
            if not p.startswith(f"{DIR_WORKFLOW}/{DIR_TASKS}/")
        ]
    if not paths:
        print("[OK] 没有需要提交的 workspace 变更。", file=sys.stderr)
        return

    success, _, err = safe_git_add(paths, repo_root)
    if not success:
        if err and "ignored by" in err.lower():
            print_gitignore_warning(paths)
        else:
            print(
                f"[WARN] git add 失败：{err.strip() if err else '未知错误'}",
                file=sys.stderr,
            )
        return

    # 检查刚才 stage 的路径是否真的有 staged 变更。
    rc, _, _ = run_git(
        ["diff", "--cached", "--quiet", "--", *paths], cwd=repo_root
    )
    if rc == 0:
        print("[OK] 没有需要提交的 workspace 变更。", file=sys.stderr)
        return

    rc, _, commit_err = run_git(["commit", "-m", commit_msg], cwd=repo_root)
    if rc == 0:
        print(f"[OK] 已自动提交：{commit_msg}", file=sys.stderr)
    else:
        print(
            f"[WARN] 自动提交失败：{commit_err.strip()}",
            file=sys.stderr,
        )


def add_session(
    title: str,
    commit: str = "-",
    summary: str = "未提供会话摘要。",
    changes: list[str] | None = None,
    extra_content: str | None = None,
    tests: list[str] | None = None,
    next_steps: list[str] | None = None,
    auto_commit: bool = True,
    package: str | None = None,
    branch: str | None = None,
) -> int:
    """添加新的 session。"""
    repo_root = get_repo_root()
    warn_if_parallel_worktree(repo_root)
    ensure_developer(repo_root)

    developer = get_developer(repo_root)
    if not developer:
        print("错误：尚未初始化开发者身份。", file=sys.stderr)
        return 1

    dev_dir = get_workspace_dir(repo_root)
    if not dev_dir:
        print("错误：找不到 workspace 目录。", file=sys.stderr)
        return 1

    max_lines = get_max_journal_lines(repo_root)

    index_file = dev_dir / "index.md"
    today = datetime.now().strftime("%Y-%m-%d")

    journal_file, current_num, current_lines = get_latest_journal_info(dev_dir)
    current_session = get_current_session(index_file)
    new_session = current_session + 1

    session_content = generate_session_content(
        new_session, title, commit, summary, today, package, branch,
        changes=changes, extra_content=extra_content, tests=tests,
        next_steps=next_steps,
    )
    content_lines = len(session_content.splitlines())

    print("========================================", file=sys.stderr)
    print("追加会话", file=sys.stderr)
    print("========================================", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"会话：{new_session}", file=sys.stderr)
    print(f"标题：{title}", file=sys.stderr)
    print(f"提交：{commit}", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"当前 journal 文件：{FILE_JOURNAL_PREFIX}{current_num}.md", file=sys.stderr)
    print(f"当前行数：{current_lines}", file=sys.stderr)
    print(f"新增内容行数：{content_lines}", file=sys.stderr)
    print(f"追加后总行数：{current_lines + content_lines}", file=sys.stderr)
    print("", file=sys.stderr)

    target_file = journal_file
    target_num = current_num

    if current_lines + content_lines > max_lines:
        target_num = current_num + 1
        print(f"[!] 超过 {max_lines} 行，创建 {FILE_JOURNAL_PREFIX}{target_num}.md", file=sys.stderr)
        target_file = create_new_journal_file(dev_dir, target_num, developer, today, max_lines)
        print(f"已创建：{target_file}", file=sys.stderr)

    # 追加 session 内容。
    if target_file:
        with target_file.open("a", encoding="utf-8") as f:
            f.write(session_content)
        print(f"[OK] 已向 {target_file.name} 追加会话。", file=sys.stderr)

    print("", file=sys.stderr)

    # 更新 index.md。
    active_file = f"{FILE_JOURNAL_PREFIX}{target_num}.md"
    if not update_index(
        index_file,
        dev_dir,
        title,
        commit,
        new_session,
        active_file,
        today,
        branch,
    ):
        return 1

    print("", file=sys.stderr)
    print("========================================", file=sys.stderr)
    print(f"[OK] 会话 {new_session} 追加成功！", file=sys.stderr)
    print("========================================", file=sys.stderr)
    print("", file=sys.stderr)
    print("已更新文件：", file=sys.stderr)
    print(f"  - {target_file.name if target_file else 'journal'}", file=sys.stderr)
    print("  - index.md", file=sys.stderr)

    # 自动提交 workspace 变更。
    if auto_commit:
        print("", file=sys.stderr)
        _auto_commit_workspace(repo_root)

    return 0


# =============================================================================
# 主入口
# =============================================================================

def main() -> int:
    """CLI 入口。"""
    parser = argparse.ArgumentParser(
        description="向 journal 文件追加会话并更新 index.md"
    )
    parser.add_argument("--title", required=True, help="会话标题")
    parser.add_argument("--commit", default="-", help="逗号分隔的提交哈希")
    parser.add_argument("--summary", default="未提供会话摘要。", help="简短摘要")
    parser.add_argument("--content-file", help="详细内容文件路径")
    parser.add_argument("--package", help="包名称标签（例如 cli、docs-site）")
    parser.add_argument("--branch", help="分支名称（省略时自动探测）")
    parser.add_argument("--change", action="append", help="主要变更条目（可重复）")
    parser.add_argument("--test", action="append", help="测试条目（可重复）")
    parser.add_argument("--next-step", action="append", help="后续步骤条目（可重复）")
    parser.add_argument("--no-commit", action="store_true",
                        help="跳过 workspace 变更的自动提交")
    parser.add_argument("--stdin", action="store_true",
                        help="从 stdin 读取额外内容（必须显式启用）")

    args = parser.parse_args()

    extra_content: str | None = None
    if args.content_file:
        content_path = Path(args.content_file)
        if content_path.is_file():
            extra_content = content_path.read_text(encoding="utf-8")
    elif args.stdin:
        extra_content = sys.stdin.read()

    # 只加载一次活动任务，供 package 和 branch 解析共享。
    repo_root = get_repo_root()
    current = get_current_task(repo_root)
    task_data = load_task(repo_root / current) if current else None

    package = args.package
    if package:
        # CLI 来源：monorepo 中 fail-fast，single-repo 中忽略。
        if not is_monorepo(repo_root):
            print("警告：单仓库项目忽略 --package。", file=sys.stderr)
            package = None
        elif not validate_package(package, repo_root):
            packages = get_packages(repo_root)
            available = ", ".join(sorted(packages.keys())) if packages else "（无）"
            print(f"错误：未知 package '{package}'。可用值：{available}", file=sys.stderr)
            return 1
    else:
        # 推断顺序：活动任务的 task.json.package → default_package → None。
        task_package = task_data.package if task_data else None
        package = resolve_package(task_package, repo_root)

    branch = resolve_session_branch(repo_root, args.branch, task_data)

    return add_session(
        args.title, args.commit, args.summary,
        changes=args.change, extra_content=extra_content, tests=args.test,
        next_steps=args.next_step,
        auto_commit=not args.no_commit,
        package=package,
        branch=branch,
    )


if __name__ == "__main__":
    sys.exit(main())
