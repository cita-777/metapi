#!/usr/bin/env python3
"""
任务 CRUD 操作。

提供任务目录创建、归档、分支/范围/metadata 设置以及父子任务关联。
机器字段和命令名称保持原文；CLI 提示默认使用简体中文。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from .config import (
    get_codex_dispatch_mode,
    get_packages,
    get_session_auto_commit,
    is_monorepo,
    resolve_package,
    validate_package,
)
from .git import branch_exists_locally, resolve_default_branch, run_git
from .io import read_json, write_json
from .log import Colors, colored
from .paths import (
    DIR_ARCHIVE,
    DIR_TASKS,
    DIR_WORKFLOW,
    FILE_TASK_JSON,
    generate_task_date_prefix,
    get_developer,
    get_repo_root,
    get_tasks_dir,
)
from .safe_commit import (
    print_gitignore_warning,
    safe_archive_paths_to_add,
    safe_git_add,
)
from .task_utils import (
    archive_task_complete,
    find_task_by_name,
    is_within_tasks_dir,
    resolve_task_dir,
    run_task_hooks,
)


# =============================================================================
# 辅助函数
# =============================================================================

def _slugify(title: str) -> str:
    """将标题转换为 slug（仅支持 ASCII）。"""
    result = title.lower()
    result = re.sub(r"[^a-z0-9]", "-", result)
    result = re.sub(r"-+", "-", result)
    result = result.strip("-")
    return result


def ensure_tasks_dir(repo_root: Path) -> Path:
    """确保 tasks 目录存在。"""
    tasks_dir = get_tasks_dir(repo_root)
    archive_dir = tasks_dir / "archive"

    if not tasks_dir.exists():
        tasks_dir.mkdir(parents=True)
        print(colored(f"已创建任务目录：{tasks_dir}", Colors.GREEN), file=sys.stderr)

    if not archive_dir.exists():
        archive_dir.mkdir(parents=True)

    return tasks_dir


def _find_archived_task_by_dir_name(tasks_dir: Path, dir_name: str) -> Path | None:
    """按活动任务目录的精确名称查找归档任务目录。"""
    archive_dir = tasks_dir / DIR_ARCHIVE
    if not archive_dir.is_dir():
        return None

    for month_dir in sorted(archive_dir.iterdir()):
        if not month_dir.is_dir():
            continue
        candidate = month_dir / dir_name
        if candidate.is_dir():
            return candidate

    return None


def _repo_relative_path(path: Path, repo_root: Path) -> str:
    """在可能时将路径格式化为相对于仓库根目录的路径。"""
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


# =============================================================================
# Sub-agent 平台检测与 JSONL seed
# =============================================================================

# 消费 implement.jsonl / check.jsonl 的平台配置目录。必须与 src/types/ai-tools.ts 的
# AI_TOOLS 条目保持同步；这些平台列在 workflow.md 的“支持 agent” Skill Routing 区块中。
# Codex 单独检查，因为显式 inline 模式不消费 JSONL。Kilo / Antigravity / Devin 也不在
# 此列表中：它们通过 skills 加载 spec，而不是 JSONL。
_SUBAGENT_CONFIG_DIRS: tuple[str, ...] = (
    ".claude",
    ".cursor",
    ".kiro",
    ".gemini",
    ".opencode",
    ".qoder",
    ".codebuddy",
    ".factory",   # Factory Droid
    ".github/copilot",
    ".pi",        # Pi Agent
    ".trae",      # Trae IDE
    ".omp",       # Oh My Pi
    ".zcode",     # ZCode
    ".grok",      # Grok Build
    ".kimi-code", # Kimi Code
)
_CODEX_CONFIG_DIR = ".codex"

_SEED_EXAMPLE = (
    "请填写 {\"file\": \"<path>\", \"reason\": \"<原因>\"}。"
    "这里只引用 spec/research 文件，不要填写产品代码路径。"
    "可运行 `python3 ./.trellis/scripts/get_context.py --mode packages` 查看可用规范。"
    "加入真实条目后删除本行。"
)


def _has_subagent_platform(repo_root: Path) -> bool:
    """配置了任一支持 sub-agent 的平台时返回 True。

    通过探测仓库根目录的已知配置目录判断。Codex 默认通过
    ``codex.dispatch_mode: auto`` 计入（包括旧的 ``sub-agent`` 别名）；显式 inline 模式
    通过 skills 而不是 JSONL 加载上下文。
    """
    for config_dir in _SUBAGENT_CONFIG_DIRS:
        if (repo_root / config_dir).is_dir():
            return True
    if (repo_root / _CODEX_CONFIG_DIR).is_dir():
        return get_codex_dispatch_mode(repo_root) == "auto"
    return False


def _write_seed_jsonl(path: Path) -> None:
    """写入只有一行、带自描述 ``_example`` 的 seed JSONL 文件。

    seed 行没有 ``file`` 字段，因此下游消费者（hooks + preludes）通过
    ``item.get("file")`` 遍历时会自然跳过。该行仅作为文件内提示，提醒 AI 整理真实条目。
    """
    seed = {"_example": _SEED_EXAMPLE}
    path.write_text(json.dumps(seed, ensure_ascii=False) + "\n", encoding="utf-8")


def _parse_meta_pairs(pairs: list[str] | None) -> dict[str, str] | None:
    """将可重复的 ``--meta key=value`` 参数解析为 dict。

    遇到第一处 malformed pair（缺少 ``=`` 或 key 为空）时先打印包含错误值的提示，再返回
    ``None``。值按原样保存（字符串、不嵌套、不做类型转换）。
    """
    meta: dict[str, str] = {}
    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            print(
                colored(f"错误：--meta 值 '{pair}' 格式不正确（应为 key=value）。", Colors.RED),
                file=sys.stderr,
            )
            return None
        meta[key] = value
    return meta


def _default_prd_content(title: str, description: str | None = None) -> str:
    """返回每个任务创建时使用的默认 PRD 骨架。"""
    goal = (description or "").strip() or "待补充。"
    heading = title.strip() or "未命名任务"
    return f"""# {heading}

## 目标

{goal}

## 需求

- 待补充

## 验收标准

- [ ] 待补充

## 备注

- `prd.md` 只记录需求、约束和验收标准。
- 轻量任务可以只保留 `prd.md`。
- 复杂任务在 `task.py start` 前补充 `design.md`（技术设计）和 `implement.md`（执行计划）。
"""


# =============================================================================
# 命令：create
# =============================================================================

def cmd_create(args: argparse.Namespace) -> int:
    """创建新任务。"""
    repo_root = get_repo_root()

    if not args.title:
        print(colored("错误：必须提供 title。", Colors.RED), file=sys.stderr)
        return 1

    # 校验 --meta（CLI 来源：fail-fast，且在创建目录前执行）。
    meta = _parse_meta_pairs(getattr(args, "meta", None))
    if meta is None:
        return 1

    # 校验 --package（CLI 来源：fail-fast）。
    package: str | None = getattr(args, "package", None)
    if not is_monorepo(repo_root):
        # Single-repo：忽略 --package，不添加 package 前缀。
        if package:
            print(colored("警告：单仓库项目忽略 --package。", Colors.YELLOW), file=sys.stderr)
        package = None
    elif package:
        if not validate_package(package, repo_root):
            packages = get_packages(repo_root)
            available = ", ".join(sorted(packages.keys())) if packages else "(none)"
            print(colored(f"错误：未知 package '{package}'。可用值：{available}", Colors.RED), file=sys.stderr)
            return 1
    else:
        # 推断顺序：default_package → None（create 阶段还没有 task.json）。
        package = resolve_package(repo_root=repo_root)

    # 默认 assignee 为当前开发者。
    assignee = args.assignee
    if not assignee:
        assignee = get_developer(repo_root)
        if not assignee:
            print(colored("错误：尚未设置开发者身份。请先运行 init_developer.py，或使用 --assignee。", Colors.RED), file=sys.stderr)
            return 1

    ensure_tasks_dir(repo_root)

    # 将当前开发者作为 creator。
    creator = get_developer(repo_root) or assignee

    # 未提供时生成 slug。
    slug = args.slug or _slugify(args.title)
    if not slug:
        print(colored("错误：无法根据 title 生成 slug。", Colors.RED), file=sys.stderr)
        return 1

    # 按 MM-DD-slug 格式创建任务目录。
    tasks_dir = get_tasks_dir(repo_root)
    date_prefix = generate_task_date_prefix()

    # 防止 --slug 已带日期前缀（例如直接粘贴完整任务目录名），否则会产生
    # MM-DD-MM-DD-slug（issue #377）。只对显式 --slug 做此保护；标题生成的 slug 保持不变。
    if args.slug:
        m = re.match(r"^(\d{2})-(\d{2})-(.+)$", slug)
        if m and 1 <= int(m.group(1)) <= 12 and 1 <= int(m.group(2)) <= 31:
            slug_prefix = f"{m.group(1)}-{m.group(2)}"
            if slug_prefix == date_prefix:
                slug = m.group(3)
                print(
                    colored(
                        f'警告：--slug 不应包含 MM-DD 前缀，已规范化为 "{slug}"。',
                        Colors.YELLOW,
                    ),
                    file=sys.stderr,
                )
            else:
                print(
                    colored(
                        f"错误：--slug 以日期前缀 ({slug_prefix}-) 开头，但 task.py create 始终使用当天日期 ({date_prefix})。",
                        Colors.RED,
                    ),
                    file=sys.stderr,
                )
                print(f"请只传入 slug 正文，例如 --slug {m.group(3)}。", file=sys.stderr)
                return 1

    dir_name = f"{date_prefix}-{slug}"
    task_dir = tasks_dir / dir_name
    task_json_path = task_dir / FILE_TASK_JSON

    archived_task_dir = _find_archived_task_by_dir_name(tasks_dir, dir_name)
    if archived_task_dir:
        print(colored(f"错误：任务已归档：{dir_name}。", Colors.RED), file=sys.stderr)
        print(f"归档位置：{_repo_relative_path(archived_task_dir, repo_root)}", file=sys.stderr)
        print("如果要创建新任务，请使用新的 slug。", file=sys.stderr)
        return 1

    if task_dir.exists():
        print(colored(f"警告：任务目录已存在：{dir_name}。", Colors.YELLOW), file=sys.stderr)
    else:
        task_dir.mkdir(parents=True)

    today = datetime.now().strftime("%Y-%m-%d")

    # 记录 PR 目标 branch。优先使用仓库实际默认 branch（origin/HEAD），避免从 feature
    # branch 创建任务时误把 feature branch 记录为 PR 目标（#399 第 1 项）。默认 branch
    # 无法解析时（未配置 remote、离线等）回退到当前检出的 branch，保持既有行为。
    # 两者都不合适时可用 --base-branch 覆盖。
    _, branch_out, _ = run_git(["branch", "--show-current"], cwd=repo_root)
    current_branch = branch_out.strip() or "main"
    explicit_base_branch: str | None = getattr(args, "base_branch", None)
    if explicit_base_branch:
        base_branch = explicit_base_branch
    else:
        resolved_base_branch = resolve_default_branch(repo_root)
        if resolved_base_branch:
            base_branch = resolved_base_branch
        else:
            base_branch = current_branch
            print(
                colored(
                    f"警告：无法解析仓库默认 branch（未配置 remote、离线等）；"
                    f"base_branch 将记录为当前检出分支 '{base_branch}'。可用 --base-branch 覆盖。",
                    Colors.YELLOW,
                ),
                file=sys.stderr,
            )

    description = (args.description or "").strip()
    if not description.strip():
        print(
            colored(
                "警告：task description 为空；请使用 --description，便于检索和后续审计。",
                Colors.YELLOW,
            ),
            file=sys.stderr,
        )

    task_data = {
        "id": slug,
        "name": slug,
        "title": args.title,
        "description": description,
        "status": "planning",
        "dev_type": None,
        "scope": None,
        "package": package,
        "priority": args.priority,
        "creator": creator,
        "assignee": assignee,
        "createdAt": today,
        "completedAt": None,
        "branch": None,
        "base_branch": base_branch,
        "worktree_path": None,
        "commit": None,
        "pr_url": None,
        "subtasks": [],
        "children": [],
        "parent": None,
        "relatedFiles": [],
        "notes": "",
        "meta": meta,
    }

    write_json(task_json_path, task_data)

    prd_path = task_dir / "prd.md"
    if not prd_path.exists():
        prd_path.write_text(
            _default_prd_content(args.title, description),
            encoding="utf-8",
        )

    # 为支持 sub-agent 的平台生成 implement.jsonl / check.jsonl seed。
    # 任务需要上下文时，AI 会在规划阶段整理真实条目。
    # 无 agent 的平台（Kilo / Antigravity / Devin）跳过此步骤，通过 trellis-before-dev
    # skill 而不是 JSONL 加载 spec。
    seeded_jsonl = False
    if _has_subagent_platform(repo_root):
        for jsonl_name in ("implement.jsonl", "check.jsonl"):
            jsonl_path = task_dir / jsonl_name
            if not jsonl_path.exists():
                _write_seed_jsonl(jsonl_path)
        seeded_jsonl = True

    # 处理 --parent：建立双向关联。
    if args.parent:
        parent_dir = resolve_task_dir(args.parent, repo_root)
        parent_json_path = parent_dir / FILE_TASK_JSON
        if not parent_json_path.is_file():
            print(colored(f"警告：找不到父任务 task.json：{args.parent}。", Colors.YELLOW), file=sys.stderr)
        else:
            parent_data = read_json(parent_json_path)
            if parent_data:
                # 将 child 添加到 parent 的 children 列表。
                parent_children = parent_data.get("children", [])
                if dir_name not in parent_children:
                    parent_children.append(dir_name)
                    parent_data["children"] = parent_children
                    write_json(parent_json_path, parent_data)

                # 在 child 的 task.json 设置 parent。
                task_data["parent"] = parent_dir.name
                write_json(task_json_path, task_data)

                print(colored(f"已关联为子任务：{parent_dir.name}。", Colors.GREEN), file=sys.stderr)

    # 自动激活新任务，使每轮 breadcrumb 进入 planning 状态。尽力而为：没有 session
    # identity（在 AI session 外运行 CLI）时平滑降级——任务仍会创建，用户之后可运行
    # task.py start。指针按 session 隔离，因此不会影响其他 AI session。
    if getattr(args, "no_start", False):
        print(
            colored(
                "已跳过 session 激活（--no-start）；准备好后运行 task.py start。",
                Colors.YELLOW,
            ),
            file=sys.stderr,
        )
    else:
        try:
            from .active_task import resolve_context_key, set_active_task
        except Exception as exc:
            print(
                colored(f"警告：无法激活 session（导入失败：{exc}）。", Colors.YELLOW),
                file=sys.stderr,
            )
        else:
            try:
                context_key = resolve_context_key()
            except Exception as exc:
                print(
                    colored(f"警告：session 激活失败（context 解析：{exc}）。", Colors.YELLOW),
                    file=sys.stderr,
                )
            else:
                # 没有 session identity 是在 AI session 外运行 CLI 的正常情况（见上方说明），
                # 保持静默，不视为失败。
                if context_key:
                    try:
                        rel_dir = task_dir.relative_to(repo_root).as_posix()
                    except ValueError:
                        rel_dir = str(task_dir)
                    try:
                        active = set_active_task(rel_dir, repo_root)
                    except Exception as exc:
                        print(
                            colored(f"警告：session 激活失败（pointer 持久化：{exc}）。", Colors.YELLOW),
                            file=sys.stderr,
                        )
                    else:
                        if active:
                            print(
                                colored(f"已为当前 session 激活任务：{active.task_path}", Colors.GREEN),
                                file=sys.stderr,
                            )
                            print(f"来源：{active.source}", file=sys.stderr)
                        else:
                            print(
                                colored("警告：session 激活失败（没有返回 pointer）。", Colors.YELLOW),
                                file=sys.stderr,
                            )

    print(colored(f"已创建任务：{dir_name}", Colors.GREEN), file=sys.stderr)
    print("", file=sys.stderr)
    print(colored("后续步骤：", Colors.BLUE), file=sys.stderr)
    print("  - 在 prd.md 中填写需求和验收标准。", file=sys.stderr)
    print("  - 轻量任务：只保留 PRD 即可。", file=sys.stderr)
    print("  - 复杂任务：在 task.py start 前补充 design.md 和 implement.md。", file=sys.stderr)
    if seeded_jsonl:
        print(
            "  - 需要 sub-agent 上下文时，整理 implement.jsonl / check.jsonl，仅引用 spec/research。",
            file=sys.stderr,
        )
    print("  - 使用 /trellis:continue 或 phase context 判断下一步。", file=sys.stderr)
    print("", file=sys.stderr)

    # 输出相对路径，供脚本串联。
    print(f"{DIR_WORKFLOW}/{DIR_TASKS}/{dir_name}")

    run_task_hooks("after_create", task_json_path, repo_root)
    return 0


# =============================================================================
# 命令：archive
# =============================================================================

def cmd_archive(args: argparse.Namespace) -> int:
    """归档已完成任务。"""
    repo_root = get_repo_root()
    task_name = args.name

    if not task_name:
        print(colored("错误：必须提供任务名称。", Colors.RED), file=sys.stderr)
        return 1

    tasks_dir = get_tasks_dir(repo_root)

    # 解析任务目录（支持任务名称、相对路径或绝对路径）。
    task_dir = resolve_task_dir(task_name, repo_root)

    if not task_dir or not task_dir.is_dir():
        print(colored(f"错误：找不到任务：{task_name}。", Colors.RED), file=sys.stderr)
        print("当前活动任务：", file=sys.stderr)
        # 延迟导入，避免循环依赖。
        from .tasks import iter_active_tasks
        for t in iter_active_tasks(tasks_dir):
            print(f"  - {t.dir_name}/", file=sys.stderr)
        return 1

    # 拒绝归档不在 .trellis/tasks/ 直接层级下的目录。误输入名称（例如 "src"）可能解析
    # 为 repo_root/src；它虽是目录却不是任务。没有此保护，archive 会把用户源码目录移出仓库。
    if not is_within_tasks_dir(task_dir, repo_root):
        print(colored(
            f"错误：拒绝归档 '{task_name}'：{task_dir} 不在任务目录 {tasks_dir} 下。",
            Colors.RED), file=sys.stderr)
        return 1

    dir_name = task_dir.name
    task_json_path = task_dir / FILE_TASK_JSON

    # 归档前先更新 status。
    today = datetime.now().strftime("%Y-%m-%d")
    # 下面会修改其 task.json 的子任务目录名称；传给 safe_archive_paths_to_add，确保本次
    # commit 一并 stage。
    modified_children: list[str] = []
    if task_json_path.is_file():
        data = read_json(task_json_path)
        if data:
            # 记录的 branch 过期时只警告、不阻塞；它很可能已经合并并删除
            # （#399 第 2 项）。
            stored_branch = data.get("branch")
            if stored_branch and not branch_exists_locally(stored_branch, repo_root):
                print(
                    colored(
                        f"警告：记录的 branch '{stored_branch}' 已不存在于本地（可能已合并并删除）。",
                        Colors.YELLOW,
                    ),
                    file=sys.stderr,
                )

            data["status"] = "completed"
            data["completedAt"] = today
            write_json(task_json_path, data)

            # 处理归档时的子任务关系。保留该任务在 parent 的 children 列表中，使进度计数
            # （children_progress）保持一致；不在活动集合中的 child 视为已完成。
            task_children = data.get("children", [])

            # 如果这是 parent，清除所有 child 的 parent 字段。
            if task_children:
                for child_name in task_children:
                    child_dir_path = find_task_by_name(child_name, tasks_dir)
                    if child_dir_path:
                        child_json = child_dir_path / FILE_TASK_JSON
                        if child_json.is_file():
                            child_data = read_json(child_json)
                            if child_data:
                                child_data["parent"] = None
                                write_json(child_json, child_data)
                                modified_children.append(child_dir_path.name)

    # 移动路径前清除仍指向此任务的 session。
    from .active_task import clear_task_from_sessions
    clear_task_from_sessions(str(task_dir), repo_root)

    # 执行归档。
    result = archive_task_complete(task_dir, repo_root)
    if "archived_to" in result:
        archive_dest = Path(result["archived_to"])
        year_month = archive_dest.parent.name
        print(colored(f"已归档：{dir_name} -> archive/{year_month}/", Colors.GREEN), file=sys.stderr)

        # 除非指定 --no-commit，否则自动提交。
        if not getattr(args, "no_commit", False):
            if not _auto_commit_archive(dir_name, repo_root, modified_children):
                print(
                    colored(
                        "归档目录已在磁盘移动，但 Git 自动提交未完成。"
                        "请先处理 `git status` 再继续。",
                        Colors.RED,
                    ),
                    file=sys.stderr,
                )
                return 1

        # 返回归档路径。
        print(f"{DIR_WORKFLOW}/{DIR_TASKS}/{DIR_ARCHIVE}/{year_month}/{dir_name}")

        # 使用归档后的路径运行 hooks。
        archived_json = archive_dest / FILE_TASK_JSON
        run_task_hooks("after_archive", archived_json, repo_root)
        return 0

    return 1


def _auto_commit_archive(
    task_name: str,
    repo_root: Path,
    modified_children: list[str] | None = None,
) -> bool:
    """stage Trellis 所有的任务路径，并在归档后提交。

    范围严格限制为已归档任务的源路径和目标路径，以及 task.json 被编辑的 child 任务目录
    （parent → children 关系更新）。其他活动任务目录中的脏变更不会打包进归档 commit。

    如果 ``.gitignore`` 阻止这些路径，则警告并跳过，绝不使用 ``git add -f`` 重试。警告会
    明确禁止 ``git add -f .trellis/``（它会扩散到缓存/备份），并提示用户设置
    ``session_auto_commit: false``。

    遵循 ``.trellis/config.yaml`` 中的 ``session_auto_commit``：设置为 ``false`` 时立即
    返回，不触碰 git（磁盘上的 archive 目录移动不受影响）。
    """
    if not get_session_auto_commit(repo_root):
        print(
            "[OK] session_auto_commit: false — 跳过 Git stage/commit。",
            file=sys.stderr,
        )
        return True

    source_rel = f"{DIR_WORKFLOW}/{DIR_TASKS}/{task_name}"
    rc, tracked_out, _ = run_git(
        ["ls-files", "--", source_rel],
        cwd=repo_root,
    )
    source_was_tracked = rc == 0 and bool(tracked_out.strip())

    paths = safe_archive_paths_to_add(
        repo_root, task_name=task_name, modified_children=modified_children
    )
    if not paths:
        print("[OK] 没有需要提交的任务变更。", file=sys.stderr)
        return True

    success, _, err = safe_git_add(paths, repo_root)
    if not success:
        if err and "ignored by" in err.lower():
            print_gitignore_warning(paths)
        else:
            print(
                f"[WARN] git add 失败：{err.strip() if err else '未知错误'}",
                file=sys.stderr,
            )
        return not source_was_tracked

    # 为 phantom-delete bug 加双保险：`safe_git_add` 使用 `git add`（不带 -A），只会 stage
    # 新增/修改。源任务目录已由 `shutil.move` 移走，因此必须显式执行 `git rm --cached`
    # 来在同一 commit 中 stage 删除；否则它们会一直以相对 HEAD 的未提交“phantom delete”
    # 留在工作树，直到之后的操作碰巧拾取。
    #
    # 任务从未被跟踪时（例如只存在于工作树的任务），`--ignore-unmatch` 会使此操作无害。
    run_git(
        ["rm", "-r", "--cached", "--ignore-unmatch", "--", source_rel],
        cwd=repo_root,
    )

    rc, _, _ = run_git(
        ["diff", "--cached", "--quiet", "--", *paths, source_rel],
        cwd=repo_root,
    )
    if rc == 0:
        print("[OK] 没有需要提交的任务变更。", file=sys.stderr)
        return True

    commit_msg = f"chore(task): archive {task_name}"
    rc, _, err = run_git(["commit", "-m", commit_msg], cwd=repo_root)
    if rc == 0:
        print(f"[OK] 已自动提交：{commit_msg}", file=sys.stderr)
        return True
    else:
        print(f"[WARN] 自动提交失败：{err.strip()}", file=sys.stderr)
        return not source_was_tracked


# =============================================================================
# 命令：add-subtask
# =============================================================================

def cmd_add_subtask(args: argparse.Namespace) -> int:
    """将 child 任务关联到 parent 任务。"""
    repo_root = get_repo_root()

    parent_dir = resolve_task_dir(args.parent_dir, repo_root)
    child_dir = resolve_task_dir(args.child_dir, repo_root)

    parent_json_path = parent_dir / FILE_TASK_JSON
    child_json_path = child_dir / FILE_TASK_JSON

    if not parent_json_path.is_file():
        print(colored(f"错误：找不到父任务 task.json：{args.parent_dir}。", Colors.RED), file=sys.stderr)
        return 1

    if not child_json_path.is_file():
        print(colored(f"错误：找不到子任务 task.json：{args.child_dir}。", Colors.RED), file=sys.stderr)
        return 1

    parent_data = read_json(parent_json_path)
    child_data = read_json(child_json_path)

    if not parent_data or not child_data:
        print(colored("错误：读取 task.json 失败。", Colors.RED), file=sys.stderr)
        return 1

    # 检查 child 是否已有 parent。
    existing_parent = child_data.get("parent")
    if existing_parent:
        print(colored(f"错误：子任务已有父任务：{existing_parent}。", Colors.RED), file=sys.stderr)
        return 1

    # 将 child 添加到 parent 的 children 列表。
    parent_children = parent_data.get("children", [])
    child_dir_name = child_dir.name
    if child_dir_name not in parent_children:
        parent_children.append(child_dir_name)
        parent_data["children"] = parent_children

    # 在 child 的 task.json 设置 parent。
    child_data["parent"] = parent_dir.name

    # 写回两个 task.json。
    write_json(parent_json_path, parent_data)
    write_json(child_json_path, child_data)

    print(colored(f"已关联：{child_dir.name} -> {parent_dir.name}", Colors.GREEN), file=sys.stderr)
    return 0


# =============================================================================
# 命令：remove-subtask
# =============================================================================

def cmd_remove_subtask(args: argparse.Namespace) -> int:
    """解除 child 任务与 parent 任务的关联。"""
    repo_root = get_repo_root()

    parent_dir = resolve_task_dir(args.parent_dir, repo_root)
    child_dir = resolve_task_dir(args.child_dir, repo_root)

    parent_json_path = parent_dir / FILE_TASK_JSON
    child_json_path = child_dir / FILE_TASK_JSON

    if not parent_json_path.is_file():
        print(colored(f"错误：找不到父任务 task.json：{args.parent_dir}。", Colors.RED), file=sys.stderr)
        return 1

    if not child_json_path.is_file():
        print(colored(f"错误：找不到子任务 task.json：{args.child_dir}。", Colors.RED), file=sys.stderr)
        return 1

    parent_data = read_json(parent_json_path)
    child_data = read_json(child_json_path)

    if not parent_data or not child_data:
        print(colored("错误：读取 task.json 失败。", Colors.RED), file=sys.stderr)
        return 1

    # 从 parent 的 children 列表移除 child。
    parent_children = parent_data.get("children", [])
    child_dir_name = child_dir.name
    if child_dir_name in parent_children:
        parent_children.remove(child_dir_name)
        parent_data["children"] = parent_children

    # 清除 child 的 task.json 中的 parent。
    child_data["parent"] = None

    # 写回两个 task.json。
    write_json(parent_json_path, parent_data)
    write_json(child_json_path, child_data)

    print(colored(f"已解除关联：{child_dir.name} <- {parent_dir.name}", Colors.GREEN), file=sys.stderr)
    return 0


# =============================================================================
# 命令：set-branch
# =============================================================================

def cmd_set_branch(args: argparse.Namespace) -> int:
    """为任务设置 git branch。"""
    repo_root = get_repo_root()
    target_dir = resolve_task_dir(args.dir, repo_root)
    branch = args.branch

    if not branch:
        print(colored("错误：缺少参数。", Colors.RED))
        print("用法：python3 task.py set-branch <task-dir> <branch-name>")
        return 1

    task_json = target_dir / FILE_TASK_JSON
    if not task_json.is_file():
        print(colored(f"错误：{target_dir} 下找不到 task.json。", Colors.RED))
        return 1

    data = read_json(task_json)
    if not data:
        return 1

    data["branch"] = branch
    write_json(task_json, data)

    print(colored(f"✓ branch 已设置为：{branch}", Colors.GREEN))
    return 0


# =============================================================================
# 命令：set-base-branch
# =============================================================================

def cmd_set_base_branch(args: argparse.Namespace) -> int:
    """为任务设置 base branch（PR 目标）。"""
    repo_root = get_repo_root()
    target_dir = resolve_task_dir(args.dir, repo_root)
    base_branch = args.base_branch

    if not base_branch:
        print(colored("错误：缺少参数。", Colors.RED))
        print("用法：python3 task.py set-base-branch <task-dir> <base-branch>")
        print("示例：python3 task.py set-base-branch <dir> develop")
        print()
        print("此命令设置 PR 的目标 branch（功能将合并到的分支）。")
        return 1

    task_json = target_dir / FILE_TASK_JSON
    if not task_json.is_file():
        print(colored(f"错误：{target_dir} 下找不到 task.json。", Colors.RED))
        return 1

    data = read_json(task_json)
    if not data:
        return 1

    data["base_branch"] = base_branch
    write_json(task_json, data)

    print(colored(f"✓ base branch 已设置为：{base_branch}", Colors.GREEN))
    print(f"  PR 目标：{base_branch}")
    return 0


# =============================================================================
# 命令：set-scope
# =============================================================================

def cmd_set_scope(args: argparse.Namespace) -> int:
    """设置 PR 标题使用的 scope。"""
    repo_root = get_repo_root()
    target_dir = resolve_task_dir(args.dir, repo_root)
    scope = args.scope

    if not scope:
        print(colored("错误：缺少参数。", Colors.RED))
        print("用法：python3 task.py set-scope <task-dir> <scope>")
        return 1

    task_json = target_dir / FILE_TASK_JSON
    if not task_json.is_file():
        print(colored(f"错误：{target_dir} 下找不到 task.json。", Colors.RED))
        return 1

    data = read_json(task_json)
    if not data:
        return 1

    data["scope"] = scope
    write_json(task_json, data)

    print(colored(f"✓ scope 已设置为：{scope}", Colors.GREEN))
    return 0


# =============================================================================
# 命令：set-meta
# =============================================================================

def cmd_set_meta(args: argparse.Namespace) -> int:
    """在已有任务上设置或覆盖一个 metadata key。"""
    repo_root = get_repo_root()
    target_dir = resolve_task_dir(args.dir, repo_root)
    key = args.key
    value = args.value

    if not key:
        print(colored("错误：缺少参数。", Colors.RED))
        print("用法：python3 task.py set-meta <task-dir> <key> <value>")
        return 1

    task_json = target_dir / FILE_TASK_JSON
    if not task_json.is_file():
        print(colored(f"错误：{target_dir} 下找不到 task.json。", Colors.RED))
        return 1

    data = read_json(task_json)
    if not data:
        return 1

    meta = data.get("meta")
    if not isinstance(meta, dict):
        meta = {}
    meta[key] = value
    data["meta"] = meta
    write_json(task_json, data)

    print(colored(f"✓ metadata 已设置：{key} = {value}", Colors.GREEN))
    return 0
