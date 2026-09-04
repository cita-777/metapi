#!/usr/bin/env python3
"""
任务 JSONL 上下文管理。

提供：
    cmd_add_context   - 向 JSONL 上下文文件添加条目
    cmd_validate      - 校验 JSONL 上下文文件
    cmd_list_context  - 列出 JSONL 上下文条目

说明：
    ``cmd_init_context`` 已在 v0.5.0-beta.12 移除。现在 JSONL 上下文文件会在
    ``task.py create`` 时写入自描述的 ``_example`` 行；任务需要 sub-agent/spec
    上下文时，由 AI 在规划阶段整理真实条目。当前规划产物契约见
    ``.trellis/workflow.md``。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import get_context_injection_limits
from .git import branch_exists_locally
from .io import read_json
from .log import Colors, colored
from .paths import DIR_ARCHIVE, DIR_TASKS, DIR_WORKFLOW, FILE_TASK_JSON, get_repo_root
from .task_utils import resolve_task_dir

# 这些扩展名表示代码，而不是 spec/research 文档。具有这些扩展名、且不位于
# .trellis/spec/、docs/docs-site 或任务自身目录的条目，会在 `task.py validate` 中
# 触发卫生警告。读取者是 sub-agent，不是人；代码路径应由 agent 从 diff 自行读取，
# 不应放进 implement.jsonl / check.jsonl。
_CODE_FILE_EXTENSIONS = {
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".py",
    ".go",
    ".rs",
    ".java",
    ".rb",
    ".c",
    ".cc",
    ".cpp",
    ".h",
}


# =============================================================================
# 命令：add-context
# =============================================================================

def cmd_add_context(args: argparse.Namespace) -> int:
    """向 JSONL 上下文文件添加条目。"""
    repo_root = get_repo_root()
    target_dir = resolve_task_dir(args.dir, repo_root)

    jsonl_name = args.file
    path = args.path
    reason = args.reason or "手动添加"

    if not target_dir.is_dir():
        print(colored(f"错误：找不到目录：{target_dir}。", Colors.RED))
        return 1

    # 支持简写。
    if not jsonl_name.endswith(".jsonl"):
        jsonl_name = f"{jsonl_name}.jsonl"

    jsonl_file = target_dir / jsonl_name
    full_path = repo_root / path

    entry_type = "file"
    if full_path.is_dir():
        entry_type = "directory"
        if not path.endswith("/"):
            path = f"{path}/"
    elif not full_path.is_file():
        print(colored(f"错误：找不到路径：{path}。", Colors.RED))
        return 1

    # 检查条目是否已存在。
    if jsonl_file.is_file():
        content = jsonl_file.read_text(encoding="utf-8")
        if f'"{path}"' in content:
            print(colored(f"警告：条目已存在：{path}。", Colors.YELLOW))
            return 0

    # 添加条目。
    entry: dict
    if entry_type == "directory":
        entry = {"file": path, "type": "directory", "reason": reason}
    else:
        entry = {"file": path, "reason": reason}

    with jsonl_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    type_label = "目录" if entry_type == "directory" else "文件"
    print(colored(f"已添加{type_label}：{path}", Colors.GREEN))
    return 0


# =============================================================================
# 命令：validate
# =============================================================================

def cmd_validate(args: argparse.Namespace) -> int:
    """校验 JSONL 上下文文件。"""
    repo_root = get_repo_root()
    target_dir = resolve_task_dir(args.dir, repo_root)

    if not target_dir.is_dir():
        print(colored("错误：必须提供任务目录。", Colors.RED))
        return 1

    print(colored("=== 校验上下文文件 ===", Colors.BLUE))
    print(f"目标目录：{target_dir}")
    print()

    # 记录的 branch 过期时只警告，不让校验失败；它很可能已经合并并删除
    # （#399 第 2 项）。
    task_json_path = target_dir / FILE_TASK_JSON
    if task_json_path.is_file():
        task_data = read_json(task_json_path)
        stored_branch = task_data.get("branch") if task_data else None
        if stored_branch and not branch_exists_locally(stored_branch, repo_root):
            print(
                colored(
                    f"警告：记录的 branch '{stored_branch}' 已不存在于本地（可能已合并并删除）。",
                    Colors.YELLOW,
                )
            )
            print()

    total_errors = 0
    for jsonl_name in ["implement.jsonl", "check.jsonl"]:
        jsonl_file = target_dir / jsonl_name
        errors = _validate_jsonl(jsonl_file, repo_root, target_dir)
        total_errors += errors

    print()
    if total_errors == 0:
        print(colored("✓ 所有校验均已通过。", Colors.GREEN))
        return 0
    else:
        print(colored(f"✗ 校验失败（{total_errors} 个错误）。", Colors.RED))
        return 1


def _is_exempt_from_code_file_warning(file_path: str, task_rel: str) -> bool:
    """判断 JSONL 条目路径是否豁免代码文件卫生警告。

    豁免范围：规范文档（``.trellis/spec/``）、文档目录（``docs``、``docs-site``）
    以及任务自身目录（执行计划和生成产物可以合法放在此处）。
    """
    posix_path = file_path.replace("\\", "/").lstrip("/")
    exempt_prefixes = (".trellis/spec/", "docs/", "docs-site/")
    if posix_path.startswith(exempt_prefixes):
        return True
    if task_rel and (posix_path == task_rel or posix_path.startswith(f"{task_rel}/")):
        return True
    return False


def _resolve_context_entry_path(
    file_path: str, repo_root: Path, task_dir: Path | None
) -> Path | None:
    """解析 JSONL 条目，并将归档任务的自身引用绑定到归档副本。

    只有归档任务的历史自身引用会重映射。``None`` 表示重映射后的路径越界，或
    解析到了归档目录之外。
    """
    repo_path = repo_root / file_path
    if task_dir is None:
        return repo_path

    try:
        task_parts = task_dir.resolve().relative_to(repo_root.resolve()).parts
    except ValueError:
        return repo_path

    archive_prefix = (DIR_WORKFLOW, DIR_TASKS, DIR_ARCHIVE)
    if len(task_parts) != 5 or task_parts[:3] != archive_prefix:
        return repo_path

    year_month = task_parts[3]
    if (
        len(year_month) != 7
        or year_month[4] != "-"
        or not year_month[:4].isdigit()
        or not year_month[5:].isdigit()
    ):
        return repo_path

    historical_root = f"{DIR_WORKFLOW}/{DIR_TASKS}/{task_dir.name}"
    posix_path = file_path.replace("\\", "/")
    if posix_path == historical_root:
        relative_parts: tuple[str, ...] = ()
    elif posix_path.startswith(f"{historical_root}/"):
        relative_path = posix_path[len(historical_root) + 1 :]
        if relative_path.endswith("/"):
            relative_path = relative_path[:-1]
        relative_parts = tuple(relative_path.split("/")) if relative_path else ()
        if any(part in ("", ".", "..") for part in relative_parts):
            return None
    else:
        return repo_path

    try:
        archive_root = task_dir.resolve()
        resolved_path = task_dir.joinpath(*relative_parts).resolve()
        resolved_path.relative_to(archive_root)
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved_path


def _validate_jsonl(jsonl_file: Path, repo_root: Path, task_dir: Path | None = None) -> int:
    """校验单个 JSONL 文件。

    seed 行（没有 ``file`` 字段，通常是 ``{"_example": "..."}``）会静默跳过；
    它们是自描述注释，不是真实条目。

    除了缺失文件/目录、非法 JSON 等硬错误，还会输出不阻塞流程的卫生警告
    （不计入 ``errors``，也不改变退出码）：看起来像代码文件而非 spec/research
    文档的条目，以及超过 sub-agent 上下文注入上限
    （``context_injection.max_file_bytes``）的条目。
    """
    file_name = jsonl_file.name
    errors = 0

    if not jsonl_file.is_file():
        print(f"  {colored(f'{file_name}：找不到（已跳过）', Colors.YELLOW)}")
        return 0

    task_rel = ""
    if task_dir is not None:
        try:
            task_rel = task_dir.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            task_rel = ""

    max_file_bytes = get_context_injection_limits(repo_root).get("max_file_bytes", 0)

    line_num = 0
    real_entries = 0
    for line in jsonl_file.read_text(encoding="utf-8").splitlines():
        line_num += 1
        if not line.strip():
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            print(f"  {colored(f'{file_name}:{line_num}：JSON 无效', Colors.RED)}")
            errors += 1
            continue

        file_path = data.get("file")
        entry_type = data.get("type", "file")

        if not file_path:
            # seed / 注释行：静默跳过。
            continue

        real_entries += 1
        full_path = _resolve_context_entry_path(file_path, repo_root, task_dir)
        if entry_type == "directory":
            if full_path is None or not full_path.is_dir():
                print(f"  {colored(f'{file_name}:{line_num}：找不到目录：{file_path}', Colors.RED)}")
                errors += 1
            continue

        if full_path is None or not full_path.is_file():
            print(f"  {colored(f'{file_name}:{line_num}：找不到文件：{file_path}', Colors.RED)}")
            errors += 1
            continue

        extension = Path(file_path).suffix.lower()
        if extension in _CODE_FILE_EXTENSIONS and not _is_exempt_from_code_file_warning(
            file_path, task_rel
        ):
            warning_message = (
                f"{file_name}:{line_num}：警告：{file_path} 看起来是代码文件；"
                "implement/check.jsonl 应引用 spec/research 文档，agent 会自行读取代码"
            )
            print(f"  {colored(warning_message, Colors.YELLOW)}")

        if max_file_bytes:
            size = full_path.stat().st_size
            if size > max_file_bytes:
                warning_message = (
                    f"{file_name}:{line_num}：警告：{file_path} 为 {size} 字节，"
                    f"超过 context_injection.max_file_bytes（{max_file_bytes}）；注入时会截断"
                )
                print(f"  {colored(warning_message, Colors.YELLOW)}")

    if errors == 0:
        print(f"  {colored(f'{file_name}：✓（{real_entries} 个条目）', Colors.GREEN)}")
    else:
        print(f"  {colored(f'{file_name}：✗（{errors} 个错误）', Colors.RED)}")

    return errors


# =============================================================================
# 命令：list-context
# =============================================================================

def cmd_list_context(args: argparse.Namespace) -> int:
    """列出 JSONL 上下文条目。"""
    repo_root = get_repo_root()
    target_dir = resolve_task_dir(args.dir, repo_root)

    if not target_dir.is_dir():
        print(colored("错误：必须提供任务目录。", Colors.RED))
        return 1

    print(colored("=== 上下文文件 ===", Colors.BLUE))
    print()

    for jsonl_name in ["implement.jsonl", "check.jsonl"]:
        jsonl_file = target_dir / jsonl_name
        if not jsonl_file.is_file():
            continue

        print(colored(f"[{jsonl_name}]", Colors.CYAN))

        count = 0
        seed_only = True
        for line in jsonl_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            file_path = data.get("file")
            if not file_path:
                # seed / 注释行：不计为真实条目。
                continue
            seed_only = False

            count += 1
            entry_type = data.get("type", "file")
            reason = data.get("reason", "-")

            if entry_type == "directory":
                print(f"  {colored(f'{count}.', Colors.GREEN)} [DIR] {file_path}")
            else:
                print(f"  {colored(f'{count}.', Colors.GREEN)} {file_path}")
            print(f"     {colored('→', Colors.YELLOW)} {reason}")

        if seed_only:
            print(f"  {colored('（尚无整理后的条目，目前只有 seed 行）', Colors.YELLOW)}")

        print()

    return 0
