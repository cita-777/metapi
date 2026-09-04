#!/usr/bin/env python3
"""
Trellis 配置读取器。

从 .trellis/config.yaml 读取设置；缺失时使用合理的默认值。
"""

from __future__ import annotations

import sys
from pathlib import Path

from .paths import DIR_WORKFLOW, get_repo_root


# =============================================================================
# 简化 YAML 解析器（无外部依赖）
# =============================================================================


def _unquote(s: str) -> str:
    """去掉一层匹配的外层引号。

    与 str.strip('"') 不同，本函数只移除最外层的一对引号，保留值内部的嵌套引号。

    示例：
        _unquote('"hello"')        -> 'hello'
        _unquote("'hello'")        -> 'hello'
        _unquote('"echo \\'hi\\'"')  -> "echo 'hi'"
        _unquote('hello')          -> 'hello'
        _unquote('"hello\\'')       -> '"hello\\''  （引号不匹配，保持原值）
    """
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s


def _strip_inline_comment(value: str) -> str:
    """去掉 ` # …` 行内注释，同时保留引号字符串中的 `#`。

    YAML 将 ` #`（空格加井号）视为注释起始；token 内未带前置空格的 `#` 属于值的一部分，
    引号字符串不受影响。

    与 :func:`common.trellis_config._strip_inline_comment` 保持一致，确保两个 parser
    对 ``key: value  # comment`` 的处理相同。
    """
    in_quote: str | None = None
    for idx, ch in enumerate(value):
        if in_quote:
            if ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'"):
            in_quote = ch
            continue
        if ch == "#" and (idx == 0 or value[idx - 1].isspace()):
            return value[:idx]
    return value


def parse_simple_yaml(content: str) -> dict:
    """解析支持嵌套 dict 的简化 YAML（无外部依赖）。

    支持：
        - key: value（字符串）
        - key:（后续为列表项）
            - item1
            - item2
        - key:（后续为嵌套 dict）
            nested_key: value
            nested_key2:
              - item

    使用缩进识别嵌套（多缩进至少 2 个空格表示子级）。

    参数：
        content：YAML 内容字符串。

    返回：
        解析后的 dict（值可以是 str、list[str] 或 dict）。
    """
    lines = content.splitlines()
    result: dict = {}
    _parse_yaml_block(lines, 0, 0, result)
    return result


def _parse_yaml_block(
    lines: list[str], start: int, min_indent: int, target: dict
) -> int:
    """将 YAML block 解析到 target dict，并返回下一行索引。"""
    i = start
    current_list: list | None = None

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # 跳过空行和注释。
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # 计算缩进。
        indent = len(line) - len(line.lstrip())

        # 如果缩进退回到 block 之外，解析结束。
        if indent < min_indent:
            break

        if stripped.startswith("- "):
            if current_list is not None:
                current_list.append(_unquote(stripped[2:].strip()))
            i += 1
        elif ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = _strip_inline_comment(value).strip()
            was_quoted = len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'")
            value = _unquote(value)
            current_list = None

            if value or was_quoted:
                # key: value（显式写出的引号空字符串是值，不是“无值”）。
                target[key] = value
                i += 1
            else:
                # key:（无值）——查看后续内容，判断是 list 还是嵌套 dict。
                next_i, next_line = _next_content_line(lines, i + 1)
                if next_i >= len(lines):
                    target[key] = {}
                    i = next_i
                elif next_line.strip().startswith("- "):
                    # 这是 list。
                    current_list = []
                    target[key] = current_list
                    i += 1
                else:
                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_indent > indent:
                        # 这是嵌套 dict。
                        nested: dict = {}
                        target[key] = nested
                        i = _parse_yaml_block(lines, i + 1, next_indent, nested)
                    else:
                        # 值为空，后续行缩进相同或更少。
                        target[key] = {}
                        i += 1
        else:
            i += 1

    return i


def _next_content_line(lines: list[str], start: int) -> tuple[int, str]:
    """查找下一行非空且非注释的内容。"""
    i = start
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped and not stripped.startswith("#"):
            return i, lines[i]
        i += 1
    return i, ""


# 默认值
DEFAULT_SESSION_COMMIT_MESSAGE = "chore: record journal"
DEFAULT_MAX_JOURNAL_LINES = 2000
DEFAULT_SESSION_AUTO_COMMIT = True
DEFAULT_CODEX_DISPATCH_MODE = "auto"

CONFIG_FILE = "config.yaml"


def _is_true_config_value(value: object) -> bool:
    """当配置值表示启用 flag 时返回 True。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _get_config_path(repo_root: Path | None = None) -> Path:
    """获取 config.yaml 路径。"""
    root = repo_root or get_repo_root()
    return root / DIR_WORKFLOW / CONFIG_FILE


def _load_config(repo_root: Path | None = None) -> dict:
    """加载并解析 config.yaml；发生任意错误时返回空 dict。"""
    config_file = _get_config_path(repo_root)
    try:
        content = config_file.read_text(encoding="utf-8")
        return parse_simple_yaml(content)
    except (OSError, IOError):
        return {}


def get_session_commit_message(repo_root: Path | None = None) -> str:
    """获取自动提交 session 记录时使用的 commit message。"""
    config = _load_config(repo_root)
    return config.get("session_commit_message", DEFAULT_SESSION_COMMIT_MESSAGE)


def get_max_journal_lines(repo_root: Path | None = None) -> int:
    """获取每个 journal 文件允许的最大行数。"""
    config = _load_config(repo_root)
    value = config.get("max_journal_lines", DEFAULT_MAX_JOURNAL_LINES)
    try:
        return int(value)
    except (ValueError, TypeError):
        return DEFAULT_MAX_JOURNAL_LINES


def get_session_auto_commit(repo_root: Path | None = None) -> bool:
    """判断脚本是否应自动 stage 并 commit session/task 变更。

    同时控制 ``add_session.py:_auto_commit_workspace`` 和
    ``task_store.py:_auto_commit_archive``。

    默认值为 ``True``（保持既有的自动 stage + 自动 commit 行为）。在
    ``.trellis/config.yaml`` 设置 ``session_auto_commit: false`` 可完全跳过自动 stage；
    journal/archive 文件仍会写入磁盘，但由用户自行执行 ``git add`` / ``git commit``。

    支持原生 YAML 布尔值（``true`` / ``false``）及字符串别名
    ``true / false / yes / no / 1 / 0 / on / off``（不区分大小写）。无效值会输出 stderr
    警告并回退到 ``True``。
    """
    config = _load_config(repo_root)
    raw = config.get("session_auto_commit", DEFAULT_SESSION_AUTO_COMMIT)
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip().lower()
    if s in ("true", "yes", "1", "on"):
        return True
    if s in ("false", "no", "0", "off"):
        return False
    print(
        f"[WARN] session_auto_commit 值无效：{raw!r}；将使用 true（默认值）",
        file=sys.stderr,
    )
    return DEFAULT_SESSION_AUTO_COMMIT


def get_codex_dispatch_mode(repo_root: Path | None = None) -> str:
    """返回 Codex dispatch mode。

    默认值为 ``auto``：分发 Trellis sub-agent，并使用原生上下文注入和子 agent 侧回退。
    ``inline`` 是显式退出；``sub-agent`` 保留为兼容 ``auto`` 的别名。

    无效的显式配置会回退到 ``inline``，避免意外分发 sub-agent。此 CLI 侧 parser 是
    唯一会为无效值输出警告的位置；hook reader 会安全失败，不在每轮制造警告噪声。
    """
    config = _load_config(repo_root)
    codex = config.get("codex")
    if codex is None:
        return DEFAULT_CODEX_DISPATCH_MODE
    if not isinstance(codex, dict):
        print(
            f"[WARN] codex 配置无效：{codex!r}；将使用 inline",
            file=sys.stderr,
        )
        return "inline"

    raw = codex.get("dispatch_mode", DEFAULT_CODEX_DISPATCH_MODE)
    mode = str(raw).strip().lower()
    if mode in ("auto", "inline"):
        return mode
    if mode == "sub-agent":
        return "auto"
    print(
        f"[WARN] codex.dispatch_mode 值无效：{raw!r}；将使用 inline",
        file=sys.stderr,
    )
    return "inline"


DEFAULT_CONTEXT_INJECTION_MAX_FILE_BYTES = 32768
DEFAULT_CONTEXT_INJECTION_MAX_ARTIFACT_BYTES = 65536
DEFAULT_CONTEXT_INJECTION_MAX_TOTAL_BYTES = 131072


def get_context_injection_limits(repo_root: Path | None = None) -> dict[str, int]:
    """返回 sub-agent 上下文注入的字节上限。

    读取 ``.trellis/config.yaml`` 的 ``context_injection:`` 段：

        context_injection:
          max_file_bytes: 32768
          max_artifact_bytes: 65536
          max_total_bytes: 131072

    ``0`` 会关闭对应限制。缺失键使用默认值；无效值（非 int 或负数）输出 stderr 警告，
    并回退到该键的默认值。
    """
    defaults = {
        "max_file_bytes": DEFAULT_CONTEXT_INJECTION_MAX_FILE_BYTES,
        "max_artifact_bytes": DEFAULT_CONTEXT_INJECTION_MAX_ARTIFACT_BYTES,
        "max_total_bytes": DEFAULT_CONTEXT_INJECTION_MAX_TOTAL_BYTES,
    }

    config = _load_config(repo_root)
    section = config.get("context_injection")
    if not isinstance(section, dict):
        return defaults

    result = dict(defaults)
    for key, default_value in defaults.items():
        if key not in section:
            continue
        raw = section[key]
        try:
            value = int(raw)
        except (TypeError, ValueError):
            print(
                f"[WARN] context_injection.{key} 值无效：{raw!r}；"
                f"将使用默认值 {default_value}",
                file=sys.stderr,
            )
            continue
        if value < 0:
            print(
                f"[WARN] context_injection.{key} 值无效：{raw!r}；"
                f"将使用默认值 {default_value}",
                file=sys.stderr,
            )
            continue
        result[key] = value

    return result


DEFAULT_PROMPT_INJECTION_SKIP_KEYWORD = "no-trellis"


def get_prompt_injection_config(repo_root: Path | None = None) -> dict[str, str]:
    """返回每轮 prompt 注入配置。

    读取 ``.trellis/config.yaml`` 的 ``prompt_injection:`` 段：

        prompt_injection:
    skip_keyword: "no-trellis"   # "" 表示完全关闭 escape hatch

    ``skip_keyword`` 是不区分大小写、按单词边界匹配的关键词。它出现在用户 prompt 中时，
    本轮 workflow-state 注入不输出任何内容。默认值为 ``"no-trellis"``；非字符串值回退到默认值。
    """
    defaults = {"skip_keyword": DEFAULT_PROMPT_INJECTION_SKIP_KEYWORD}

    config = _load_config(repo_root)
    section = config.get("prompt_injection")
    if not isinstance(section, dict):
        return defaults

    result = dict(defaults)
    raw = section.get("skip_keyword", DEFAULT_PROMPT_INJECTION_SKIP_KEYWORD)
    if isinstance(raw, str):
        result["skip_keyword"] = raw
    return result


def get_hooks(event: str, repo_root: Path | None = None) -> list[str]:
    """获取生命周期事件对应的 hook command。

    参数：
        event：事件名称（例如 "after_create"、"after_archive"）。
        repo_root：仓库根路径。

    返回：
        要执行的 shell command 列表；未配置时为空列表。
    """
    config = _load_config(repo_root)
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        return []
    commands = hooks.get(event)
    if isinstance(commands, list):
        return [str(c) for c in commands]
    return []


# =============================================================================
# Monorepo / Package
# =============================================================================


def get_packages(repo_root: Path | None = None) -> dict[str, dict] | None:
    """获取 monorepo package 声明。

    返回：
        package 名称到配置（path、type 等）的映射；未配置时返回 None（single-repo 模式）。

    返回示例：
        {"cli": {"path": "packages/cli"}, "docs-site": {"path": "docs-site", "type": "submodule"}}
    """
    config = _load_config(repo_root)
    packages = config.get("packages")
    if not isinstance(packages, dict):
        return None
    # 确保每个值都是 dict（过滤标量条目）。
    filtered = {k: v for k, v in packages.items() if isinstance(v, dict)}
    if not filtered:
        return None
    return filtered


def get_default_package(repo_root: Path | None = None) -> str | None:
    """获取配置中的默认 package 名称。

    返回：
        package 名称字符串；未配置时返回 None。
    """
    config = _load_config(repo_root)
    value = config.get("default_package")
    return str(value) if value else None


def get_submodule_packages(repo_root: Path | None = None) -> dict[str, str]:
    """获取作为 git submodule 的 package。

    返回：
        submodule 类型 package 的名称到路径映射；未配置时为空 dict。

    返回示例：
        {"docs-site": "docs-site"}
    """
    packages = get_packages(repo_root)
    if packages is None:
        return {}
    return {
        name: cfg.get("path", name)
        for name, cfg in packages.items()
        if cfg.get("type") == "submodule"
    }


def get_git_packages(repo_root: Path | None = None) -> dict[str, str]:
    """获取拥有独立 git 仓库的 package。

    这些是带独立 .git 的子目录（不是 submodule），并在 config.yaml 中标记 ``git: true``。

    返回：
        git-repo package 的名称到路径映射；未配置时为空 dict。

    配置示例：

        packages:
          backend:
            path: iqs
            git: true

    返回示例：

        {"backend": "iqs"}
    """
    packages = get_packages(repo_root)
    if packages is None:
        return {}
    return {
        name: cfg.get("path", name)
        for name, cfg in packages.items()
        if _is_true_config_value(cfg.get("git"))
    }


def is_monorepo(repo_root: Path | None = None) -> bool:
    """检查项目是否配置为 monorepo（config 中存在 package）。"""
    return get_packages(repo_root) is not None


def get_spec_base(package: str | None = None, repo_root: Path | None = None) -> str:
    """获取相对于 .trellis/ 的 spec 目录基路径。

    Single-repo：返回 "spec"。
    带 package 的 monorepo：返回 "spec/<package>"。
    未指定 package 的 monorepo：返回 "spec"（调用方应补充 package）。
    """
    if package and is_monorepo(repo_root):
        return f"spec/{package}"
    return "spec"


def validate_package(package: str, repo_root: Path | None = None) -> bool:
    """检查 package 名称在本项目中是否有效。

    Single-repo（未配置 package）：始终返回 True。
    Monorepo：仅当 package 存在于 config.yaml 的 packages 中时返回 True。
    """
    packages = get_packages(repo_root)
    if packages is None:
        return True  # 单仓库项目无需校验 package。
    return package in packages


def resolve_package(
    task_package: str | None = None,
    repo_root: Path | None = None,
) -> str | None:
    """从推断来源解析并校验 package。

    检查顺序：task_package → default_package。推断值无效时向 stderr 输出警告并跳过。

    返回：
        已解析的 package 名称；找不到有效 package 时返回 None。

    说明：
        CLI --package 应由调用方单独校验（错误时 fail-fast 并列出可用 package）。
    """
    packages = get_packages(repo_root)
    if packages is None:
        return None  # Single-repo 不需要 package。

    # 尝试 task_package（防止 malformed JSON 中出现非字符串值）。
    if task_package and isinstance(task_package, str):
        if task_package in packages:
            return task_package
        print(
            f"警告：config 中找不到 task.json 的 package '{task_package}'，已跳过",
            file=sys.stderr,
        )

    # 尝试 default_package。
    default = get_default_package(repo_root)
    if default:
        if default in packages:
            return default
        print(
            f"警告：config 中找不到 default_package '{default}'，已跳过",
            file=sys.stderr,
        )

    return None


def get_spec_scope(repo_root: Path | None = None) -> list[str] | str | None:
    """获取 session.spec_scope 配置。

    返回：
        list[str]：纳入 spec 扫描的 package 名称。
        str：使用当前任务 package 的 "active_task"。
        None：未配置范围（扫描全部 package）。
    """
    config = _load_config(repo_root)
    session = config.get("session")
    if not isinstance(session, dict):
        return None

    scope = session.get("spec_scope")
    if scope is None:
        return None
    if isinstance(scope, str):
        return scope  # e.g. "active_task"
    if isinstance(scope, list):
        return [str(s) for s in scope]
    return None
