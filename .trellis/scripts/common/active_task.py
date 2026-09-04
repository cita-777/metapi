#!/usr/bin/env python3
"""按 session 解析活动任务。

面向用户的概念是唯一的“活动任务”。Trellis 按 AI session/window 将指针存放在
`.trellis/.runtime/sessions/` 下；没有稳定的 session key 时就不存在活动任务。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DIR_WORKFLOW = ".trellis"
DIR_TASKS = "tasks"
DIR_RUNTIME = ".runtime"
DIR_SESSIONS = "sessions"
DIR_SHELL_TICKETS = "shell-tickets"
# 这是 0.6.13 之前的名称，当时桥接只支持 Cursor。仍然读取它，避免升级过程中
# 正在执行命令的 session 静默降级；不会再写入该名称。ticket 只存活 30 秒，旧目录
# 会自行过期——无需迁移，只需对通常不存在的目录执行 glob。完全忽略旧目录会让
# 那条命令落到当前正在工作的错误平台上。
DIR_LEGACY_CURSOR_SHELL_TICKETS = "cursor-shell"
SHELL_TICKET_TTL_SECONDS = 30
TASK_SESSION_COMMANDS = {"start", "current", "finish"}

_SESSION_KEYS = ("session_id", "sessionId", "sessionID")
_CONVERSATION_KEYS = ("conversation_id", "conversationId", "conversationID")
_TRANSCRIPT_KEYS = ("transcript_path", "transcriptPath", "transcript")
_NESTED_KEYS = ("input", "properties", "event", "hook_input", "hookInput")
_KNOWN_PLATFORMS = {
    "claude",
    "codex",
    "cursor",
    "opencode",
    "gemini",
    "droid",
    "qoder",
    "codebuddy",
    "kiro",
    "copilot",
    "pi",
    "trae",
    "grok",
    "kimi",
    "zcode",
    "snow",
}

# 下面每个名称都记录了核验依据。不要因为相邻平台相似就类推添加名称：2026-08-05
# 对全部 21 个平台的审计发现，已声明的 21 个名称中有 12 个从未在任何地方存在——
# 它们只是按没有厂商认可的 `<PLATFORM>_SESSION_ID` 形状猜出来的，所谓统一性就是
# 唯一的“证据”。没有已验证名称的平台不应加入任何表，而应通过 TRELLIS_CONTEXT_ID
# 或其 hook/plugin bridge 解析。
_ENV_SESSION_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # 已确认但未文档化（2026-08-05 在 Claude Code 2.1.221 的真实 bash 子进程中
    # 验证；code.claude.com/docs/en/env-vars 中不存在）。CLAUDE_SESSION_ID 已从此处
    # 移除，同一真实环境也确认它不存在。
    ("claude", ("CLAUDE_CODE_SESSION_ID",)),
    # 已确认但未文档化（2026-08-05 验证：由 codex-cli 0.146.0 注入 shell 子进程，
    # 父进程环境中不存在；见 openai/codex#19937）。CODEX_SESSION_ID 已移除；真实的
    # `codex exec` 环境中不存在它。
    ("codex", ("CODEX_THREAD_ID",)),
    # 已确认但仅限 HOOK 作用域（2026-08-05 验证）：由 Gemini 的 hookRunner.ts 设置。
    # 其 shell tool 在 shellExecutionService.ts 中构建子进程环境，只添加
    # GEMINI_CLI/TERM/PAGER/GIT_PAGER，因此不会到达 bash 子进程，只能在 hook 进程内解析。
    ("gemini", ("GEMINI_SESSION_ID",)),
    # 已确认但仅限 HOOK 作用域（2026-08-05 验证）：docs.qoder.com/zh/extensions/hooks
    # 说明它由 Qoder *IDE plugin* 在 hook 执行时注入；Qoder CLI hook 文档和灵码文档中
    # 没有该变量。
    ("qoder", ("QODER_SESSION_ID",)),
    # 未验证（2026-08-05）：kiro.dev/docs/hooks/ 中没有它，但 Dynatrace dtctl、
    # oh-my-agent 和 gastown 都用它做 agent 检测，其中一处说明它“在 interactive 和
    # --no-interactive 下都会设置”。保留它是因为没有证据不等于证伪。要最终确认，
    # 需在装有 Kiro 的机器上从 Kiro shell-tool 调用 `env | grep KIRO`。
    ("kiro", ("KIRO_SESSION_ID",)),
    # 未验证（2026-08-05）：docs.github.com/en/copilot/reference/hooks-reference 和
    # CLI programmatic reference 中都没有它。要最终确认，应运行 `copilot help environment`
    # （上述文档称其为权威列表）；当前无法运行，因为本机未安装 CLI，copilot-cli 也不带源码。
    ("copilot", ("COPILOT_SESSION_ID", "COPILOT_SESSIONID")),
    # 推断但未验证（2026-08-05）：ZCode 闭源，当前无法安装。它在其他地方沿用 Claude
    # 的命名（其文档有 CLAUDE_PLUGIN_ROOT / CLAUDE_PLUGIN_DATA 兼容别名），而此前声明的
    # CLAUDE_SESSION_ID 在 Claude Code 中也不存在，因此 ZCode 实际会复用
    # CLAUDE_CODE_SESSION_ID。先尝试该名称，并保留历史名称作为回退；两者都不存在时
    # 行为不变。平台限定查询（_iter_env_keys 按平台过滤），因此只有解析出 "zcode" 后
    # 才会命中，不会与上面的 claude 条目冲突。
    ("zcode", ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID")),
    # 按厂商设计已确认（2026-08-05 验证）：Snow 的 sessionIdentityEnv.ts 会把
    # SNOW_SESSION_ID 导出到 hook/terminal/sub-agent 子进程，并在源码头部注明 Trellis。
    # TRELLIS_CONTEXT_ID 仍是首选覆盖值，Snow 也会设置它。
    ("snow", ("SNOW_SESSION_ID",)),
)
_ENV_CONVERSATION_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # cursor-agent（CLI）中已确认但未文档化（2026-08-05 验证：值匹配
    # ~/.cursor/chats/<ws>/<id>）。Cursor *IDE* 尚未验证；2026-05 的论坛请求没有得到
    # staff 回复。臆造的 CURSOR_SESSION_ID 已从 session 表移除：在真实 cursor-agent
    # shell 中为空。Cursor 的另一条路径是下面的 shell ticket
    # （_lookup_shell_ticket_context_key），它并不专属于 Cursor。
    ("cursor", ("CURSOR_CONVERSATION_ID", "CURSOR_CONVERSATIONID")),
)
_ENV_TRANSCRIPT_KEYS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # 已确认但仅限 HOOK 作用域（2026-08-05 验证）：Cursor hook script 文档有说明，
    # 但 agent 自己的 shell 环境为空。
    ("cursor", ("CURSOR_TRANSCRIPT_PATH",)),
    # 未验证——从未调查。2026-08-05 审计只覆盖 session 表，不能据此推断这些变量
    # 真实或虚构（CLAUDE_/CODEX_TRANSCRIPT_PATH 已移除，因为它们确实经过检查：文档和
    # 真实环境都不存在）。要分别确认，需在 hook 和 shell-tool 调用中运行
    # `env | grep _TRANSCRIPT_PATH`。
    ("gemini", ("GEMINI_TRANSCRIPT_PATH",)),
    ("droid", ("FACTORY_TRANSCRIPT_PATH", "DROID_TRANSCRIPT_PATH")),
    ("qoder", ("QODER_TRANSCRIPT_PATH",)),
    ("codebuddy", ("CODEBUDDY_TRANSCRIPT_PATH",)),
)
_ENV_PLATFORM_ALIASES = {
    "claude-code": "claude",
    "factory": "droid",
    "factory-ai": "droid",
    "github-copilot": "copilot",
}
# ZCode 有意复用 Claude 的 session 环境变量名。Hook 知道 host 是 ZCode，而后续 shell
# 命令只能看到共享变量名，并通过 claude 条目解析。两条路径统一为一个 runtime 文件名。
_CONTEXT_KEY_PLATFORM_ALIASES = {
    "zcode": "claude",
    # Factory Droid 的配置目录是 `.factory/`，因此按安装目录命名平台的 hook 会报告
    # "factory"，其同级 hook 则报告 "droid"。无论哪种情况都使用同一个 runtime 文件名。
    "factory": "droid",
}


@dataclass(frozen=True)
class ActiveTask:
    """解析后的活动任务状态。"""

    task_path: str | None
    source_type: str
    context_key: str | None = None
    stale: bool = False

    @property
    def source(self) -> str:
        """返回供人阅读的来源标签。"""
        if self.source_type == "session" and self.context_key:
            return f"session:{self.context_key}"
        if self.source_type == "session-fallback" and self.context_key:
            return f"session-fallback:{self.context_key}"
        return self.source_type


def normalize_task_ref(task_ref: str) -> str:
    """归一化 task ref，保证存储和比较稳定。"""
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


def resolve_task_ref(task_ref: str, repo_root: Path) -> Path | None:
    """将 task ref 解析为绝对任务目录。"""
    normalized = normalize_task_ref(task_ref)
    if not normalized:
        return None

    path_obj = Path(normalized)
    if path_obj.is_absolute():
        return path_obj

    if normalized.startswith(f"{DIR_WORKFLOW}/"):
        return repo_root / path_obj

    return repo_root / DIR_WORKFLOW / DIR_TASKS / path_obj


def _runtime_sessions_dir(repo_root: Path) -> Path:
    return repo_root / DIR_WORKFLOW / DIR_RUNTIME / DIR_SESSIONS


def _sanitize_key(raw: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw.strip())
    safe = safe.strip("._-")
    return safe[:160] if safe else ""


def _hash_value(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _as_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _string_value(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _lookup_string(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = _string_value(data.get(key))
        if value:
            return value

    for nested_key in _NESTED_KEYS:
        nested = _as_dict(data.get(nested_key))
        if not nested:
            continue
        value = _lookup_string(nested, keys)
        if value:
            return value

    return None


def _detect_platform(platform_input: dict[str, Any] | None, platform: str | None) -> str:
    if platform:
        return _sanitize_key(platform) or "session"
    if platform_input:
        for key in ("_trellis_platform", "trellis_platform", "platform", "source"):
            value = _string_value(platform_input.get(key))
            if value:
                return _sanitize_key(value) or "session"
        if _string_value(platform_input.get("cursor_version")):
            return "cursor"
    return "session"


def _context_key(platform_name: str, kind: str, value: str) -> str:
    platform_name = _CONTEXT_KEY_PLATFORM_ALIASES.get(platform_name, platform_name)
    if kind == "transcript":
        return f"{platform_name}_transcript_{_hash_value(value)}"
    safe_value = _sanitize_key(value)
    if safe_value:
        return f"{platform_name}_{safe_value}"
    return f"{platform_name}_{_hash_value(value)}"


def _iter_env_keys(
    env_keys: tuple[tuple[str, tuple[str, ...]], ...],
    platform_name: str | None,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """将环境变量表收窄到一个平台；未指定平台时返回完整表。

    没有条目的平台返回空 tuple，调用方的 `for` 循环自然不会执行。这是正常情况，
    不是错误：没有已验证环境变量名称的平台会有意从这些表中缺席。
    """
    if not platform_name:
        return env_keys
    matched = tuple((name, keys) for name, keys in env_keys if name == platform_name)
    return matched


def _env_platform_name(platform_name: str | None) -> str | None:
    if not platform_name or platform_name == "session":
        return None
    return _ENV_PLATFORM_ALIASES.get(platform_name, platform_name)


def _lookup_env_context_key(platform_name: str | None) -> str | None:
    """从平台提供的环境变量解析 context key。

    Hook 会把 `TRELLIS_CONTEXT_ID` 传给它启动的子进程，但 AI 运行的 shell 命令只有在
    host platform 将 session identity 导出到命令环境时才能看到它。这些名称只是尽力而
    为的适配；都不存在时，就没有按 session 隔离的活动任务。
    """
    env_platform_name = _env_platform_name(platform_name)

    for name, keys in _iter_env_keys(_ENV_SESSION_KEYS, env_platform_name):
        for key in keys:
            value = _string_value(os.environ.get(key))
            if value:
                return _context_key(name, "session", value)

    for name, keys in _iter_env_keys(_ENV_CONVERSATION_KEYS, env_platform_name):
        for key in keys:
            value = _string_value(os.environ.get(key))
            if value:
                return _context_key(name, "conversation", value)

    for name, keys in _iter_env_keys(_ENV_TRANSCRIPT_KEYS, env_platform_name):
        for key in keys:
            value = _string_value(os.environ.get(key))
            if value:
                return _context_key(name, "transcript", value)

    return None


def _find_repo_root_from_cwd() -> Path | None:
    current = Path.cwd().resolve()
    while True:
        if (current / DIR_WORKFLOW).is_dir():
            return current
        if current == current.parent:
            return None
        current = current.parent


def _shell_ticket_dirs(repo_root: Path) -> tuple[Path, ...]:
    runtime_dir = repo_root / DIR_WORKFLOW / DIR_RUNTIME
    return (
        runtime_dir / DIR_SHELL_TICKETS,
        runtime_dir / DIR_LEGACY_CURSOR_SHELL_TICKETS,
    )


def _remove_file(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except OSError:
        return False


def _task_refs_match(left: str | None, right: str | None, repo_root: Path) -> bool:
    if not left or not right:
        return False
    left_path = resolve_task_ref(left, repo_root)
    right_path = resolve_task_ref(right, repo_root)
    if left_path is not None and right_path is not None:
        return left_path == right_path
    return normalize_task_ref(left) == normalize_task_ref(right)


def _pending_ticket_matches_args(ticket: dict[str, Any], repo_root: Path) -> bool:
    if Path(sys.argv[0]).name != "task.py":
        return False
    args = tuple(sys.argv[1:])
    if not args:
        return False

    command_name = args[0]
    if command_name not in TASK_SESSION_COMMANDS:
        return False

    subcommands = ticket.get("subcommands")
    if not isinstance(subcommands, list):
        return False

    for subcommand in subcommands:
        if not isinstance(subcommand, dict):
            continue
        if _string_value(subcommand.get("name")) != command_name:
            continue
        if command_name != "start":
            return True
        task_ref = args[1] if len(args) > 1 else None
        if _task_refs_match(_string_value(subcommand.get("task_ref")), task_ref, repo_root):
            return True

    return False


def _ticket_is_fresh(ticket: dict[str, Any], ticket_path: Path, now: float) -> bool:
    expires_at = ticket.get("expires_at_epoch")
    if isinstance(expires_at, (int, float)) and expires_at < now:
        _remove_file(ticket_path)
        return False

    created_at = ticket.get("created_at_epoch")
    if isinstance(created_at, (int, float)):
        if now - created_at <= SHELL_TICKET_TTL_SECONDS:
            return True
        _remove_file(ticket_path)
        return False
    return True


def _ticket_cwd_matches_repo(ticket: dict[str, Any], repo_root: Path) -> bool:
    cwd = _string_value(ticket.get("cwd"))
    if not cwd:
        return True
    try:
        Path(cwd).resolve().relative_to(repo_root)
    except ValueError:
        return False
    return True


def _matching_ticket_context_key(
    ticket_path: Path,
    repo_root: Path,
    now: float,
) -> str | None:
    """只按 ticket 自身条件接受它，不按写入 ticket 的平台筛选。

    ticket 携带的 `platform` 字段只是调试元数据；以前按它做门控，导致除 Cursor 外的
    所有平台都看不到这条桥接路径。
    """
    ticket = _read_json(ticket_path)
    if ticket is None:
        return None
    if not _ticket_is_fresh(ticket, ticket_path, now):
        return None
    if not _ticket_cwd_matches_repo(ticket, repo_root):
        return None
    if not _pending_ticket_matches_args(ticket, repo_root):
        return None
    return _string_value(ticket.get("context_key"))


def _lookup_shell_ticket_context_key() -> str | None:
    """从短时 shell ticket 解析 session identity。

    调查过的平台都不会把 session id 导出到 shell 子进程，但支持 hook 的平台都会把
    该 id 交给 hook。因此，在 shell 命令执行前运行的 hook 写入 ticket，本函数再读回。
    ticket 只有同时满足“仍然新鲜、为本仓库写入、匹配当前执行的 `task.py` 子命令”，且
    恰好只有一个 context key 匹配时才有效。两个并发窗口会一起降级，不会让一个窗口
    继承另一个窗口的指针。
    """
    repo_root = _find_repo_root_from_cwd()
    if repo_root is None:
        return None

    now = time.time()
    candidates: set[str] = set()
    for ticket_dir in _shell_ticket_dirs(repo_root):
        if not ticket_dir.is_dir():
            continue
        for ticket_path in ticket_dir.glob("*.json"):
            context_key = _matching_ticket_context_key(ticket_path, repo_root, now)
            if context_key:
                candidates.add(context_key)

    if len(candidates) == 1:
        return next(iter(candidates))
    return None


def resolve_context_key(
    platform_input: dict[str, Any] | None = None,
    platform: str | None = None,
    *,
    allow_environment_context: bool = True,
) -> str | None:
    """在可用时解析稳定的 session/window context key。

    `TRELLIS_CONTEXT_ID` 是 CLI script 和子进程使用的显式 context-key 覆盖值；它本身
    不存储任务。
    """
    if allow_environment_context:
        override = _string_value(os.environ.get("TRELLIS_CONTEXT_ID"))
        if override:
            return _sanitize_key(override) or _hash_value(override)

    data = _as_dict(platform_input)
    platform_name = _detect_platform(data, platform) if data or platform else None

    if data:
        session_id = _lookup_string(data, _SESSION_KEYS)
        if session_id:
            return _context_key(platform_name or "session", "session", session_id)

        conversation_id = _lookup_string(data, _CONVERSATION_KEYS)
        if conversation_id:
            return _context_key(platform_name or "session", "conversation", conversation_id)

        transcript_path = _lookup_string(data, _TRANSCRIPT_KEYS)
        if transcript_path:
            return _context_key(platform_name or "session", "transcript", transcript_path)

    if allow_environment_context:
        env_context_key = _lookup_env_context_key(platform_name)
        if env_context_key:
            return env_context_key

    # 有意放在链条最后：真正把 identity 导出到 shell 的平台优先于 ticket，且查询不按
    # 平台名称做门控。
    if allow_environment_context:
        return _lookup_shell_ticket_context_key()
    return None


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _write_json(path: Path, data: dict[str, Any]) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return True
    except OSError:
        return False


def _canonical_task_ref(task_path: str, repo_root: Path) -> str | None:
    normalized = normalize_task_ref(task_path)
    if not normalized:
        return None
    full_path = resolve_task_ref(normalized, repo_root)
    if full_path is None or not full_path.is_dir():
        return None
    try:
        return full_path.relative_to(repo_root).as_posix()
    except ValueError:
        return str(full_path)


def _active_from_ref(
    task_ref: str | None,
    repo_root: Path,
    source_type: str,
    context_key: str | None = None,
) -> ActiveTask | None:
    if not task_ref:
        return None
    resolved = resolve_task_ref(task_ref, repo_root)
    stale = resolved is None or not resolved.is_dir()
    return ActiveTask(task_ref, source_type, context_key, stale)


def _context_path(repo_root: Path, context_key: str) -> Path:
    return _runtime_sessions_dir(repo_root) / f"{context_key}.json"


def resolve_active_task(
    repo_root: Path,
    platform_input: dict[str, Any] | None = None,
    platform: str | None = None,
    *,
    allow_single_session_fallback: bool = True,
    allow_environment_context: bool = True,
) -> ActiveTask:
    """仅从 session runtime state 解析活动任务。

    过期的 session task 会以 stale 标记返回。缺少 context identity 或 session context
    缺失/为空时，回退到单 session 推断：如果 runtime 中恰好有一个 session 文件，就以
    ``source_type="session-fallback"`` 返回其中的任务——覆盖不会继承父 session id 的
    pull-based platform sub-agent（copilot、gemini、qoder）。文件数为 0 或至少 2 时返回
    ActiveTask(None)，拒绝跨窗口猜测。
    """
    context_key = resolve_context_key(
        platform_input,
        platform,
        allow_environment_context=allow_environment_context,
    )
    if context_key:
        context = _read_json(_context_path(repo_root, context_key)) or {}
        task_ref = _string_value(context.get("current_task"))
        active = _active_from_ref(task_ref, repo_root, "session", context_key)
        if active:
            return active

    if allow_single_session_fallback:
        fallback = _resolve_single_session_fallback(repo_root)
        if fallback is not None:
            return fallback

    return ActiveTask(None, "none", context_key)


def _resolve_single_session_fallback(repo_root: Path) -> ActiveTask | None:
    """在恰好存在一个 session 文件时返回其指向的任务。

    当 context-key 解析失败时使用（class-2 platform sub-agent 很常见）。存在 0 个或
    至少 2 个 session 文件时返回 None，拒绝跨窗口选择，以保持 04-21 的多 session 隔离契约。
    """
    sessions_dir = _runtime_sessions_dir(repo_root)
    if not sessions_dir.is_dir():
        return None

    session_files = sorted(sessions_dir.glob("*.json"))
    if len(session_files) != 1:
        return None

    session_file = session_files[0]
    context = _read_json(session_file) or {}
    task_ref = _string_value(context.get("current_task"))
    if not task_ref:
        return None

    fallback_key = session_file.stem
    return _active_from_ref(task_ref, repo_root, "session-fallback", fallback_key)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _context_metadata(
    platform_input: dict[str, Any] | None,
    platform: str | None,
    context_key: str | None = None,
) -> dict[str, Any]:
    data = _as_dict(platform_input) or {}
    platform_name = _detect_platform(data, platform)
    if platform_name == "session" and context_key:
        prefix = context_key.split("_", 1)[0]
        if prefix in _KNOWN_PLATFORMS:
            platform_name = prefix
    metadata: dict[str, Any] = {
        "platform": platform_name,
        "last_seen_at": _utc_now(),
    }
    for key in (*_SESSION_KEYS, *_CONVERSATION_KEYS, *_TRANSCRIPT_KEYS):
        value = _lookup_string(data, (key,))
        if value:
            metadata[key] = value
    return metadata


def set_active_task(
    task_path: str,
    repo_root: Path,
    platform_input: dict[str, Any] | None = None,
    platform: str | None = None,
) -> ActiveTask | None:
    """在 session 作用域设置活动任务。

    没有 context key 时返回 None；调用方应向用户显示如何提供 session identity 的错误。
    """
    canonical = _canonical_task_ref(task_path, repo_root)
    if canonical is None:
        return None

    context_key = resolve_context_key(platform_input, platform)
    if not context_key:
        return None

    context_path = _context_path(repo_root, context_key)
    context = _read_json(context_path) or {}
    context.update(_context_metadata(platform_input, platform, context_key))
    context["current_task"] = canonical
    context.setdefault("current_run", None)
    if not _write_json(context_path, context):
        return None
    return ActiveTask(canonical, "session", context_key)


def clear_active_task(
    repo_root: Path,
    platform_input: dict[str, Any] | None = None,
    platform: str | None = None,
) -> ActiveTask:
    """删除已解析的 session context 文件，从而清除活动任务。"""
    context_key = resolve_context_key(platform_input, platform)
    if not context_key:
        return ActiveTask(None, "none")

    previous = resolve_active_task(repo_root, platform_input, platform)
    if not previous.task_path or not previous.context_key:
        return previous

    context_path = _context_path(repo_root, previous.context_key)
    if context_path.is_file():
        _remove_file(context_path)
    return previous


def clear_task_from_sessions(task_path: str, repo_root: Path) -> int:
    """删除所有指向指定任务的 session runtime 文件。"""
    target = _canonical_task_ref(task_path, repo_root) or normalize_task_ref(task_path)
    if not target:
        return 0

    cleared = 0
    sessions_dir = _runtime_sessions_dir(repo_root)
    if not sessions_dir.is_dir():
        return cleared

    for session_path in sessions_dir.glob("*.json"):
        context = _read_json(session_path) or {}
        current = _string_value(context.get("current_task"))
        if not current:
            continue
        current_ref = _canonical_task_ref(current, repo_root) or normalize_task_ref(current)
        if current_ref != target:
            continue
        if session_path.is_file() and _remove_file(session_path):
            cleared += 1

    return cleared


def get_current_task_source(
    repo_root: Path,
    platform_input: dict[str, Any] | None = None,
    platform: str | None = None,
) -> tuple[str, str | None, str | None]:
    """为兼容旧调用方返回 (`source_type`, `context_key`, `task_path`)。"""
    active = resolve_active_task(repo_root, platform_input, platform)
    return active.source_type, active.context_key, active.task_path
