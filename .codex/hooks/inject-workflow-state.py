#!/usr/bin/env python3
"""Trellis 每轮 breadcrumb hook（UserPromptSubmit / BeforeAgent 等价事件）。

每个用户 prompt 都会运行。通过 Trellis 的 session-aware 活动任务解析器解析当前
任务，并输出简短的 <workflow-state> 块，提醒主 AI 当前任务及应遵循的流程。

输出的 ``hookEventName`` 字段会随平台变化：大多数 host 使用
``UserPromptSubmit``（Claude Code 的命名，Cursor / Qoder / CodeBuddy / Droid /
Codex / Copilot 也接受）；Gemini CLI 0.40.x 将每轮事件改名为 ``BeforeAgent``，
其 schema validator 会拒绝旧名称。``_detect_platform`` 在运行时选择正确值。
Breadcrumb 文本只从 workflow.md 的 ``[workflow-state:STATUS]`` 标签块读取，
workflow.md 是唯一事实来源。本脚本不维护备用字典；workflow.md 缺失或标签不存在时，
breadcrumb 会退化为“请查阅 .trellis/workflow.md 确认当前步骤”，让用户看见并修复
损坏状态，而不是由 hook 静默掩盖。

注册此 hook 的平台由 templates/shared-hooks/index.ts 中的
SHARED_HOOKS_BY_PLATFORM 决定，目前包括 Claude、Codex、Gemini、Qoder、Copilot、
CodeBuddy、Droid、Kiro、Trae 和 ZCode。该表是唯一事实来源；列出的平台通过
collect<Platform>Templates() 和 collectSharedHooks() 将本文件加入模板映射，初始化时
由一个 writer 写入磁盘。Kiro 通过 CLI custom agent 的 ``hooks.userPromptSubmit``
和 IDE ``.kiro.hook`` 的 ``promptSubmit`` 事件接入，其分支输出纯文本 breadcrumb
（Kiro 会把 hook stdout 直接加入对话上下文）。

静默退出 0 的情况（无输出）：
  - 找不到 .trellis/ 目录（不是 Trellis 项目）
  - task.json 格式错误或缺少 status
"""
from __future__ import annotations

import json
import os
import re
import sys
import queue
import threading
from pathlib import Path

# 在 Windows 上强制 stdin/stdout/stderr 使用 UTF-8。默认 codepage 可能是
# cp936 / cp1252 等；stdin 的 host CLI hook payload 和 stdout 的注入块含有中文
# 任务名、PRD 片段时，否则会触发 UnicodeDecodeError / UnicodeEncodeError。
# 这等价于 `python -X utf8`，但按 stream 应用，不依赖 host CLI 的命令接线。
if sys.platform.startswith("win"):
    import io as _io
    for _stream_name in ("stdin", "stdout", "stderr"):
        _stream = getattr(sys, _stream_name, None)
        if _stream is None:
            continue
        if hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
            except Exception:
                pass  # Windows stream 设置失败时保持 hook 启动不中断。
        elif hasattr(_stream, "detach"):
            try:
                setattr(sys, _stream_name, _io.TextIOWrapper(_stream.detach(), encoding="utf-8", errors="replace"))
            except Exception:
                pass  # Windows stream 设置失败时保持 hook 启动不中断。
from typing import Optional


# 当 Codex session 没有活动任务时使用的 bootstrap 提示。Codex 不会收到完整的
# SessionStart 概览；这里的短提示只引导主 session 加载一次 start skill，并保持每轮
# 状态块精简。
CODEX_NO_TASK_BOOTSTRAP_NOTICE = """<trellis-bootstrap>
如果本 session 尚未加载 Trellis 上下文，请先阅读一次 `trellis-start` skill。
Trellis 管理文档默认使用简体中文；命令、路径、代码符号和机器字段保持原文。
</trellis-bootstrap>"""


# ---------------------------------------------------------------------------
# 可抵抗 CWD 漂移的 Trellis 根目录探测（修复本 hook 的路径健壮性）。
# ---------------------------------------------------------------------------

def find_trellis_root(start: Path) -> Optional[Path]:
    """从 start 向上查找包含 .trellis/ 的目录。

    处理 CWD 漂移（子目录启动、monorepo package 等）。找不到 .trellis/ 时返回 None，
    不输出任何内容。
    """
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / ".trellis").is_dir():
            return cur
        cur = cur.parent
    return None


# ---------------------------------------------------------------------------
# 活动任务探测。
# ---------------------------------------------------------------------------

def _detect_platform(input_data: dict) -> str | None:
    if isinstance(input_data.get("cursor_version"), str):
        return "cursor"
    # CLAUDE_PROJECT_DIR 是多个 host 共用的兼容别名，必须最后检查；否则 CodeBuddy、
    # ZCode、Trae 等会被误判为 claude，context key 变成 `claude_<their-session-id>`。
    # 该 key 与 host 真正名称下由 `task.py start` 写入的 session 文件不一致，于是磁盘
    # 上明明有指针，每轮却都会报告 no_task。CodeBuddy IDE 4.10.4 的实测也观察到这一点：
    # session 文件和 `update-check-claude_...marker` 使用同一个 id。
    env_map = {
        "ZCODE_PROJECT_DIR": "zcode",
        "CURSOR_PROJECT_DIR": "cursor",
        "CODEBUDDY_PROJECT_DIR": "codebuddy",
        "FACTORY_PROJECT_DIR": "droid",
        "GEMINI_PROJECT_DIR": "gemini",
        "QODER_PROJECT_DIR": "qoder",
        "KIRO_PROJECT_DIR": "kiro",
        "COPILOT_PROJECT_DIR": "copilot",
        "TRAE_PROJECT_DIR": "trae",
        # 最后检查共享别名；只有没有匹配厂商变量时它才有意义。
        "CLAUDE_PROJECT_DIR": "claude",
    }
    for env_name, platform in env_map.items():
        if os.environ.get(env_name):
            return platform
    script_parts = set(Path(sys.argv[0]).parts)
    if ".claude" in script_parts:
        return "claude"
    if ".cursor" in script_parts:
        return "cursor"
    if ".codex" in script_parts:
        return "codex"
    if ".gemini" in script_parts:
        return "gemini"
    if ".qoder" in script_parts:
        return "qoder"
    if ".codebuddy" in script_parts:
        return "codebuddy"
    if ".factory" in script_parts:
        return "droid"
    if ".kiro" in script_parts:
        return "kiro"
    if ".trae" in script_parts:
        return "trae"
    if ".zcode" in script_parts:
        return "zcode"
    return None


def _resolve_active_task(root: Path, input_data: dict):
    scripts_dir = root / ".trellis" / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from common.active_task import resolve_active_task  # type: ignore[import-not-found]

    return resolve_active_task(root, input_data, platform=_detect_platform(input_data))


def get_active_task(root: Path, input_data: dict) -> Optional[tuple[str, str, str]]:
    """从当前活动任务返回 ``(task_id, status, source)``。"""
    active = _resolve_active_task(root, input_data)
    if not active.task_path:
        return None

    task_dir = Path(active.task_path)
    if not task_dir.is_absolute():
        task_dir = root / task_dir
    if active.stale:
        return task_dir.name, f"stale_{active.source_type}", active.source

    task_json = task_dir / "task.json"
    if not task_json.is_file():
        return None
    try:
        data = json.loads(task_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    task_id = data.get("id") or task_dir.name
    status = data.get("status", "")
    if not isinstance(status, str) or not status:
        return None
    return task_id, status, active.source


# ---------------------------------------------------------------------------
# Breadcrumb 加载：解析 workflow.md，缺失时使用通用中文提示
# ---------------------------------------------------------------------------

# 支持由字母、数字、下划线和连字符组成的 STATUS 值
#（例如 "in-review" / "blocked-by-team" 与 "in_progress" 并存）。
_TAG_RE = re.compile(
    r"\[workflow-state:([A-Za-z0-9_-]+)\]\s*\n(.*?)\n\s*\[/workflow-state:\1\]",
    re.DOTALL,
)

def load_breadcrumbs(root: Path) -> dict[str, str]:
    """解析 workflow.md 中的 [workflow-state:STATUS] 标签块。

    返回 {status: body_text}。workflow.md 是唯一事实来源，本脚本不维护备用字典。
    标签缺失（或 workflow.md 缺失/无法读取）时，build_breadcrumb 使用通用提示，
    让用户看见并修复损坏状态，而不是由 hook 静默掩盖。
    """
    workflow = root / ".trellis" / "workflow.md"
    if not workflow.is_file():
        return {}
    try:
        content = workflow.read_text(encoding="utf-8")
    except OSError:
        return {}

    result: dict[str, str] = {}
    for match in _TAG_RE.finditer(content):
        status = match.group(1)
        body = match.group(2).strip()
        if body:
            result[status] = body
    return result


def _read_trellis_config(root: Path) -> dict:
    """通过捆绑的 trellis_config 辅助函数读取 .trellis/config.yaml。

    辅助函数位于 .trellis/scripts/common；本 hook 位于 scripts 树之外，因此导入前
    需要扩展 sys.path。
    """
    scripts_dir = root / ".trellis" / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from common.trellis_config import read_trellis_config  # type: ignore[import-not-found]
    except Exception:
        return {}
    try:
        return read_trellis_config(root)
    except Exception:
        return {}


DEFAULT_PROMPT_INJECTION_SKIP_KEYWORD = "no-trellis"


def _resolve_skip_keyword(config: dict) -> str:
    """从解析后的 .trellis/config.yaml 读取 `prompt_injection.skip_keyword`。

    行为与 `common.config.get_prompt_injection_config()` 一致。默认值为
    "no-trellis"；空字符串会关闭 escape hatch；非字符串值回退到默认值。
    """
    if isinstance(config, dict):
        section = config.get("prompt_injection")
        if isinstance(section, dict):
            raw = section.get("skip_keyword", DEFAULT_PROMPT_INJECTION_SKIP_KEYWORD)
            if isinstance(raw, str):
                return raw
    return DEFAULT_PROMPT_INJECTION_SKIP_KEYWORD


def prompt_has_skip_keyword(prompt: str, keyword: str) -> bool:
    """在 `prompt` 中按不区分大小写的单词边界匹配 `keyword`。

    连字符按单词字符处理，因此 "no-trellisx" / "xno-trellis" /
    "foo-no-trellis" 不会匹配，而标点或空白边界会匹配。空 keyword 永不匹配
    （即关闭 escape hatch）。
    """
    if not keyword or not isinstance(prompt, str):
        return False
    pattern = r"(?<![\w-])" + re.escape(keyword) + r"(?![\w-])"
    return re.search(pattern, prompt, re.IGNORECASE) is not None


def _resolve_codex_dispatch_mode(config: dict) -> str:
    """将 .trellis/config.yaml 中的 `codex.dispatch_mode` 归一化为 "auto" 或 "inline"。

    默认值为 `auto`；旧值 `sub-agent` 是 `auto` 的别名。其他显式值（包括非法值）
    都回退为 `inline`，且不在每轮重复警告。`_codex_mode_banner`（每轮 banner）
    与 `resolve_breadcrumb_key`（breadcrumb 标签键）共享该结果，保持一致。
    """
    mode = "auto"
    if isinstance(config, dict):
        codex_cfg = config.get("codex")
        if isinstance(codex_cfg, dict):
            cfg_mode = str(codex_cfg.get("dispatch_mode", mode)).strip().lower()
            if cfg_mode == "inline":
                mode = "inline"
            elif cfg_mode in ("auto", "sub-agent"):
                mode = "auto"
            else:
                mode = "inline"
    return mode


def _codex_mode_banner(config: dict) -> str:
    """为 additionalContext 输出 `<codex-mode>` banner。

    从 .trellis/config.yaml 读取 `codex.dispatch_mode`；默认 `auto`，通过 Codex 原生
    上下文注入 dispatch Trellis sub-agent，并以子 agent 侧加载兜底。它不依赖继承的
    parent transcript：`fork_turns` 仍由调用方控制，新历史的 sub-agent 仍会收到显式
    委派任务和继承的 session 配置。`inline` 是显式退出；旧值 `sub-agent` 是 `auto`
    的别名。非法显式值回退到 `inline`，不在每轮重复警告。banner 每轮明确当前模式，
    与按 status 提供的 workflow-state body 互补；模式说明应遵循哪种 dispatch 协议，
    workflow-state 说明当前步骤。
    """
    mode = _resolve_codex_dispatch_mode(config)
    if mode == "auto":
        meaning = (
            "auto：implement/check 默认使用 Trellis sub-agent；优先使用 Codex 原生上下文注入，"
            "不可用时由 child-side loading 兜底。主 session 仍负责协调、澄清、更新规范、commit 和 finish。"
        )
    else:
        meaning = "inline：由主 session 直接实现/检查；不要 dispatch implement/check sub-agent。"
    return f"<codex-mode>{meaning}</codex-mode>"


def resolve_breadcrumb_key(
    status: str, platform: str | None, config: dict
) -> str:
    """根据 Codex dispatch_mode 选择 breadcrumb 标签键。

    Codex 默认使用 ``auto``，因此原生 SubagentStart dispatch 使用普通的 ``<status>``
    breadcrumb，并由子 agent 侧加载兜底；它不依赖继承的 parent transcript。``inline``
    选择对应的 ``<status>-inline`` 标签；``sub-agent`` 仍是 ``auto`` 的别名。非法显式
    值回退到 inline，且不在每轮重复警告。

    非 Codex 平台原样返回普通 status。
    """
    if platform == "codex":
        mode = _resolve_codex_dispatch_mode(config)
        return f"{status}-inline" if mode == "inline" else status
    return status


def build_breadcrumb(
    task_id: Optional[str],
    status: str,
    templates: dict[str, str],
    source: str | None = None,
    breadcrumb_key: str | None = None,
) -> str:
    """构建 <workflow-state>...</workflow-state> 块。

    - 已知 status（workflow.md 中存在标签）→ 详细模板正文
    - 未知 status（没有标签或 workflow.md 缺失）→ 通用的
      “请查阅 .trellis/workflow.md 确认当前步骤”提示
    - `no_task` 伪状态（task_id 为 None）→ header 不包含任务信息
    """
    lookup_key = breadcrumb_key or status
    body = templates.get(lookup_key)
    if body is None and lookup_key != status:
        body = templates.get(status)
    if body is None:
        body = "请查阅 .trellis/workflow.md 确认当前步骤。"
    header = f"状态：{status}" if task_id is None else f"任务：{task_id}（{status}）"
    return f"<workflow-state>\n{header}\n{body}\n</workflow-state>"


# ---------------------------------------------------------------------------
# 入口。
# ---------------------------------------------------------------------------

def _load_hook_input() -> dict:
    """读取 hook JSON，不假设 host runner 一定会关闭 stdin。

    Kiro IDE `runCommand` 及类似 runner 可能在不发送 payload 时保持 stdin 打开，
    此时直接执行 `json.load(sys.stdin)` 会永久阻塞。正常 runner 会写入完整 JSON 并
    关闭 stdin，因此短时 daemon read 可以保留正常路径，并对非管道 host 安全回退为 `{}`。
    """
    result_queue: "queue.Queue[str | Exception]" = queue.Queue(maxsize=1)

    def _read() -> None:
        try:
            result_queue.put(sys.stdin.read())
        except Exception as exc:
            result_queue.put(exc)

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    try:
        raw = result_queue.get(timeout=0.2)
    except queue.Empty:
        return {}

    if isinstance(raw, Exception):
        return {}
    try:
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def main() -> int:
    if os.environ.get("TRELLIS_HOOKS") == "0" or os.environ.get("TRELLIS_DISABLE_HOOKS") == "1":
        return 0

    data = _load_hook_input()

    cwd_value = data.get("cwd")
    cwd_str = cwd_value if isinstance(cwd_value, str) and cwd_value else os.getcwd()
    cwd = Path(cwd_str)

    root = find_trellis_root(cwd)
    if root is None:
        return 0  # 不是 Trellis 项目。

    config = _read_trellis_config(root)
    if prompt_has_skip_keyword(data.get("prompt", ""), _resolve_skip_keyword(config)):
        return 0  # 用户选择本轮跳过 breadcrumb。

    templates = load_breadcrumbs(root)
    platform = _detect_platform(data)
    task = get_active_task(root, data)
    if task is None:
        # 没有活动任务时仍输出 breadcrumb，提示用户描述真实工作后使用
        # trellis-brainstorm + task.py create。
        no_task_key = resolve_breadcrumb_key("no_task", platform, config)
        breadcrumb = build_breadcrumb(
            None, "no_task", templates, breadcrumb_key=no_task_key
        )
    else:
        task_id, status, source = task
        status_key = resolve_breadcrumb_key(status, platform, config)
        source_for_breadcrumb = None if platform == "codex" else source
        breadcrumb = build_breadcrumb(
            task_id, status, templates, source_for_breadcrumb, breadcrumb_key=status_key
        )
    if platform == "codex":
        parts: list[str] = []
        if task is None:
            parts.append(CODEX_NO_TASK_BOOTSTRAP_NOTICE)
        parts.append(_codex_mode_banner(config))
        parts.append(breadcrumb)
        breadcrumb = "\n\n".join(parts)

    # Kiro（CLI userPromptSubmit / IDE promptSubmit）会把 hook stdout 直接加入对话上下文，
    # 不使用 JSON envelope，因此输出裸 breadcrumb 文本。该分支与其他平台隔离，其他平台
    # 继续使用下面不变的 hookSpecificOutput JSON 路径。
    if platform == "kiro":
        print(breadcrumb)
        return 0

    # Gemini CLI 0.40.x 拒绝 "UserPromptSubmit"，其每轮事件名为 "BeforeAgent"。
    # 其他平台（Claude/Cursor/Qoder/CodeBuddy/Droid/Codex/Copilot）接受原 Claude 风格名称。
    hook_event_name = (
        "BeforeAgent" if platform == "gemini" else "UserPromptSubmit"
    )

    output = {
        "hookSpecificOutput": {
            "hookEventName": hook_event_name,
            "additionalContext": breadcrumb,
        }
    }
    print(json.dumps(output, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
