#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Workflow 阶段提取。

从 .trellis/workflow.md 提取步骤级内容，并按需筛选平台专属区块。

workflow.md 中的平台标记语法：

    [Claude Code, Cursor, ...]
    支持 agent 的内容
    [/Claude Code, Cursor, ...]

提供：
    get_phase_index   - 提取 Phase Index 段落（不传 --step）
    get_step          - 提取单个步骤（#### X.X）段落
    filter_platform   - 删除不包含指定平台名称的平台区块
"""

from __future__ import annotations

import re

from .paths import DIR_WORKFLOW, get_repo_root


def _workflow_md_path():
    return get_repo_root() / DIR_WORKFLOW / "workflow.md"

# 匹配平台标记行："[A, B, C]" 或 "[/A, B, C]"。
_MARKER_RE = re.compile(r"^\[(/?)([A-Za-z][^\[\]]*)\]\s*$")

# 步骤标题："#### 1.0 标题" 或 "#### 1.0 ..."。
_STEP_HEADING_RE = re.compile(r"^####\s+(\d+\.\d+)\b.*$")

# Phase Index 从这里开始；后面是 Phase 1/2/3 步骤正文，至 Breadcrumbs 结束。
_PHASE_INDEX_HEADING = "## Phase Index"


def _read_workflow() -> str:
    path = _workflow_md_path()
    if not path.exists():
        raise FileNotFoundError(f"找不到 workflow.md：{path}")
    return path.read_text(encoding="utf-8")


def _parse_marker(line: str) -> tuple[bool, list[str]] | None:
    """解析平台标记行。

    返回：
        如果是标记，返回 (is_closing, [platform_names])；否则返回 None。
    """
    m = _MARKER_RE.match(line)
    if not m:
        return None
    is_closing = m.group(1) == "/"
    names = [p.strip() for p in m.group(2).split(",") if p.strip()]
    return is_closing, names


def get_phase_index() -> str:
    """返回 workflow.md 中精简的 Phase Index 摘要。

    SessionStart 和未指定步骤的 phase context 使用此摘要定位。Phase 1/2/3 的详细
    指令通过 ``get_step`` 按需加载。``[workflow-state:STATUS]`` 标签块由每轮 hook
    单独消费，因此从此输出中移除。
    """
    text = _read_workflow()
    lines = text.splitlines()

    start: int | None = None
    end: int | None = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start is None and stripped == _PHASE_INDEX_HEADING:
            start = i
            continue
        if start is not None and stripped == "## Phase 1: Plan":
            end = i
            break

    if start is None:
        return ""
    if end is None:
        end = len(lines)

    section = "\n".join(lines[start:end]).rstrip()
    # 移除 [workflow-state:STATUS]...[/workflow-state:STATUS] 区块；这些区块由
    # inject-workflow-state.py 在每轮单独注入。
    import re as _re
    tag_re = _re.compile(
        r"\[workflow-state:([A-Za-z0-9_-]+)\]\s*\n.*?\n\s*\[/workflow-state:\1\]\n?",
        _re.DOTALL,
    )
    return tag_re.sub("", section).rstrip() + "\n"


def get_step(step_id: str) -> str:
    """返回与 step_id 匹配的 `#### X.X` 段落（标题和正文）。

    正文在下一个 `####`、`---` 或 `##` 标题处结束（取最先出现者）。
    """
    text = _read_workflow()
    lines = text.splitlines()

    start: int | None = None
    for i, line in enumerate(lines):
        m = _STEP_HEADING_RE.match(line)
        if m and m.group(1) == step_id:
            start = i
            break
    if start is None:
        return ""

    end: int = len(lines)
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if line.startswith("#### "):
            end = j
            break
        if line.startswith("## "):
            end = j
            break
        # 第 0 列的水平分隔线。
        if line.strip() == "---":
            end = j
            break

    return "\n".join(lines[start:end]).rstrip() + "\n"


def _platform_matches(platform: str, block_names: list[str]) -> bool:
    """不区分大小写并兼容连字符/空格，例如 cursor、Cursor、claude-code、Claude Code。"""
    needle = platform.lower().replace("-", "").replace("_", "").replace(" ", "")
    for name in block_names:
        hay = name.lower().replace("-", "").replace("_", "").replace(" ", "")
        if needle == hay:
            return True
    return False


def resolve_effective_platform(platform: str, config: dict) -> str:
    """将 ``codex`` 映射为带 dispatch mode 命名空间的虚拟平台名称。

    传入 ``--platform codex`` 时，默认返回 ``"codex-sub-agent"``；在
    ``.trellis/config.yaml`` 明确配置时返回 ``"codex-inline"``。
    ``sub-agent`` 仍是 ``auto`` 的别名。随后 ``filter_platform`` 只保留标记列表中
    包含该命名空间名称的区块（例如 ``[codex-sub-agent, ...]`` 或
    ``[codex-inline, Kilo, Antigravity, Devin]``）。

    Codex 原生上下文注入支持 ``auto`` 默认值。非法显式值安全回退到 ``inline``；
    此 renderer 可能在普通 CLI 输出流程中运行，因此有意不发出 warning。

    其他平台原样返回。
    """
    if platform == "codex":
        mode = "auto"
        codex_cfg = config.get("codex") if isinstance(config, dict) else None
        if codex_cfg is not None:
            if not isinstance(codex_cfg, dict):
                mode = "inline"
            else:
                cfg_mode = str(codex_cfg.get("dispatch_mode", mode)).strip().lower()
                if cfg_mode == "inline":
                    mode = "inline"
                elif cfg_mode in ("auto", "sub-agent"):
                    mode = "auto"
                else:
                    mode = "inline"
        return "codex-sub-agent" if mode == "auto" else "codex-inline"
    return platform


def filter_platform(content: str, platform: str) -> str:
    """保留所有 ``[...]`` 区块外的行，以及包含指定平台的区块内行。

    标记行本身会从输出中删除。
    """
    lines = content.splitlines()
    out: list[str] = []

    in_block = False
    keep_block = False

    for line in lines:
        marker = _parse_marker(line)
        if marker is not None:
            is_closing, names = marker
            if not is_closing:
                in_block = True
                keep_block = _platform_matches(platform, names)
            else:
                in_block = False
                keep_block = False
            continue  # 不把标记行本身写入输出。

        if in_block:
            if keep_block:
                out.append(line)
            continue
        out.append(line)

    # 压缩因移除标记而产生的连续空行（超过 2 行时折叠）。
    collapsed: list[str] = []
    blank_run = 0
    for line in out:
        if line.strip() == "":
            blank_run += 1
            if blank_run <= 2:
                collapsed.append(line)
        else:
            blank_run = 0
            collapsed.append(line)

    return "\n".join(collapsed).rstrip() + "\n"
