#!/usr/bin/env python3
"""
Package 探测与上下文输出。

提供：
    get_packages_info           - 获取结构化 package 信息
    get_packages_section        - 构建 PACKAGES 文本段
    get_context_packages_text   - 完整 package 文本输出（--mode packages）
    get_context_packages_json   - 完整 package JSON 输出（--mode packages --json）
"""

from __future__ import annotations

from pathlib import Path

from .config import _is_true_config_value, get_default_package, get_packages, get_spec_scope
from .paths import (
    DIR_SPEC,
    DIR_WORKFLOW,
    get_current_task,
    get_repo_root,
)
from .tasks import load_task


# =============================================================================
# 内部辅助函数
# =============================================================================

def _scan_spec_layers(spec_dir: Path, package: str | None = None) -> list[str]:
    """扫描规范目录，返回可用的层目录。

    monorepo：扫描 spec/<package>/；
    single-repo：扫描 spec/。
    """
    target = spec_dir / package if package else spec_dir
    if not target.is_dir():
        return []
    return sorted(
        d.name for d in target.iterdir() if d.is_dir() and d.name != "guides"
    )


def _get_active_task_package(repo_root: Path) -> str | None:
    """读取活动任务 task.json 中的 package 字段。"""
    current = get_current_task(repo_root)
    if not current:
        return None
    ct = load_task(repo_root / current)
    return ct.package if ct and ct.package else None


def _resolve_scope_set(
    packages: dict,
    spec_scope,
    task_pkg: str | None,
    default_pkg: str | None,
) -> set | None:
    """将 spec_scope 解析为允许的 package 集合；None 表示扫描全部。"""
    if not packages:
        return None

    if spec_scope is None:
        return None

    if isinstance(spec_scope, str) and spec_scope == "active_task":
        if task_pkg and task_pkg in packages:
            return {task_pkg}
        if default_pkg and default_pkg in packages:
            return {default_pkg}
        return None

    if isinstance(spec_scope, list):
        valid = {e for e in spec_scope if e in packages}
        if valid:
            return valid
        # 全部无效时回退到任务或默认 package。
        if task_pkg and task_pkg in packages:
            return {task_pkg}
        if default_pkg and default_pkg in packages:
            return {default_pkg}
        return None

    return None


# =============================================================================
# 对外函数
# =============================================================================

def get_packages_info(repo_root: Path) -> list[dict]:
    """获取 monorepo 项目的结构化 package 信息。

    返回字段包括 name、path、type、default、specLayers、isSubmodule 和 isGitRepo。
    single-repo 项目返回空列表。
    """
    packages = get_packages(repo_root)
    if not packages:
        return []

    default_pkg = get_default_package(repo_root)
    spec_dir = repo_root / DIR_WORKFLOW / DIR_SPEC
    result = []

    for pkg_name, pkg_config in packages.items():
        pkg_path = pkg_config.get("path", pkg_name) if isinstance(pkg_config, dict) else str(pkg_config)
        pkg_type = pkg_config.get("type", "local") if isinstance(pkg_config, dict) else "local"
        pkg_git = pkg_config.get("git", False) if isinstance(pkg_config, dict) else False
        layers = _scan_spec_layers(spec_dir, pkg_name)

        result.append({
            "name": pkg_name,
            "path": pkg_path,
            "type": pkg_type,
            "default": pkg_name == default_pkg,
            "specLayers": layers,
            "isSubmodule": pkg_type == "submodule",
            "isGitRepo": _is_true_config_value(pkg_git),
        })

    return result


def get_packages_section(repo_root: Path) -> str:
    """构建文本输出中的包信息（PACKAGES）段落。"""
    spec_dir = repo_root / DIR_WORKFLOW / DIR_SPEC
    pkg_info = get_packages_info(repo_root)

    lines: list[str] = []
    lines.append("## PACKAGES（包信息）")

    if not pkg_info:
        lines.append("（单仓库模式：single-repo）")
        layers = _scan_spec_layers(spec_dir)
        if layers:
            lines.append(f"规范层：{', '.join(layers)}")
        return "\n".join(lines)

    default_pkg = get_default_package(repo_root)

    for pkg in pkg_info:
        layers_str = f"  [{', '.join(pkg['specLayers'])}]" if pkg["specLayers"] else ""
        submodule_tag = " （submodule）" if pkg["isSubmodule"] else ""
        git_repo_tag = " （Git 仓库）" if pkg["isGitRepo"] else ""
        default_tag = "  *" if pkg["default"] else ""
        lines.append(
            f"- {pkg['name']:<16} {pkg['path']:<20}{layers_str}{submodule_tag}{git_repo_tag}{default_tag}"
        )

    if default_pkg:
        lines.append(f"默认 package：{default_pkg}")

    return "\n".join(lines)


def get_context_packages_text(repo_root: Path | None = None) -> str:
    """以格式化文本返回 package 上下文（对应 --mode packages）。"""
    if repo_root is None:
        repo_root = get_repo_root()

    pkg_info = get_packages_info(repo_root)
    lines: list[str] = []

    if not pkg_info:
        spec_dir = repo_root / DIR_WORKFLOW / DIR_SPEC
        lines.append("单仓库项目（single-repo，未配置 packages）")
        lines.append("")
        layers = _scan_spec_layers(spec_dir)
        if layers:
            lines.append(f"规范层：{', '.join(layers)}")
        return "\n".join(lines)

    # 解析范围，用于输出标注。
    packages_dict = get_packages(repo_root) or {}
    default_pkg = get_default_package(repo_root)
    spec_scope = get_spec_scope(repo_root)
    task_pkg = _get_active_task_package(repo_root)
    scope_set = _resolve_scope_set(packages_dict, spec_scope, task_pkg, default_pkg)

    lines.append("## PACKAGES（包信息）")
    lines.append("")
    for pkg in pkg_info:
        default_tag = "（默认）" if pkg["default"] else ""
        type_tag = f" [{pkg['type']}]" if pkg["type"] != "local" else ""
        git_tag = " [Git 仓库]" if pkg["isGitRepo"] else ""

        # 范围标注。
        scope_tag = ""
        if scope_set is not None and pkg["name"] not in scope_set:
            scope_tag = "（超出范围）"

        lines.append(f"### {pkg['name']}{default_tag}{type_tag}{git_tag}{scope_tag}")
        lines.append(f"路径：{pkg['path']}")
        if pkg["specLayers"]:
            lines.append(f"规范层：{', '.join(pkg['specLayers'])}")
            for layer in pkg["specLayers"]:
                lines.append(f"  - .trellis/spec/{pkg['name']}/{layer}/index.md")
        else:
            lines.append("规范：未配置")
        lines.append("")

    # 同时显示共享指南。
    guides_dir = repo_root / DIR_WORKFLOW / DIR_SPEC / "guides"
    if guides_dir.is_dir():
        lines.append("### 共享指南（始终包含）")
        lines.append("路径：.trellis/spec/guides/index.md")
        lines.append("")

    return "\n".join(lines)


def get_context_packages_json(repo_root: Path | None = None) -> dict:
    """以字典返回 package 上下文（对应 --mode packages --json）。"""
    if repo_root is None:
        repo_root = get_repo_root()

    pkg_info = get_packages_info(repo_root)

    if not pkg_info:
        spec_dir = repo_root / DIR_WORKFLOW / DIR_SPEC
        layers = _scan_spec_layers(spec_dir)
        return {
            "mode": "single-repo",
            "specLayers": layers,
        }

    default_pkg = get_default_package(repo_root)
    spec_scope = get_spec_scope(repo_root)
    task_pkg = _get_active_task_package(repo_root)

    return {
        "mode": "monorepo",
        "packages": pkg_info,
        "defaultPackage": default_pkg,
        "specScope": spec_scope,
        "activeTaskPackage": task_pkg,
    }
