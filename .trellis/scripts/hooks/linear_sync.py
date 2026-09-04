#!/usr/bin/env python3
"""Trellis 任务生命周期的 Linear 同步 hook。

通过 `linearis` CLI 将任务事件同步到 Linear。

用法（由 task.py hook 自动调用）：
    python3 .trellis/scripts/hooks/linear_sync.py create
    python3 .trellis/scripts/hooks/linear_sync.py start
    python3 .trellis/scripts/hooks/linear_sync.py archive

手动用法：
    TASK_JSON_PATH=.trellis/tasks/<name>/task.json python3 .trellis/scripts/hooks/linear_sync.py sync

环境变量：
    TASK_JSON_PATH  - task.json 的绝对路径（由 task.py 设置）

配置：
    .trellis/hooks.local.json  - 本地配置（已加入 gitignore），示例：
    {
      "linear": {
        "team": "TEAM_KEY",
        "project": "示例项目",
        "assignees": {
          "开发者名称": "linear-user-id"
        }
      }
    }
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# ─── 配置 ─────────────────────────────────────────────────────────────────────

# Trellis priority → Linear priority（1=紧急，2=高，3=中，4=低；数值含义由 Linear 定义）。
PRIORITY_MAP = {"P0": 1, "P1": 2, "P2": 3, "P3": 4}

# Linear status 名称（必须与团队 workflow 一致）。
STATUS_IN_PROGRESS = "In Progress"
STATUS_DONE = "Done"


def _load_config() -> dict:
    """从 .trellis/hooks.local.json 加载本地 hook 配置。"""
    task_json_path = os.environ.get("TASK_JSON_PATH", "")
    if task_json_path:
        # 从 task.json 向上查找 .trellis/。
        trellis_dir = Path(task_json_path).parent.parent.parent
    else:
        trellis_dir = Path(".trellis")

    config_path = trellis_dir / "hooks.local.json"
    try:
        with open(config_path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


CONFIG = _load_config()
LINEAR_CFG = CONFIG.get("linear", {})

TEAM = LINEAR_CFG.get("team", "")
PROJECT = LINEAR_CFG.get("project", "")
ASSIGNEE_MAP = LINEAR_CFG.get("assignees", {})

# ─── 辅助函数 ─────────────────────────────────────────────────────────────────


def _read_task() -> tuple[dict, str]:
    path = os.environ.get("TASK_JSON_PATH", "")
    if not path:
        print("未设置 TASK_JSON_PATH。", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return json.load(f), path


def _write_task(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _linearis(*args: str) -> dict | None:
    result = subprocess.run(
        ["linearis", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        print(f"linearis 出错：{result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    stdout = result.stdout.strip()
    if stdout:
        return json.loads(stdout)
    return None


def _get_linear_issue(task: dict) -> str | None:
    meta = task.get("meta")
    if isinstance(meta, dict):
        return meta.get("linear_issue")
    return None


# ─── 操作 ─────────────────────────────────────────────────────────────────────


def cmd_create() -> None:
    if not TEAM:
        print("hooks.local.json 未配置 linear.team。", file=sys.stderr)
        sys.exit(1)

    task, path = _read_task()

    # 已关联时跳过。
    if _get_linear_issue(task):
        print(f"已关联：{_get_linear_issue(task)}")
        return

    title = task.get("title") or task.get("name") or "未命名任务"
    args = ["issues", "create", title, "--team", TEAM]

    # 映射 priority。
    priority = PRIORITY_MAP.get(task.get("priority", ""), 0)
    if priority:
        args.extend(["-p", str(priority)])

    # 设置 project。
    if PROJECT:
        args.extend(["--project", PROJECT])

    # 分配给 Linear 用户。
    assignee = task.get("assignee", "")
    linear_user_id = ASSIGNEE_MAP.get(assignee)
    if linear_user_id:
        args.extend(["--assignee", linear_user_id])

    # 如果 parent 已有 Linear issue，则建立关联。
    parent_issue = _resolve_parent_linear_issue(task)
    if parent_issue:
        args.extend(["--parent-ticket", parent_issue])

    result = _linearis(*args)
    if result and "identifier" in result:
        if not isinstance(task.get("meta"), dict):
            task["meta"] = {}
        task["meta"]["linear_issue"] = result["identifier"]
        _write_task(task, path)
        print(f"已创建 Linear issue：{result['identifier']}")


def cmd_start() -> None:
    task, _ = _read_task()
    issue = _get_linear_issue(task)
    if not issue:
        return
    _linearis("issues", "update", issue, "-s", STATUS_IN_PROGRESS)
    print(f"已更新 {issue} -> {STATUS_IN_PROGRESS}")
    cmd_sync()


def cmd_archive() -> None:
    task, _ = _read_task()
    issue = _get_linear_issue(task)
    if not issue:
        return
    _linearis("issues", "update", issue, "-s", STATUS_DONE)
    print(f"已更新 {issue} -> {STATUS_DONE}")


def cmd_sync() -> None:
    """将 prd.md 内容同步到 Linear issue description。"""
    task, _ = _read_task()
    issue = _get_linear_issue(task)
    if not issue:
        print("meta 中没有 linear_issue，请先运行 create。", file=sys.stderr)
        sys.exit(1)

    # 查找 task.json 旁边的 prd.md。
    task_json_path = os.environ.get("TASK_JSON_PATH", "")
    prd_path = Path(task_json_path).parent / "prd.md"
    if not prd_path.is_file():
        print(f"在 {prd_path} 找不到 prd.md。", file=sys.stderr)
        sys.exit(1)

    description = prd_path.read_text(encoding="utf-8").strip()
    _linearis("issues", "update", issue, "-d", description)
    print(f"已将 prd.md 同步到 {issue} 的 description。")


# ─── Parent Issue 解析 ───────────────────────────────────────────────────────


def _resolve_parent_linear_issue(task: dict) -> str | None:
    """查找 parent 任务的 Linear issue 标识符。"""
    parent_name = task.get("parent")
    if not parent_name:
        return None

    task_json_path = os.environ.get("TASK_JSON_PATH", "")
    if not task_json_path:
        return None

    current_task_dir = Path(task_json_path).parent
    tasks_dir = current_task_dir.parent
    parent_json = tasks_dir / parent_name / "task.json"

    if parent_json.exists():
        try:
            with open(parent_json, encoding="utf-8") as f:
                parent_task = json.load(f)
            return _get_linear_issue(parent_task)
        except (json.JSONDecodeError, OSError):
            pass
    return None


# ─── 主入口 ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    actions = {
        "create": cmd_create,
        "start": cmd_start,
        "archive": cmd_archive,
        "sync": cmd_sync,
    }
    fn = actions.get(action)
    if fn:
        fn()
    else:
        print(f"未知 action：{action}", file=sys.stderr)
        print(f"有效 action：{', '.join(actions)}", file=sys.stderr)
        sys.exit(1)
