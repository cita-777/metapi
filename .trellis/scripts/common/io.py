"""
JSON 文件 I/O 工具。

为所有 Trellis script 提供 read_json 和 write_json，作为 JSON 文件操作的唯一事实来源。
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def read_json(path: Path) -> dict | None:
    """读取并解析 JSON 文件。

    文件不存在、JSON 无效或无法读取时返回 None。
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def write_json(path: Path, data: dict) -> bool:
    """以易读格式将 dict 写入 JSON 文件。

    写入是原子的：内容先写入同目录临时文件，再重命名覆盖目标。写入中途崩溃或按下
    Ctrl-C 会保留原文件而不是留下截断文件，因此损坏的 task.json 不会让任务从
    `task.py list` 中静默消失。

    成功返回 True，出错返回 False。
    """
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    try:
        fd, tmp = tempfile.mkstemp(
            dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
        )
    except OSError:
        return False

    try:
        try:
            f = os.fdopen(fd, "w", encoding="utf-8")
        except OSError:
            # fdopen 没有取得 fd 的所有权，需要手动关闭。
            os.close(fd)
            raise
        with f:
            f.write(payload)
        os.replace(tmp, path)
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
