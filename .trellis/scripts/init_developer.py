#!/usr/bin/env python3
"""
为 Trellis workflow 初始化开发者身份。

用法：
    python3 init_developer.py <developer-name>

此命令会创建：
    - 包含开发者信息的 .trellis/.developer 文件
    - .trellis/workspace/<name>/ 目录结构
"""

from __future__ import annotations

import sys

from common.paths import (
    DIR_WORKFLOW,
    FILE_DEVELOPER,
    get_developer,
)
from common.developer import init_developer


def main() -> None:
    """CLI 入口。"""
    if len(sys.argv) < 2:
        print(f"用法：{sys.argv[0]} <developer-name>")
        print()
        print("示例：")
        print(f"  {sys.argv[0]} john")
        sys.exit(1)

    name = sys.argv[1]

    # 检查是否已经初始化
    existing = get_developer()
    if existing:
        print(f"开发者身份已初始化：{existing}")
        print()
        print(f"如需重新初始化，请先删除 {DIR_WORKFLOW}/{FILE_DEVELOPER}")
        sys.exit(0)

    if init_developer(name):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
