#!/usr/bin/env python3
"""
获取当前开发者名称。

这是对 common/paths.py 的包装。
"""

from __future__ import annotations

import sys

from common.paths import get_developer


def main() -> None:
    """CLI 入口。"""
    developer = get_developer()
    if developer:
        print(developer)
    else:
        print("尚未初始化开发者身份。", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
