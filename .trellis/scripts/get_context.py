#!/usr/bin/env python3
"""
获取 AI agent 的 session 上下文。

用法：
    python3 get_context.py           以文本格式输出上下文
    python3 get_context.py --json    以 JSON 格式输出上下文
"""

from __future__ import annotations

from common.git_context import main


if __name__ == "__main__":
    main()
