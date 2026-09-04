"""
终端输出工具：颜色和结构化日志。

Colors 与 log_* 函数的唯一事实来源，供所有 Trellis script 使用。
"""

from __future__ import annotations


class Colors:
    """终端输出使用的 ANSI 颜色码。"""

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    DIM = "\033[2m"
    NC = "\033[0m"  # 无颜色 / 重置


def colored(text: str, color: str) -> str:
    """为文本应用 ANSI 颜色。"""
    return f"{color}{text}{Colors.NC}"


def log_info(msg: str) -> None:
    """以 [INFO] 前缀输出 info 级别消息。"""
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")


def log_success(msg: str) -> None:
    """以 [SUCCESS] 前缀输出成功消息。"""
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {msg}")


def log_warn(msg: str) -> None:
    """以 [WARN] 前缀输出警告消息。"""
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def log_error(msg: str) -> None:
    """以 [ERROR] 前缀输出错误消息。"""
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")
