"""
多平台 CLI 适配器。

抽象 Claude Code、OpenCode、Cursor、iFlow、Codex、Kilo、Kiro Code、Gemini CLI、
Antigravity、Devin、Qoder、CodeBuddy、GitHub Copilot、Factory Droid 和 Pi Agent
接口之间的差异。

支持的平台：
- claude：Claude Code（默认）
- opencode：OpenCode
- cursor：Cursor IDE
- iflow：iFlow CLI
- codex：Codex CLI（基于 skills）
- kilo：Kilo CLI
- kiro：Kiro Code（基于 skills）
- gemini：Gemini CLI
- antigravity：Antigravity（基于 workflow）
- devin：Devin（原名 Windsurf；基于 workflow）
- qoder：Qoder
- codebuddy：CodeBuddy
- copilot：GitHub Copilot（VS Code）
- droid：Factory Droid（基于 commands）
- pi：Pi Agent（基于 extension）
- trae：Trae IDE（仅 IDE、基于 hooks）
- omp：Oh My Pi
- grok：Grok Build（基于 pull 的 skills/agents；不注入 hook context）
- kimi：Kimi Code（基于 pull 的 skills；commands 作为 skills 提供；不注入 hook context）

用法：
    from common.cli_adapter import CLIAdapter

    adapter = CLIAdapter("opencode")
    cmd = adapter.build_run_command(
        agent="dispatch",
        session_id="abc123",
        prompt="开始流水线"
    )
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal

Platform = Literal[
    "claude",
    "opencode",
    "cursor",
    "iflow",
    "codex",
    "kilo",
    "kiro",
    "gemini",
    "antigravity",
    "devin",
    "qoder",
    "codebuddy",
    "copilot",
    "droid",
    "pi",
    "trae",
    "omp",
    "grok",
    "kimi",
]


@dataclass
class CLIAdapter:
    """适配不同的 AI 编程 CLI 工具。"""

    platform: Platform

    # =========================================================================
    # Agent 名称映射
    # =========================================================================

    # OpenCode 有不能覆盖的内置 agent。
    # 参见：https://github.com/sst/opencode/issues/4271
    # 注意：这是类级常量，不是 dataclass 字段。
    _AGENT_NAME_MAP: ClassVar[dict[Platform, dict[str, str]]] = {
        "claude": {},  # 不需要映射
        "opencode": {
            "plan": "trellis-plan",  # OpenCode 内置了 'plan'
        },
    }

    def get_agent_name(self, agent: str) -> str:
        """获取平台专用的 agent 名称。

        参数：
            agent：原始 agent 名称（例如 'plan'、'dispatch'）

        返回：
            平台专用的 agent 名称（例如 OpenCode 使用 'trellis-plan'）
        """
        mapping = self._AGENT_NAME_MAP.get(self.platform, {})
        return mapping.get(agent, agent)

    # =========================================================================
    # Agent 路径
    # =========================================================================

    @property
    def config_dir_name(self) -> str:
        """获取平台专用的配置目录名称。

        返回：
            目录名称（'.claude'、'.opencode'、'.cursor'、'.iflow'、'.codex'、
            '.kilocode'、'.kiro'、'.gemini'、'.agent'、'.devin'、'.qoder'、
            '.codebuddy'、'.github/copilot'、'.factory'、'.pi' 或 '.trae'）
        """
        if self.platform == "opencode":
            return ".opencode"
        elif self.platform == "cursor":
            return ".cursor"
        elif self.platform == "iflow":
            return ".iflow"
        elif self.platform == "codex":
            return ".codex"
        elif self.platform == "kilo":
            return ".kilocode"
        elif self.platform == "kiro":
            return ".kiro"
        elif self.platform == "gemini":
            return ".gemini"
        elif self.platform == "antigravity":
            return ".agent"
        elif self.platform == "devin":
            return ".devin"
        elif self.platform == "qoder":
            return ".qoder"
        elif self.platform == "codebuddy":
            return ".codebuddy"
        elif self.platform == "copilot":
            return ".github/copilot"
        elif self.platform == "droid":
            return ".factory"
        elif self.platform == "pi":
            return ".pi"
        elif self.platform == "trae":
            return ".trae"
        elif self.platform == "omp":
            return ".omp"
        elif self.platform == "grok":
            return ".grok"
        elif self.platform == "kimi":
            return ".kimi-code"
        else:
            return ".claude"

    def get_config_dir(self, project_root: Path) -> Path:
        """获取平台专用的配置目录。

        参数：
            project_root：项目根目录

        返回：
            配置目录路径（.claude、.opencode、.cursor、.iflow、.codex、.kilocode、
            .kiro、.gemini、.agent、.devin、.qoder、.codebuddy、.github/copilot、
            .factory、.pi 或 .trae）
        """
        return project_root / self.config_dir_name

    def get_agent_path(self, agent: str, project_root: Path) -> Path:
        """获取 agent 定义文件路径。

        参数：
            agent：agent 名称（映射前的原始名称）
            project_root：项目根目录

        返回：
            agent 定义文件路径（大多数平台使用 .md，Codex 使用 .toml）
        """
        mapped_name = self.get_agent_name(agent)
        if self.platform == "codex":
            return self.get_config_dir(project_root) / "agents" / f"{mapped_name}.toml"
        return self.get_config_dir(project_root) / "agents" / f"{mapped_name}.md"

    def get_commands_path(self, project_root: Path, *parts: str) -> Path:
        """获取 commands 目录或具体 command 文件的路径。

        参数：
            project_root：项目根目录
            *parts：额外路径片段（例如 'trellis'、'finish-work.md'）

        返回：
            commands 目录或文件路径

        说明：
            Cursor 使用前缀命名：.cursor/commands/trellis-<name>.md
            Antigravity 使用 workflow 目录：.agent/workflows/<name>.md
            Devin 使用 workflow 目录：.devin/workflows/trellis-<name>.md
            Copilot 使用 prompt 文件：.github/prompts/<name>.prompt.md
            Pi 使用 prompt 模板：.pi/prompts/trellis-<name>.md
            Claude/OpenCode 使用子目录：.claude/commands/trellis/<name>.md
        """
        if self.platform == "pi":
            prompts_dir = self.get_config_dir(project_root) / "prompts"
            if not parts:
                return prompts_dir
            if len(parts) >= 2 and parts[0] == "trellis":
                filename = parts[-1]
                if filename.endswith(".md"):
                    filename = filename[:-3]
                return prompts_dir / f"trellis-{filename}.md"
            return prompts_dir / Path(*parts)
        # OMP 和 Grok：扁平的 slash command 路径为 .{platform}/commands/trellis-<name>.md
        if self.platform in ("omp", "grok"):
            commands_dir = self.get_config_dir(project_root) / "commands"
            if not parts:
                return commands_dir
            if len(parts) >= 2 and parts[0] == "trellis":
                filename = parts[-1]
                if filename.endswith(".md"):
                    filename = filename[:-3]
                return commands_dir / f"trellis-{filename}.md"
            return commands_dir / Path(*parts)

        # Kimi：commands 作为 skills，路径为 .kimi-code/skills/trellis-<name>/SKILL.md
        if self.platform == "kimi":
            skills_dir = self.get_config_dir(project_root) / "skills"
            if not parts:
                return skills_dir
            if len(parts) >= 2 and parts[0] == "trellis":
                filename = parts[-1]
                if filename.endswith(".md"):
                    filename = filename[:-3]
                return skills_dir / f"trellis-{filename}" / "SKILL.md"
            return skills_dir / Path(*parts)

        if self.platform == "devin":
            workflow_dir = self.get_config_dir(project_root) / "workflows"
            if not parts:
                return workflow_dir
            if len(parts) >= 2 and parts[0] == "trellis":
                filename = parts[-1]
                return workflow_dir / f"trellis-{filename}"
            return workflow_dir / Path(*parts)

        if self.platform in ("antigravity", "kilo"):
            workflow_dir = self.get_config_dir(project_root) / "workflows"
            if not parts:
                return workflow_dir
            if len(parts) >= 2 and parts[0] == "trellis":
                filename = parts[-1]
                return workflow_dir / filename
            return workflow_dir / Path(*parts)

        if self.platform == "copilot":
            prompts_dir = project_root / ".github" / "prompts"
            if not parts:
                return prompts_dir
            if len(parts) >= 2 and parts[0] == "trellis":
                filename = parts[-1]
                if filename.endswith(".md"):
                    filename = filename[:-3]
                return prompts_dir / f"{filename}.prompt.md"
            return prompts_dir / Path(*parts)

        if not parts:
            return self.get_config_dir(project_root) / "commands"

        # Cursor 使用前缀命名，而不是子目录
        if self.platform == "cursor" and len(parts) >= 2 and parts[0] == "trellis":
            # 将 trellis/<name>.md 转换为 trellis-<name>.md
            filename = parts[-1]
            return (
                self.get_config_dir(project_root) / "commands" / f"trellis-{filename}"
            )

        return self.get_config_dir(project_root) / "commands" / Path(*parts)

    def get_trellis_command_path(self, name: str) -> str:
        """获取 Trellis command 文件的相对路径。

        参数：
            name：不带扩展名的 command 名称（例如 'finish-work'、'check'）

        返回：
            用于 JSONL 条目的相对路径字符串

        说明：
            Cursor：.cursor/commands/trellis-<name>.md
            Codex：.agents/skills/trellis-<name>/SKILL.md
            Kiro：.kiro/skills/trellis-<name>/SKILL.md
            Gemini：.gemini/commands/trellis/<name>.toml
            Antigravity：.agent/workflows/<name>.md
            Devin：.devin/workflows/trellis-<name>.md
            Pi：.pi/prompts/trellis-<name>.md
            其他平台：.{platform}/commands/trellis/<name>.md
        """
        if self.platform == "cursor":
            return f".cursor/commands/trellis-{name}.md"
        elif self.platform == "codex":
            # 0.5.0-beta.0 将所有 skill 目录重命名为带 `trellis-` 前缀
            # （60 多条重命名记录见该版本的 manifest）。
            return f".agents/skills/trellis-{name}/SKILL.md"
        elif self.platform == "kiro":
            return f".kiro/skills/trellis-{name}/SKILL.md"
        elif self.platform == "gemini":
            return f".gemini/commands/trellis/{name}.toml"
        elif self.platform == "antigravity":
            return f".agent/workflows/{name}.md"
        elif self.platform == "devin":
            return f".devin/workflows/trellis-{name}.md"
        elif self.platform == "kilo":
            return f".kilocode/workflows/{name}.md"
        elif self.platform == "copilot":
            return f".github/prompts/{name}.prompt.md"
        elif self.platform == "droid":
            return f".factory/commands/trellis/{name}.md"
        elif self.platform == "pi":
            return f".pi/prompts/trellis-{name}.md"
        elif self.platform in ("omp", "grok"):
            return f"{self.config_dir_name}/commands/trellis-{name}.md"
        elif self.platform == "kimi":
            return f".kimi-code/skills/trellis-{name}/SKILL.md"
        else:
            return f"{self.config_dir_name}/commands/trellis/{name}.md"

    # =========================================================================
    # 环境变量
    # =========================================================================

    def get_non_interactive_env(self) -> dict[str, str]:
        """获取非交互模式所需的环境变量。

        返回：
            要设置的环境变量字典
        """
        if self.platform == "opencode":
            return {"OPENCODE_NON_INTERACTIVE": "1"}
        elif self.platform == "iflow":
            return {"IFLOW_NON_INTERACTIVE": "1"}
        elif self.platform == "codex":
            return {"CODEX_NON_INTERACTIVE": "1"}
        elif self.platform == "kiro":
            return {"KIRO_NON_INTERACTIVE": "1"}
        elif self.platform == "gemini":
            return {}  # Gemini CLI 没有非交互环境变量
        elif self.platform == "antigravity":
            return {}
        elif self.platform == "devin":
            return {}
        elif self.platform == "qoder":
            return {}
        elif self.platform == "codebuddy":
            return {}
        elif self.platform == "copilot":
            return {}
        elif self.platform == "droid":
            return {}
        elif self.platform == "pi":
            return {}
        elif self.platform == "trae":
            return {}
        elif self.platform == "omp":
            return {}
        elif self.platform == "grok":
            return {}
        elif self.platform == "kimi":
            return {}
        else:
            return {"CLAUDE_NON_INTERACTIVE": "1"}

    # =========================================================================
    # CLI command 构建
    # =========================================================================

    def build_run_command(
        self,
        agent: str,
        prompt: str,
        session_id: str | None = None,
        skip_permissions: bool = True,
        verbose: bool = True,
        json_output: bool = True,
    ) -> list[str]:
        """构建运行 agent 的 CLI command。

        参数：
            agent：agent 名称（必要时会映射）
            prompt：发送给 agent 的 prompt
            session_id：可选 session ID（仅 Claude Code 创建时支持）
            skip_permissions：是否跳过权限提示
            verbose：是否启用详细输出
            json_output：是否使用 JSON 输出格式

        返回：
            command 参数列表
        """
        mapped_agent = self.get_agent_name(agent)

        if self.platform == "opencode":
            cmd = ["opencode", "run"]
            cmd.extend(["--agent", mapped_agent])

            # 注意：OpenCode 的 'run' 模式默认是非交互的。
            # 没有等价于 Claude Code --dangerously-skip-permissions 的选项。
            # 参见：https://github.com/anomalyco/opencode/issues/9070

            if json_output:
                cmd.extend(["--format", "json"])

            if verbose:
                cmd.extend(["--log-level", "DEBUG", "--print-logs"])

            # 注意：OpenCode 创建时不支持 --session-id。
            # session ID 必须在启动后从日志提取。

            cmd.append(prompt)

        elif self.platform == "iflow":
            cmd = ["iflow", "-y", "-p"]
            cmd.append(f"${mapped_agent} {prompt}")
        elif self.platform == "codex":
            cmd = ["codex", "exec"]
            cmd.append(prompt)
        elif self.platform == "kiro":
            cmd = ["kiro", "run", prompt]
        elif self.platform == "gemini":
            cmd = ["gemini"]
            cmd.append(prompt)
        elif self.platform == "antigravity":
            raise ValueError(
                "Antigravity workflow 是 UI slash command；不支持 CLI agent run。"
            )
        elif self.platform == "devin":
            raise ValueError(
                "Devin workflow 是 UI slash command；不支持 CLI agent run。"
            )
        elif self.platform == "qoder":
            cmd = ["qodercli", "-p", prompt]
        elif self.platform == "codebuddy":
            raise ValueError(
                "CodeBuddy 不支持 non-interactive mode（没有 CLI agent）。"
            )
        elif self.platform == "copilot":
            raise ValueError(
                "GitHub Copilot 仅支持 IDE；不支持 CLI agent run。"
            )
        elif self.platform == "droid":
            raise ValueError(
                "Factory Droid 暂不支持 CLI agent run。"
            )
        elif self.platform == "pi":
            cmd = ["pi", "-p", prompt]
        elif self.platform == "trae":
            raise ValueError(
                "Trae 仅支持 IDE；不支持 CLI agent run。"
            )
        elif self.platform == "omp":
            raise ValueError(
                "OMP 使用原生 task tool 运行 agent；不支持 CLI agent run。"
            )
        elif self.platform == "grok":
            # 无头单 prompt；sub-agent 使用进程内 spawn_subagent。
            cmd = ["grok", "-p", prompt, "--yolo"]
        elif self.platform == "kimi":
            # 无头单 prompt 并自动批准；sub-agent 是在 session 内分发的内置
            # coder/explore/plan agent。
            cmd = ["kimi", "-p", prompt, "--yolo"]

        else:  # claude
            cmd = ["claude", "-p"]
            cmd.extend(["--agent", mapped_agent])

            if session_id:
                cmd.extend(["--session-id", session_id])

            if skip_permissions:
                cmd.append("--dangerously-skip-permissions")

            if json_output:
                cmd.extend(["--output-format", "stream-json"])

            if verbose:
                cmd.append("--verbose")

            cmd.append(prompt)

        return cmd

    def build_resume_command(self, session_id: str) -> list[str]:
        """构建恢复 session 的 CLI command。

        参数：
            session_id：要恢复的 session ID（iFlow 会忽略）

        返回：
            command 参数列表
        """
        if self.platform == "opencode":
            return ["opencode", "run", "--session", session_id]
        elif self.platform == "iflow":
            # iFlow 使用 -c 继续最近的 conversation。
            # iFlow 不支持 session ID，因此忽略 session_id。
            return ["iflow", "-c"]
        elif self.platform == "codex":
            return ["codex", "resume", session_id]
        elif self.platform == "kiro":
            return ["kiro", "resume", session_id]
        elif self.platform == "gemini":
            return ["gemini", "--resume", session_id]
        elif self.platform == "antigravity":
            raise ValueError(
                "Antigravity workflow 是 UI slash command；不支持 CLI resume。"
            )
        elif self.platform == "devin":
            raise ValueError(
                "Devin workflow 是 UI slash command；不支持 CLI resume。"
            )
        elif self.platform == "qoder":
            return ["qodercli", "--resume", session_id]
        elif self.platform == "codebuddy":
            raise ValueError(
                "CodeBuddy 不支持 non-interactive mode（没有 CLI agent）。"
            )
        elif self.platform == "copilot":
            raise ValueError(
                "GitHub Copilot 仅支持 IDE；不支持 CLI resume。"
            )
        elif self.platform == "droid":
            raise ValueError(
                "Factory Droid 暂不支持 CLI resume。"
            )
        elif self.platform == "pi":
            return ["pi", "-c", session_id]
        elif self.platform == "trae":
            raise ValueError(
                "Trae 仅支持 IDE；不支持 CLI resume。"
            )
        elif self.platform == "omp":
            raise ValueError(
                "OMP 使用原生 task tool 运行 agent；不支持 CLI resume。"
            )
        elif self.platform == "grok":
            return ["grok", "-c"]
        elif self.platform == "kimi":
            return ["kimi", "--session", session_id]
        else:
            return ["claude", "--resume", session_id]

    def get_resume_command_str(self, session_id: str, cwd: str | None = None) -> str:
        """获取供人阅读的恢复 command 字符串。

        参数：
            session_id：要恢复的 session ID
            cwd：可选的工作目录（先执行 cd）

        返回：
            用于展示的 command 字符串
        """
        cmd = self.build_resume_command(session_id)
        cmd_str = " ".join(cmd)

        if cwd:
            return f"cd {cwd} && {cmd_str}"
        return cmd_str

    # =========================================================================
    # 平台检测辅助方法
    # =========================================================================

    @property
    def is_opencode(self) -> bool:
        """判断平台是否为 OpenCode。"""
        return self.platform == "opencode"

    @property
    def is_claude(self) -> bool:
        """判断平台是否为 Claude Code。"""
        return self.platform == "claude"

    @property
    def is_cursor(self) -> bool:
        """判断平台是否为 Cursor。"""
        return self.platform == "cursor"

    @property
    def is_iflow(self) -> bool:
        """判断平台是否为 iFlow CLI。"""
        return self.platform == "iflow"

    @property
    def cli_name(self) -> str:
        """获取 CLI 可执行文件名称。

        注意：Cursor 没有 CLI 工具，此处返回类似 None 的占位值。
        """
        if self.is_opencode:
            return "opencode"
        elif self.is_cursor:
            return "cursor"  # 注意：Cursor 仅支持 IDE，没有 CLI
        elif self.platform == "iflow":
            return "iflow"
        elif self.platform == "kiro":
            return "kiro"
        elif self.platform == "gemini":
            return "gemini"
        elif self.platform == "antigravity":
            return "agy"
        elif self.platform == "devin":
            return "devin"
        elif self.platform == "qoder":
            return "qodercli"
        elif self.platform == "codebuddy":
            return "codebuddy"
        elif self.platform == "copilot":
            return "copilot"
        elif self.platform == "droid":
            return "droid"
        elif self.platform == "pi":
            return "pi"
        elif self.platform == "trae":
            return "trae"
        elif self.platform == "omp":
            return "omp"
        elif self.platform == "grok":
            return "grok"
        elif self.platform == "kimi":
            return "kimi"
        else:
            return "claude"

    @property
    def supports_cli_agents(self) -> bool:
        """判断平台是否支持通过 CLI 运行 agent。

        Claude Code、OpenCode、iFlow、Codex 支持 CLI agent 执行；Cursor 仅支持 IDE，
        不支持 CLI agent。
        """
        return self.platform in (
            "claude",
            "opencode",
            "iflow",
            "codex",
            "pi",
            "grok",
            "kimi",
        )

    @property
    def requires_agent_definition_file(self) -> bool:
        """判断平台是否需要 agent 定义文件（.md/.toml）才能运行。

        Claude Code、OpenCode、iFlow：需要 agent .md 文件（--agent flag）。
        Codex：自动发现 .codex/agents/*.toml，不需要 --agent flag。
        """
        return self.platform in ("claude", "opencode", "iflow")

    # =========================================================================
    # Session ID 处理
    # =========================================================================

    @property
    def supports_session_id_on_create(self) -> bool:
        """判断平台是否支持创建时指定 session ID。

        Claude Code：支持（--session-id）。
        OpenCode：不支持（自动生成，需从日志提取）。
        iFlow：不支持（没有 session ID 能力）。
        """
        return self.platform == "claude"

    def extract_session_id_from_log(self, log_content: str) -> str | None:
        """从日志输出提取 session ID（仅 OpenCode）。

        OpenCode 生成的 session ID 格式为：ses_xxx。

        参数：
            log_content：日志文件内容

        返回：
            找到时返回 session ID，否则返回 None
        """
        import re

        # OpenCode session ID 模式
        match = re.search(r"ses_[a-zA-Z0-9]+", log_content)
        if match:
            return match.group(0)
        return None


# =============================================================================
# 工厂函数
# =============================================================================


def get_cli_adapter(platform: str = "claude") -> CLIAdapter:
    """获取指定平台的 CLI 适配器。

    参数：
        platform：平台名称（'claude'、'opencode'、'cursor'、'iflow'、'codex'、
            'kilo'、'kiro'、'gemini'、'antigravity'、'devin'、'qoder'、'codebuddy'、
            'copilot'、'droid'、'pi' 或 'trae'）

    返回：
        CLIAdapter 实例

    异常：
        ValueError：平台不受支持时抛出

    说明：
        'windsurf' 作为 'devin' 的弃用别名接受（Windsurf 已更名为 Devin），并在
        校验前归一化。
    """
    # 弃用别名：Windsurf 已更名为 Devin。
    if platform == "windsurf":
        platform = "devin"
    if platform not in (
        "claude",
        "opencode",
        "cursor",
        "iflow",
        "codex",
        "kilo",
        "kiro",
        "gemini",
        "antigravity",
        "devin",
        "qoder",
        "codebuddy",
        "copilot",
        "droid",
        "pi",
        "trae",
        "omp",
        "grok",
        "kimi",
    ):
        raise ValueError(
            f"不支持的平台：{platform}（必须是 'claude'、'opencode'、'cursor'、'iflow'、'codex'、'kilo'、'kiro'、'gemini'、'antigravity'、'devin'、'qoder'、'codebuddy'、'copilot'、'droid'、'pi'、'trae'、'omp'、'grok' 或 'kimi'）"
        )

    return CLIAdapter(platform=platform)  # type: ignore


_ALL_PLATFORM_CONFIG_DIRS = (
    ".claude",
    ".cursor",
    ".iflow",
    ".opencode",
    ".codex",
    ".kilocode",
    ".kiro",
    ".gemini",
    ".agent",
    ".devin",
    ".windsurf",  # 已弃用：Devin 重命名前的配置目录，仍作为平台信号。
    ".qoder",
    ".codebuddy",
    ".github/copilot",
    ".factory",
    ".pi",
    ".trae",
    ".omp",
    ".grok",
    ".kimi-code",
)
"""detect_platform 排除检查使用的平台配置目录名称。

这里不列出 `.agents/skills/`：它是跨平台共享层（由 Codex 写入，也可由
Amp/Cline/Warp 等通过 agentskills.io 标准消费），不能作为单一平台信号。它的存在
不应阻止 Kiro、Antigravity、Devin 或其他平台的检测。
"""


def _has_other_platform_dir(project_root: Path, exclude: set[str]) -> bool:
    """检查除 *exclude* 外是否存在其他平台配置目录。"""
    return any(
        (project_root / d).is_dir()
        for d in _ALL_PLATFORM_CONFIG_DIRS
        if d not in exclude
    )


def detect_platform(project_root: Path) -> Platform:
    """根据现有配置目录自动检测平台。

    检测顺序：
    1. 设置了 TRELLIS_PLATFORM 环境变量时使用它；
    2. 存在 .opencode 目录 → opencode；
    3. 存在 .iflow 目录 → iflow；
    4. 存在 .cursor 且不存在 .claude → cursor；
    5. 存在 .gemini 目录 → gemini；
    6. 存在 .codex 且没有其他平台目录 → codex；
    7. 存在 .kilocode 目录 → kilo；
    8. 存在 .kiro/skills 且没有其他平台目录 → kiro；
    9. 存在 .agent/workflows 且没有其他平台目录 → antigravity；
    10. 存在 .devin/workflows（或旧的 .windsurf/workflows）且没有其他平台目录 → devin；
    11. 存在 .codebuddy 目录 → codebuddy；
    12. 存在 .qoder 目录 → qoder；
    13. 存在 .github/copilot 目录 → copilot；
    14. 存在 .factory 目录 → droid；
    15. 存在 .pi 目录 → pi；
    16. 存在 .trae 目录 → trae；
    17. 默认 → claude。

    参数：
        project_root：项目根目录

    返回：
        检测到的平台（'claude'、'opencode'、'cursor'、'iflow'、'codex'、'kilo'、
        'kiro'、'gemini'、'antigravity'、'devin'、'qoder'、'codebuddy'、'copilot'、
        'droid'、'pi'、'trae'，或默认的 'claude'）
    """
    import os

    # 先检查环境变量。
    env_platform = os.environ.get("TRELLIS_PLATFORM", "").lower()
    # 弃用别名：Windsurf 已更名为 Devin。
    if env_platform == "windsurf":
        env_platform = "devin"
    if env_platform in (
        "claude",
        "opencode",
        "cursor",
        "iflow",
        "codex",
        "kilo",
        "kiro",
        "gemini",
        "antigravity",
        "devin",
        "qoder",
        "codebuddy",
        "copilot",
        "droid",
        "pi",
        "trae",
        "omp",
        "grok",
        "kimi",
    ):
        return env_platform  # type: ignore

    # 检查 .opencode 目录（OpenCode 专用）。
    if (project_root / ".opencode").is_dir():
        return "opencode"

    # 检查 .iflow 目录（iFlow 专用）。
    if (project_root / ".iflow").is_dir():
        return "iflow"

    # 检查 .cursor 目录（Cursor 专用）。
    # 只有在 .claude 不存在时才检测为 cursor，以免混淆。
    if (project_root / ".cursor").is_dir() and not (project_root / ".claude").is_dir():
        return "cursor"

    # 检查 .gemini 目录（Gemini CLI 专用）。
    if (project_root / ".gemini").is_dir():
        return "gemini"

    # 检查 .codex 目录（Codex 专用）。
    # 仅有 .agents/skills/ 不会触发 codex 检测（它是共享标准）。
    if (project_root / ".codex").is_dir() and not _has_other_platform_dir(
        project_root, {".codex", ".agents"}
    ):
        return "codex"

    # 检查 .kilocode 目录（Kilo 专用）。
    if (project_root / ".kilocode").is_dir():
        return "kilo"

    # 只有不存在其他平台配置时才检查 Kiro skills 目录。
    if (project_root / ".kiro" / "skills").is_dir() and not _has_other_platform_dir(
        project_root, {".kiro"}
    ):
        return "kiro"

    # 只有不存在其他平台配置时才检查 Antigravity workflow 目录。
    if (
        project_root / ".agent" / "workflows"
    ).is_dir() and not _has_other_platform_dir(
        project_root, {".agent", ".gemini"}
    ):
        return "antigravity"

    # 只有不存在其他平台配置时才检查 Devin workflow 目录。`.windsurf/workflows` 是
    # 更名之前的旧路径（在用户通过 `trellis update --migrate` 迁移前，为兼容性仍检测为 devin）。
    if (
        (project_root / ".devin" / "workflows").is_dir()
        or (project_root / ".windsurf" / "workflows").is_dir()
    ) and not _has_other_platform_dir(
        project_root, {".devin", ".windsurf"}
    ):
        return "devin"

    # 检查 .codebuddy 目录（CodeBuddy 专用）。
    if (project_root / ".codebuddy").is_dir():
        return "codebuddy"

    # 检查 .qoder 目录（Qoder 专用）。
    if (project_root / ".qoder").is_dir():
        return "qoder"

    # 检查 .github/copilot 目录（GitHub Copilot 专用）。
    if (project_root / ".github" / "copilot").is_dir():
        return "copilot"

    # 检查 .factory 目录（Factory Droid 专用）。
    if (project_root / ".factory").is_dir():
        return "droid"

    # 检查 .pi 目录（Pi Agent 专用）。
    if (project_root / ".pi").is_dir():
        return "pi"

    # 检查 .trae 目录（Trae IDE 专用）。
    if (project_root / ".trae").is_dir():
        return "trae"

    # 检查 .omp 目录（OMP 专用）。
    if (project_root / ".omp").is_dir():
        return "omp"

    # 检查 .grok 目录（Grok Build 专用）。
    if (project_root / ".grok").is_dir():
        return "grok"

    # 检查 .kimi-code 目录（Kimi Code 专用）。
    if (project_root / ".kimi-code").is_dir():
        return "kimi"

    # 回退：检出目录只有 Codex 共享 skills 层（.agents/skills/trellis-* 目录），没有
    # 明确的平台配置目录。常见于新克隆：.codex/ 被 gitignore 或缺失，但共享 skills
    # 已提交到 Git。必须防止 .claude/ 或其他平台目录同时存在的情况——.agents/skills/
    # 可以合法地与任何平台共存，作为 Amp/Cline/Warp 等共享消费层。
    agents_skills = project_root / ".agents" / "skills"
    if agents_skills.is_dir() and not _has_other_platform_dir(
        project_root, set()
    ):
        try:
            for entry in agents_skills.iterdir():
                if entry.is_dir() and entry.name.startswith("trellis-"):
                    return "codex"
        except OSError:
            pass

    return "claude"


def get_cli_adapter_auto(project_root: Path) -> CLIAdapter:
    """获取自动检测平台对应的 CLI 适配器。

    参数：
        project_root：项目根目录

    返回：
        检测平台对应的 CLIAdapter 实例
    """
    platform = detect_platform(project_root)
    return CLIAdapter(platform=platform)
