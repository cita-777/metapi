# Security Policy / 安全政策

## Overview / 概述

The security of Metapi is important to us. This document outlines our security policy and how to report vulnerabilities.

Metapi 的安全对我们很重要。本文档概述了我们的安全政策以及如何报告漏洞。

Since Metapi is a self-hosted meta-aggregation layer that manages sensitive credentials (API keys, account passwords) and proxies AI API requests, security is a critical concern.

由于 Metapi 是一个自托管的元聚合层，管理敏感凭证（API 密钥、账号密码）并代理 AI API 请求，因此安全性至关重要。

## Supported Versions / 支持的版本

We provide security updates for the following versions / 我们为以下版本提供安全更新:

| Version / 版本 | Supported / 支持状态 |
| -------------- | -------------------- |
| Latest release / 最新版本 | ✅ Fully supported / 完全支持 |
| `main` branch / `main` 分支 | ✅ Supported / 支持 |
| Older releases / 旧版本 | ⚠️ Best effort / 尽力而为 |
| Forks / 分支 | ❌ Not supported / 不支持 |

**Recommendation** / **建议**: Always use the latest stable release from [GitHub Releases](https://github.com/cita-777/metapi/releases) or the `main` branch for the most up-to-date security patches.

始终使用 [GitHub Releases](https://github.com/cita-777/metapi/releases) 的最新稳定版本或 `main` 分支以获得最新的安全补丁。

## Security Considerations / 安全注意事项

When deploying Metapi, please consider / 部署 Metapi 时，请考虑:

### Credential Storage / 凭证存储

- All sensitive credentials (API keys, passwords) are encrypted at rest in the database / 所有敏感凭证（API 密钥、密码）在数据库中静态加密存储
- Use strong `AUTH_TOKEN` and `PROXY_TOKEN` values / 使用强 `AUTH_TOKEN` 和 `PROXY_TOKEN` 值
- Never commit `.env` files or expose tokens in logs / 切勿提交 `.env` 文件或在日志中暴露令牌

### Network Security / 网络安全

- Deploy behind HTTPS/TLS in production / 在生产环境中部署在 HTTPS/TLS 后面
- Use `ADMIN_IP_ALLOWLIST` to restrict admin access / 使用 `ADMIN_IP_ALLOWLIST` 限制管理员访问
- Consider firewall rules to limit access to port 4000 / 考虑使用防火墙规则限制对端口 4000 的访问

### Database Security / 数据库安全

- Secure your database with strong credentials / 使用强凭证保护您的数据库
- Regularly backup the `data/` directory / 定期备份 `data/` 目录
- For production, consider using MySQL/PostgreSQL instead of SQLite / 对于生产环境，考虑使用 MySQL/PostgreSQL 而不是 SQLite

### Docker Security / Docker 安全

- Keep Docker images up to date / 保持 Docker 镜像最新
- Use volume mounts carefully to avoid exposing sensitive data / 谨慎使用卷挂载以避免暴露敏感数据
- Run containers with minimal privileges / 以最小权限运行容器

## Reporting a Vulnerability / 报告漏洞

**⚠️ Please do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

**⚠️ 请勿通过公开的 GitHub issue、讨论或 pull request 报告安全漏洞。**

### Reporting Channels / 报告渠道

Use one of these private channels / 使用以下私密渠道之一:

1. **GitHub Security Advisory** (Preferred) / **GitHub 安全公告**（首选）
   - Go to: https://github.com/cita-777/metapi/security/advisories/new
   - This allows for coordinated disclosure and CVE assignment / 这允许协调披露和 CVE 分配

2. **Email** / **邮件**
   - Send to: `cita-777@users.noreply.github.com`
   - Subject: `[Metapi Security] <brief description>` / 主题：`[Metapi Security] <简要描述>`

### What to Include / 应包含的内容

To help us understand and address the issue quickly, please include / 为了帮助我们快速理解和解决问题，请包含:

- **Description** / **描述**: Clear description of the vulnerability / 漏洞的清晰描述
- **Impact** / **影响**: What an attacker could achieve / 攻击者可能实现的目标
- **Affected versions** / **受影响的版本**: Version, commit hash, or deployment mode / 版本、提交哈希或部署模式
- **Affected components** / **受影响的组件**: Specific endpoints, modules, or configuration / 特定端点、模块或配置
- **Reproduction steps** / **复现步骤**: Step-by-step instructions to reproduce / 逐步复现说明
- **Proof of concept** / **概念验证**: Code, screenshots, or logs (with secrets redacted) / 代码、截图或日志（删除敏感信息）
- **Attack preconditions** / **攻击前提条件**: Required access level, network position, etc. / 所需访问级别、网络位置等
- **Suggested fix** / **建议修复**: If you have ideas for mitigation or patches / 如果您有缓解措施或补丁的想法

### Example Report / 报告示例

```
Subject: [Metapi Security] SQL Injection in account search

Description:
The account search endpoint is vulnerable to SQL injection through the
'name' parameter, allowing unauthorized database access.

Impact:
An authenticated attacker could extract all account credentials from
the database.

Affected Version:
v1.2.2 and earlier

Reproduction:
1. Login to Metapi admin panel
2. Navigate to /api/accounts/search?name=' OR '1'='1
3. Observe all accounts returned

Proof of Concept:
[Screenshot attached with sensitive data redacted]

Suggested Fix:
Use parameterized queries instead of string concatenation in
src/server/routes/api/accounts.ts:45
```

## Response Process / 响应流程

Our security response process / 我们的安全响应流程:

1. **Acknowledgment** / **确认**: We aim to acknowledge your report within **3 business days** / 我们力求在 **3 个工作日**内确认您的报告

2. **Initial Triage** / **初步分类**: We will provide initial assessment or follow-up questions within **7 business days** / 我们将在 **7 个工作日**内提供初步评估或后续问题

3. **Investigation** / **调查**: We may request additional details, logs, or reproduction steps / 我们可能会要求额外的细节、日志或复现步骤

4. **Fix Development** / **修复开发**: We will develop and test a fix / 我们将开发并测试修复方案

5. **Coordinated Disclosure** / **协调披露**: We will coordinate disclosure timing with you / 我们将与您协调披露时间
   - Please keep the vulnerability confidential until we release a fix / 请在我们发布修复之前对漏洞保密
   - We will credit you in the security advisory (unless you prefer to remain anonymous) / 我们将在安全公告中致谢您（除非您希望保持匿名）

6. **Release** / **发布**: We will release a patched version and publish a security advisory / 我们将发布修补版本并发布安全公告

### Severity Assessment / 严重性评估

We use the following severity levels / 我们使用以下严重性级别:

- **Critical** / **严重**: Remote code execution, credential theft, data breach / 远程代码执行、凭证盗窃、数据泄露
- **High** / **高**: Authentication bypass, privilege escalation / 身份验证绕过、权限提升
- **Medium** / **中**: Information disclosure, denial of service / 信息泄露、拒绝服务
- **Low** / **低**: Minor information leaks, configuration issues / 轻微信息泄露、配置问题

## Public Disclosure / 公开披露

If a vulnerability is accidentally posted publicly / 如果漏洞被意外公开发布:

1. We will immediately assess the risk / 我们将立即评估风险
2. We may redact sensitive details from the public post / 我们可能会从公开帖子中删除敏感细节
3. We will redirect the reporter to this private process / 我们将把报告者重定向到此私密流程
4. We will expedite the fix and release process / 我们将加快修复和发布流程

## Security Updates / 安全更新

Security updates will be announced through / 安全更新将通过以下方式公布:

- [GitHub Security Advisories](https://github.com/cita-777/metapi/security/advisories)
- [GitHub Releases](https://github.com/cita-777/metapi/releases) with `[SECURITY]` tag / 带有 `[SECURITY]` 标签
- Project README and documentation / 项目 README 和文档

Subscribe to repository notifications to stay informed / 订阅仓库通知以保持了解。

## Bug Bounty / 漏洞赏金

We currently do not offer a paid bug bounty program. However, we deeply appreciate security researchers who responsibly disclose vulnerabilities and will publicly acknowledge your contribution (with your permission).

我们目前不提供付费漏洞赏金计划。但是，我们非常感谢负责任地披露漏洞的安全研究人员，并将公开致谢您的贡献（经您许可）。

## Questions / 问题

If you have questions about this security policy, please contact `cita-777@users.noreply.github.com`.

如果您对本安全政策有疑问，请联系 `cita-777@users.noreply.github.com`。

---

**Thank you for helping keep Metapi and its users safe!**

**感谢您帮助保护 Metapi 及其用户的安全！**
