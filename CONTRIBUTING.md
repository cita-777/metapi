# Contributing / 贡献指南

Thank you for your interest in contributing to Metapi! / 感谢您对 Metapi 项目的贡献！

Metapi is a meta-aggregation layer for AI API platforms (New API, One API, OneHub, etc.), providing unified proxy, intelligent routing, and centralized management.

Metapi 是 AI API 聚合平台（New API、One API、OneHub 等）的元聚合层，提供统一代理、智能路由和集中管理。

## Before You Start / 开始之前

- Check existing [Issues](https://github.com/cita-777/metapi/issues) and [Pull Requests](https://github.com/cita-777/metapi/pulls) to avoid duplicates. / 检查现有的 [Issues](https://github.com/cita-777/metapi/issues) 和 [Pull Requests](https://github.com/cita-777/metapi/pulls) 以避免重复。
- For major changes, open an issue first to discuss your proposal. / 对于重大更改，请先开启 issue 讨论您的提案。
- Read our [Code of Conduct](CODE_OF_CONDUCT.md). / 阅读我们的[行为准则](CODE_OF_CONDUCT.md)。

## Local Development Setup / 本地开发环境设置

### Prerequisites / 前置要求

- Node.js 20+ / Node.js 20 或更高版本
- npm or compatible package manager / npm 或兼容的包管理器

### Setup Steps / 设置步骤

1. **Fork and clone the repository** / **Fork 并克隆仓库**

```bash
git clone https://github.com/YOUR_USERNAME/metapi.git
cd metapi
```

2. **Install dependencies** / **安装依赖**

```bash
npm install
```

3. **Create environment file** / **创建环境文件**

```bash
# Windows PowerShell
Copy-Item .env.example .env

# Linux/macOS/Git Bash
cp .env.example .env
```

Edit `.env` and set your tokens / 编辑 `.env` 并设置您的令牌:

```env
AUTH_TOKEN=your-dev-admin-token
PROXY_TOKEN=your-dev-proxy-token
```

4. **Initialize database** / **初始化数据库**

```bash
npm run db:migrate
```

5. **Start development server** / **启动开发服务器**

```bash
npm run dev
```

The app will be available at `http://localhost:4000` (backend) and `http://localhost:5173` (frontend).

应用将在 `http://localhost:4000`（后端）和 `http://localhost:5173`（前端）可用。

## Development Commands / 开发命令

### Web Application / Web 应用

```bash
npm run dev              # Start backend + frontend with hot reload / 启动后端 + 前端热更新
npm run dev:server       # Start backend only / 仅启动后端
npm run build            # Build all (web + server + desktop) / 构建全部
npm run build:web        # Build frontend only / 仅构建前端
npm run build:server     # Build backend only / 仅构建后端
```

### Desktop Application / 桌面应用

```bash
npm run dev:desktop              # Start desktop app in dev mode / 开发模式启动桌面应用
npm run build:desktop            # Build desktop app / 构建桌面应用
npm run dist:desktop             # Package desktop app / 打包桌面应用
npm run dist:desktop:mac:intel   # Package for macOS Intel / 打包 macOS Intel 版本
```

### Documentation / 文档

```bash
npm run docs:dev         # Start VitePress dev server / 启动 VitePress 开发服务器
npm run docs:build       # Build documentation / 构建文档
npm run docs:preview     # Preview built docs / 预览构建的文档
```

### Testing / 测试

```bash
npm test                 # Run all tests / 运行所有测试
npm run test:watch       # Run tests in watch mode / 监听模式运行测试
npm run smoke:db         # Database smoke test (SQLite) / 数据库冒烟测试（SQLite）
npm run smoke:db:mysql   # MySQL smoke test / MySQL 冒烟测试
npm run smoke:db:postgres # PostgreSQL smoke test / PostgreSQL 冒烟测试
```

### Database / 数据库

```bash
npm run db:generate      # Generate Drizzle migration files / 生成 Drizzle 迁移文件
npm run db:migrate       # Run database migrations / 运行数据库迁移
npm run schema:generate  # Generate schema artifacts / 生成 schema 构件
```

## Project Structure / 项目结构

```
metapi/
├── src/
│   ├── server/          # Backend (Fastify) / 后端（Fastify）
│   │   ├── routes/      # API routes / API 路由
│   │   ├── services/    # Business logic / 业务逻辑
│   │   ├── db/          # Database & ORM / 数据库与 ORM
│   │   └── middleware/  # Middleware / 中间件
│   ├── web/             # Frontend (React + Vite) / 前端（React + Vite）
│   └── desktop/         # Electron desktop app / Electron 桌面应用
├── docs/                # VitePress documentation / VitePress 文档
├── drizzle/             # Database migrations / 数据库迁移
└── scripts/             # Build & dev scripts / 构建与开发脚本
```

## Pull Request Guidelines / Pull Request 指南

### Before Submitting / 提交之前

1. **Keep PRs focused and small** / **保持 PR 专注且小巧**
   - One feature or fix per PR / 每个 PR 一个功能或修复
   - Split large changes into multiple PRs / 将大型更改拆分为多个 PR

2. **Write tests** / **编写测试**
   - Add tests for new features / 为新功能添加测试
   - Update tests for behavior changes / 为行为变更更新测试
   - Ensure all tests pass: `npm test` / 确保所有测试通过：`npm test`

3. **Update documentation** / **更新文档**
   - Update README if adding user-facing features / 如果添加面向用户的功能，请更新 README
   - Update docs/ for configuration or API changes / 配置或 API 更改请更新 docs/
   - Add JSDoc comments for new functions / 为新函数添加 JSDoc 注释

4. **Run checks** / **运行检查**
   - Documentation changes: `npm run docs:build` / 文档更改：`npm run docs:build`
   - Code changes: `npm test && npm run build` / 代码更改：`npm test && npm run build`
   - Database changes: `npm run smoke:db` / 数据库更改：`npm run smoke:db`

5. **Follow code style** / **遵循代码风格**
   - Use TypeScript for type safety / 使用 TypeScript 确保类型安全
   - Follow existing code patterns / 遵循现有代码模式
   - Keep functions small and focused / 保持函数小而专注

### Commit Messages / 提交信息

Use conventional commit format / 使用约定式提交格式:

```
<type>: <description>

[optional body]
```

Types / 类型:
- `feat`: New feature / 新功能
- `fix`: Bug fix / 错误修复
- `docs`: Documentation / 文档
- `refactor`: Code refactoring / 代码重构
- `test`: Tests / 测试
- `chore`: Build/tooling / 构建/工具

Examples / 示例:
```
feat: add AnyRouter platform adapter
fix: handle empty model list in dashboard
docs: update Docker deployment guide
refactor: extract route selection logic
test: add tests for checkin reward parser
chore: upgrade Vite to 6.0
```

### What Not to Commit / 不要提交的内容

- Runtime data: `data/`, `tmp/` / 运行时数据：`data/`、`tmp/`
- Environment files: `.env` (only `.env.example` is tracked) / 环境文件：`.env`（仅跟踪 `.env.example`）
- Build artifacts: `dist/`, `node_modules/` / 构建产物：`dist/`、`node_modules/`
- IDE-specific files (unless beneficial to all contributors) / IDE 特定文件（除非对所有贡献者有益）

## Platform Adapters / 平台适配器

If you're adding support for a new AI API platform / 如果您要添加对新 AI API 平台的支持:

1. Create adapter in `src/server/services/platforms/` / 在 `src/server/services/platforms/` 中创建适配器
2. Implement required interfaces: login, balance, models, proxy / 实现必需接口：登录、余额、模型、代理
3. Add platform tests / 添加平台测试
4. Update documentation with platform details / 更新文档说明平台详情

## Windows Development Notes / Windows 开发注意事项

- Use `restart.bat` to restart dev server (clears port locks) / 使用 `restart.bat` 重启开发服务器（清除端口锁定）
- Use PowerShell `Copy-Item` instead of `cp` / 使用 PowerShell 的 `Copy-Item` 而不是 `cp`
- If Node.js upgrade breaks scripts, run `npm install` again / 如果 Node.js 升级导致脚本损坏，请重新运行 `npm install`

## Getting Help / 获取帮助

- 📖 [Documentation](https://metapi.cita777.me) / [文档](https://metapi.cita777.me)
- 💬 [GitHub Discussions](https://github.com/cita-777/metapi/discussions) / [GitHub 讨论区](https://github.com/cita-777/metapi/discussions)
- 🐛 [Issue Tracker](https://github.com/cita-777/metapi/issues) / [Issue 跟踪](https://github.com/cita-777/metapi/issues)

## License / 许可证

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

通过贡献，您同意您的贡献将根据 [MIT 许可证](LICENSE) 授权。
