# Metapi 项目结构

本文档只说明当前仓库里长期维护的主目录，帮助贡献者快速判断代码、脚本和文档应当放在哪里。

## 顶层目录

```text
metapi/
├── build/                # 打包静态资源（如 Electron 图标）
├── data/                 # 默认运行时数据目录（SQLite、日志、导出文件）
├── dist/                 # 构建产物（web / server / desktop）
├── docker/               # Dockerfile、Compose 与部署模板
├── docs/                 # VitePress 文档、截图、Logo 与社区规范
├── drizzle/              # Drizzle SQL 迁移与 meta 快照
├── scripts/              # 开发脚本、桌面打包钩子、一次性 codemod
├── src/
│   ├── desktop/          # Electron 主进程与桌面运行时
│   ├── server/           # Fastify 服务、数据库、代理路由与业务服务
│   └── web/              # React 管理后台
├── tmp/                  # 临时调试文件（已 gitignore）
├── restart.bat           # Windows 快捷重启入口，转发到 scripts/dev/restart.bat
├── package.json          # 脚本入口与依赖清单
├── electron-builder.yml  # 桌面打包配置
├── drizzle.config.ts     # Drizzle 配置
├── vite.config.ts        # Web 构建配置
└── tsconfig*.json        # TypeScript 配置
```

## 源码目录

### `src/server`

```text
src/server/
├── index.ts              # Fastify 启动、运行时初始化、启动摘要输出
├── config.ts             # 环境变量解析与 Fastify 配置
├── desktop.ts            # 桌面模式下的静态资源与公开路由适配
├── nativeModuleGuard.ts  # better-sqlite3 ABI 兼容检查
├── db/                   # schema、连接、迁移、兼容列修复
├── middleware/           # 认证等通用中间件
├── routes/
│   ├── api/              # 管理端 API（sites / accounts / tokens / settings ...）
│   └── proxy/            # OpenAI / Claude / Gemini 兼容代理入口
├── services/             # 业务服务、平台适配器、日志 / 文件 / 路由 / 迁移能力
└── transformers/         # 协议转换与共享归一化层
```

- 新的管理接口优先放在 `routes/api/`。
- 新的 `/v1/*`、多模态、文件、视频等兼容代理逻辑放在 `routes/proxy/`。
- 协议格式转换或跨协议共享归一化，优先落在 `transformers/` 而不是路由文件里。

### `src/web`

```text
src/web/
├── main.tsx              # Vite 入口
├── App.tsx               # 路由与页面装配
├── api.ts                # 管理端 API 客户端
├── authSession.ts        # 登录态管理
├── appLocalState.ts      # 本地安装 / UI 状态
├── docsLink.ts           # 文档链接映射
├── i18n*.ts*             # 国际化
├── components/           # 通用组件与图表组件
├── pages/                # 路由页与页面级 helpers
└── public/               # Web 静态资源
```

- 页面级测试和 helper 与页面代码同目录维护。
- 通用展示组件放 `components/`；只被单页消费的纯逻辑优先放 `pages/helpers/`。

### `src/desktop`

```text
src/desktop/
├── main.ts               # Electron 主进程入口
├── runtime.ts            # 桌面运行时端口 / 路径解析
└── runtime.test.ts       # 桌面运行时测试
```

## 脚本与文档目录

```text
scripts/
├── dev/                  # 本地开发脚本（run-server.ts / restart.bat / db-smoke.ts）
├── desktop/              # Electron 打包钩子（afterPack / afterSign）
└── codemods/             # 一次性仓库级重构脚本
```

```text
docs/
├── .vitepress/           # 文档站导航与主题配置
├── community/            # 社区贡献规范
├── public/               # 文档站公开静态资源
├── logos/                # 可编辑 Logo 源文件与草稿
├── screenshots/          # 文档截图
└── *.md                  # 面向用户和维护者的文档页面
```

## 放置规则

- 测试文件尽量与被测源码同目录，命名使用 `*.test.ts` 或 `*.test.tsx`。
- 运行时数据放 `data/`，临时排障文件放 `tmp/`，不要散落在仓库根目录。
- 桌面打包脚本统一放 `scripts/desktop/`，不要把一次性签名或打包命令写进根目录批处理。
- 文档站真正对外可访问的静态资源放 `docs/public/`；仍需继续编辑的素材保留在 `docs/logos/` 或 `docs/screenshots/`。
