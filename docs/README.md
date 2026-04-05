# 文档维护与贡献

> `/README` 路由为兼容旧链接与维护工作流而保留。面向所有用户的公开入口始终是 [文档首页](/)。

## 这页适合谁

- 文档维护者：调整导航、重构内容结构、检查首页是否仍然聚焦对外说明。
- FAQ / 教程贡献者：补充排障经验、接入说明、案例沉淀。
- 功能发布或运维负责人：在能力变更后同步校正文档入口、截图和索引。

## 文档站运行

本地预览：

```bash
npm run docs:dev
```

构建静态站点：

```bash
npm run docs:build
```

## 内容地图

| 内容领域 | 首选页面 | 什么时候改这里 |
|------|--------|------------|
| 对外第一印象、产品定位、核心入口 | [文档首页](/) | 需要调整公开落地页信息架构、首页 CTA 或首屏导航时 |
| 新用户部署与首条请求 | [快速上手](./getting-started.md) | 新安装流程、默认端口、首次调用步骤变化时 |
| 上游平台选择与接法 | [上游接入](./upstream-integration.md) | 平台支持范围、官方预设、API 请求地址池、自动识别规则变化时 |
| Provider OAuth 授权 | [OAuth 管理](./oauth.md) | 支持的 OAuth provider、授权流程、回调方式或自动重绑能力变化时 |
| 生产部署与回滚 | [部署指南](./deployment.md) | Docker Compose、反向代理、升级回滚策略变更时 |
| K3s / Helm 高级升级面板 | [K3s 更新中心（高级）](./k3s-update-center.md) | 需要说明谁适合使用更新中心、helper 怎么配、K3s/Helm 发布链路怎么接入时 |
| 环境变量、参数和配置项 | [配置说明](./configuration.md) | 设置页 / 通知设置 / 下游密钥这些 UI 入口变化，或仅剩 env-only 的部署级参数变化时 |
| 客户端与工具接入 | [客户端接入](./client-integration.md) | Open WebUI、Cherry Studio、Cursor 等接入方式变化时 |
| 管理后台脚本化调用 | [管理 API](./management-api.md) | 需要说明如何用脚本批量导入站点/账号，或对接外部自动化时 |
| 运维排障与日常维护 | [运维手册](./operations.md) / [常见问题](./faq.md) | 新排障案例、备份恢复、健康检查、典型报错变化时 |
| FAQ / 教程协作沉淀 | [FAQ/教程贡献规范](./community/faq-tutorial-guidelines.md) | 需要新增教程、FAQ 模板、内容提交流程时 |
| 仓库目录与组织约定 | [目录规范](./project-structure.md) | 目录结构、归档策略或命名约定变化时 |
| 工程守则与漂移治理 | [Harness Engineering](./engineering/harness-engineering.md) | 需要更新仓库级黄金原则、自动巡检范围或垃圾回收流程时 |

## 维护约定

- [文档首页](/) 是唯一公共落地页。不要在 `/README` 或其他主题页重新堆一份 `文档中心总览`。
- 优先补强现有页面，再决定是否新增页面。只有在读者对象、内容边界和长期维护者都明确时再扩展路由。
- 导航、侧边栏和页面标题应反映公开入口和维护入口的分工，避免两个首页争夺注意力。
- 内链优先使用站内 clean URL 形式，保证 VitePress 构建结果和部署路径一致。
- 涉及界面、架构或流程变化时，同步检查首页截图、架构图和相关说明是否仍然匹配当前产品。

## 更新前自检

1. 先确认目标读者是谁，以及内容该落在哪个现有页面。
2. 如果入口结构变了，同步更新 `docs/.vitepress/config.ts` 的 `nav` 和 `sidebar`。
3. 检查新增或修改的内链是否还能在站内自然发现，不要把关键入口只藏在单个页面里。
4. 运行 `npm run docs:build`，确认没有引入构建错误，并额外抽查关键入口与内链。

## 相关入口

- [FAQ/教程贡献规范](./community/faq-tutorial-guidelines.md)
- [返回文档首页](/)
- [项目贡献流程](https://github.com/cita-777/metapi/blob/main/CONTRIBUTING.md)
- [安全策略](https://github.com/cita-777/metapi/blob/main/SECURITY.md)
- [行为准则](https://github.com/cita-777/metapi/blob/main/CODE_OF_CONDUCT.md)
