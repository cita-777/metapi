# Single Source Consolidation Full-Scope Follow-Through

## Context

This document supersedes the scoped execution boundary of
[`2026-03-22-single-source-consolidation-pr1.md`](./2026-03-22-single-source-consolidation-pr1.md)
for PR #244. The PR1 document remains a historical snapshot of the initial
landing slice. This document captures the expanded branch-wide finish that
continued until the single-source, workflow, schema, and web admin duplication
themes were fully closed for this PR.

## Goals

- Eliminate active double-source implementations for proxy protocols and runtime headers.
- Centralize account, OAuth, route refresh, and platform discovery workflows.
- Collapse schema metadata normalization and feature compatibility drift points.
- Remove repeated web admin page scaffolding and large inline modal/panel implementations.
- Finish the branch in a merge-ready state with focused regressions and formal builds.

## Scope Delivered In This Branch

### Server and Shared Runtime

- OpenAI Responses normalization and conversion now flow through one shared implementation boundary.
- Shared proxy surface orchestration owns retry recovery, success bookkeeping, and surface-level failure handling.
- Provider header/body runtime shaping is centralized behind provider profiles and shared header utilities.
- OAuth identity now treats structured columns as the canonical source, with compatibility/backfill isolated to a removable layer.
- Route refresh and rebuild sequencing flows through `routeRefreshWorkflow`, not controller-local orchestration.
- Platform discovery moved out of `modelService` into dedicated registry-backed discovery modules.
- Schema metadata normalization is shared by contract and introspection code paths.
- Legacy schema compatibility derives feature-owned allowances from feature specs instead of maintaining a second whitelist.

### Web Admin

- Token-route, brand, and downstream client display rules now rely on shared helpers and registries instead of page-local duplicates.
- `ResponsiveBatchActionBar` centralizes repeated batch action shells across admin list pages.
- `ResponsiveFilterPanel` centralizes the responsive "desktop controls vs mobile sheet" scaffold across admin pages.
- `Settings`, `Accounts`, `ModelTester`, and `DownstreamKeys` no longer keep their heaviest modal or drawer UIs inline in the page file.
- Brand matching metadata is owned by `brandRegistry`, with `BrandIcon` reduced to rendering concerns.

## Commit Groups

### Protocol and Workflow Consolidation

- review-driven cleanup commits
- OAuth identity and route refresh workflow commits
- downstream client/runtime header/profile consolidation commits
- platform discovery extraction commits

### Schema and Shared Contract Consolidation

- shared schema metadata normalization
- legacy schema compatibility derivation from feature specs
- shared token-route contract and pattern ownership

### Web Admin Decomposition

- responsive batch action scaffold
- responsive filter scaffold
- settings modal extraction
- accounts model management modal extraction
- model tester panel extraction
- downstream key drawer extraction

## Final Verification Matrix

Run these groups before calling the branch complete.

### Protocol and Surface

- `npm test -- src/server/proxy-core/surfaces/sharedSurface.test.ts src/server/routes/proxy src/server/transformers/openai/responses src/server/transformers/anthropic/messages src/server/services/proxyInputFileResolver.test.ts`

### OAuth, Workflow, and Platforms

- `npm test -- src/server/routes/api src/server/services/accountMutationWorkflow.test.ts src/server/services/modelService.discovery.test.ts src/server/services/oauth/oauthAccount.test.ts src/server/services/platforms/standardApiProvider.test.ts src/server/services/platforms/llmUpstream.test.ts`

### Schema

- `npm run test:schema:unit`
- `npm run schema:contract`
- `npm run smoke:db:sqlite`

### Web and Build

- `npm test -- src/web/pages/responsiveFilterPanel.architecture.test.ts src/web/pages/checkin.mobile.test.tsx src/web/pages/logs.mobile.test.tsx src/web/pages/programLogs.mobile-layout.test.tsx src/web/pages/accounts.batch-actions.test.tsx src/web/pages/sites.mobile-actions.test.tsx src/web/pages/tokens.batch-actions.test.tsx src/web/pages/DownstreamKeys.test.tsx src/web/pages/DownstreamKeys.mobile.test.tsx src/web/pages/downstreamKeys.mobile-layout.test.tsx src/web/pages/tokenRoutes.mobile-layout.test.tsx src/web/pages/tokenRoutes.mobile.test.tsx src/web/pages/models.mobile-layout.test.tsx`
- `npm run build`

## Done Definition

The branch is complete when:

- no page under `src/web/pages` imports `MobileFilterSheet` directly;
- no active protocol path keeps parallel single-source conversions alive;
- controller layers do not own route rebuild choreography;
- schema metadata and compatibility rules do not keep a second handwritten truth source;
- focused regressions and formal builds pass from the commands above.
