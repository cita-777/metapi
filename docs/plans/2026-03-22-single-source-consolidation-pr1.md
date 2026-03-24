# Single Source Consolidation PR1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Land PR1 for the highest-value duplication and double-source issues around responses normalization, shared proxy surface orchestration, provider runtime headers, token-route contract sharing, account mutation workflow, and standard API platform helpers.

**Architecture:** Keep PR1 focused on extracting shared single-source modules and rewiring existing callers to consume them. Do not expand this PR into schema metamodel rewrites, `chatFormatsCore` breakup, or mobile page scaffold work; those remain follow-up PR scope once the highest-risk protocol and workflow duplications are removed.

**Tech Stack:** TypeScript, Fastify, Vitest, shared server/web modules under `src/shared`, server proxy-core surfaces/providers/services, React admin pages.

---

## Task 1: Savepoint Commit

**Files:**
- Commit: `src/server/config.ts`
- Commit: `src/server/config.test.ts`
- Commit: `src/server/db/proxyFileSchemaCompatibility.ts`
- Commit: `src/server/db/proxyFileSchemaCompatibility.test.ts`

**Step 1: Verify the savepoint changes**

Run: `npm test -- src/server/config.test.ts src/server/db/proxyFileSchemaCompatibility.test.ts`
Expected: PASS

**Step 2: Commit the savepoint**

Run:

```bash
git add src/server/config.ts src/server/config.test.ts src/server/db/proxyFileSchemaCompatibility.ts src/server/db/proxyFileSchemaCompatibility.test.ts
git commit -m "fix: trust proxy headers and align proxy file mysql indexes"
```

**Step 3: Cherry-pick into PR1 branch**

Run:

```bash
git cherry-pick <savepoint-commit>
```

Expected: first commit preserved inside PR1 branch before the larger consolidation commit.

## Task 2: Responses Single Source

**Files:**
- Create: `src/server/transformers/openai/responses/normalization.ts`
- Modify: `src/server/transformers/openai/responses/conversion.ts`
- Modify: `src/server/transformers/openai/responses/compatibility.ts`
- Test: `src/server/transformers/openai/responses/conversion.test.ts`

**Step 1: Move shared normalization helpers into one source**

Keep `normalizeResponsesInputForCompatibility`, `normalizeResponsesMessageContent`, and related block normalization in `normalization.ts`.

**Step 2: Rewire both callers**

Make `conversion.ts` and `compatibility.ts` import the shared helpers instead of maintaining their own independent copies.

**Step 3: Verify parity**

Run: `npm test -- src/server/transformers/openai/responses/conversion.test.ts`
Expected: PASS, including assertions that compatibility exports point at the shared implementation.

## Task 3: Shared Surface Orchestration

**Files:**
- Create: `src/server/proxy-core/surfaces/sharedSurface.ts`
- Modify: `src/server/proxy-core/surfaces/chatSurface.ts`
- Modify: `src/server/proxy-core/surfaces/openAiResponsesSurface.ts`
- Modify: `src/server/proxy-core/surfaces/geminiSurface.ts`
- Test: `src/server/proxy-core/surfaces/sharedSurface.test.ts`

**Step 1: Extract common orchestration primitives**

Centralize channel selection, dispatch, proxy logging, retry/failure handling, and common failure response shaping in `sharedSurface.ts`.

**Step 2: Rewire surface callers**

Make chat and responses surfaces consume the shared orchestration helpers instead of each keeping a parallel flow.

**Step 3: Verify behavior**

Run: `npm test -- src/server/proxy-core/surfaces/sharedSurface.test.ts`
Expected: PASS

## Task 4: Provider Header Builders

**Files:**
- Create: `src/server/proxy-core/providers/headerUtils.ts`
- Modify: `src/server/proxy-core/providers/codexProviderProfile.ts`
- Modify: `src/server/proxy-core/providers/claudeProviderProfile.ts`
- Modify: `src/server/proxy-core/providers/geminiCliProviderProfile.ts`
- Modify: `src/server/routes/proxy/upstreamEndpoint.ts`
- Test: `src/server/proxy-core/providers/headerUtils.test.ts`

**Step 1: Extract header parsing and runtime header construction**

Keep Codex, Claude, and Gemini CLI runtime header shaping in `headerUtils.ts`.

**Step 2: Remove duplicate builders**

Make both provider profiles and `upstreamEndpoint.ts` call the shared header builders.

**Step 3: Verify behavior**

Run: `npm test -- src/server/proxy-core/providers/headerUtils.test.ts`
Expected: PASS

## Task 5: Cross-Layer Token Route Contract

**Files:**
- Create: `src/shared/tokenRouteContract.js`
- Create: `src/shared/tokenRouteContract.d.ts`
- Create: `src/shared/tokenRoutePatterns.js`
- Create: `src/shared/tokenRoutePatterns.d.ts`
- Modify: `src/server/services/tokenRouter.ts`
- Modify: `src/server/routes/api/tokens.ts`
- Modify: `src/web/pages/token-routes/utils.ts`
- Modify: `src/web/pages/token-routes/types.ts`
- Modify: `src/web/pages/helpers/routeListVisibility.ts`
- Modify: `src/web/pages/Settings.tsx`
- Test: `src/shared/tokenRouteContract.test.ts`
- Test: `src/shared/tokenRoutePatterns.test.ts`

**Step 1: Extract shared route mode and pattern matching**

Make route mode normalization and model pattern matching authoritative in `src/shared`.

**Step 2: Rewire server and web**

Make token router, route APIs, token-routes helpers, and settings consume the shared contract instead of maintaining separate copies.

**Step 3: Verify behavior**

Run: `npm test -- src/shared/tokenRouteContract.test.ts src/shared/tokenRoutePatterns.test.ts`
Expected: PASS

## Task 6: Account Mutation Workflow

**Files:**
- Create: `src/server/services/accountMutationWorkflow.ts`
- Modify: `src/server/routes/api/accounts.ts`
- Modify: `src/server/routes/api/accountTokens.ts`
- Test: `src/server/services/accountMutationWorkflow.test.ts`

**Step 1: Extract convergence workflow**

Move token sync, default token ensure, balance refresh, model refresh, and route rebuild sequencing into `accountMutationWorkflow.ts`.

**Step 2: Rewire controllers**

Make account and account-token APIs call the workflow service instead of each owning private orchestration logic.

**Step 3: Verify behavior**

Run: `npm test -- src/server/services/accountMutationWorkflow.test.ts`
Expected: PASS

## Task 7: Standard API Provider Base

**Files:**
- Create: `src/server/services/platforms/standardApiProvider.ts`
- Modify: `src/server/services/platforms/openai.ts`
- Modify: `src/server/services/platforms/claude.ts`
- Modify: `src/server/services/platforms/gemini.ts`
- Modify: `src/server/services/platforms/cliproxyapi.ts`
- Test: `src/server/services/platforms/standardApiProvider.test.ts`
- Test: `src/server/services/platforms/llmUpstream.test.ts`

**Step 1: Extract shared standard API adapter logic**

Centralize base URL normalization, `/v1/models` resolution, unsupported login/checkin/balance defaults, and common model fetch behavior.

**Step 2: Rewire adapters**

Make OpenAI, Claude, Gemini, and CLIProxyAPI adapters extend the shared base instead of repeating the same template logic.

**Step 3: Verify behavior**

Run: `npm test -- src/server/services/platforms/standardApiProvider.test.ts src/server/services/platforms/llmUpstream.test.ts`
Expected: PASS

## Task 8: Shared Input File Resolution And Web Helpers

**Files:**
- Modify: `src/server/services/proxyInputFileResolver.ts`
- Modify: `src/server/services/proxyInputFileResolver.test.ts`
- Modify: `src/server/proxy-core/surfaces/inputFilesSurface.ts`
- Create: `src/web/pages/helpers/accountConnection.ts`
- Create: `src/web/pages/helpers/accountConnection.test.ts`
- Modify: `src/web/pages/Accounts.tsx`
- Modify: `src/web/pages/Tokens.tsx`
- Modify: `src/web/api.ts`
- Modify: `src/web/api.test.ts`

**Step 1: Make route-level file inlining reuse the service implementation**

Replace the duplicate `inputFilesSurface.ts` implementation with a re-export of the shared resolver service.

**Step 2: Extract shared web account helpers**

Move `resolveAccountCredentialMode`, `parsePositiveInt`, and `isTruthyFlag` into a single helper consumed by both Accounts and Tokens.

**Step 3: De-duplicate proxy test aliases**

Make `testProxy` / `proxyTest` and stream variants reuse the same implementation function.

**Step 4: Verify behavior**

Run: `npm test -- src/server/services/proxyInputFileResolver.test.ts src/web/pages/helpers/accountConnection.test.ts src/web/api.test.ts`
Expected: PASS

## Task 9: PR1 Verification And Commit

**Files:**
- Verify: `scripts/dev/copy-runtime-db-generated.ts`
- Verify: `scripts/dev/copy-runtime-db-generated.test.ts`
- Verify: all files touched in Tasks 2-8

**Step 1: Run focused regression suite**

Run:

```bash
npm test -- scripts/dev/copy-runtime-db-generated.test.ts src/server/proxy-core/cliProfiles/codexProfile.test.ts src/server/proxy-core/providers/headerUtils.test.ts src/server/proxy-core/surfaces/sharedSurface.test.ts src/server/routes/api/oauth.test.ts src/server/services/accountMutationWorkflow.test.ts src/server/services/modelService.discovery.test.ts src/server/services/oauth/oauthAccount.test.ts src/server/services/platforms/standardApiProvider.test.ts src/server/services/platforms/llmUpstream.test.ts src/server/services/proxyInputFileResolver.test.ts src/server/transformers/openai/responses/conversion.test.ts src/shared/tokenRouteContract.test.ts src/shared/tokenRoutePatterns.test.ts src/web/api.test.ts src/web/pages/helpers/accountConnection.test.ts
```

Expected: PASS

**Step 2: Run server build**

Run: `npm run build:server`
Expected: PASS

**Step 3: Commit PR1 consolidation work**

Run:

```bash
git add docs/plans/2026-03-22-single-source-consolidation-pr1.md scripts/dev/copy-runtime-db-generated.test.ts scripts/dev/copy-runtime-db-generated.ts src/server/proxy-core/cliProfiles/codexProfile.ts src/server/proxy-core/cliProfiles/codexProfile.test.ts src/server/proxy-core/providers/headerUtils.ts src/server/proxy-core/providers/headerUtils.test.ts src/server/proxy-core/providers/claudeProviderProfile.ts src/server/proxy-core/providers/codexProviderProfile.ts src/server/proxy-core/providers/geminiCliProviderProfile.ts src/server/proxy-core/surfaces/chatSurface.ts src/server/proxy-core/surfaces/geminiSurface.ts src/server/proxy-core/surfaces/inputFilesSurface.ts src/server/proxy-core/surfaces/openAiResponsesSurface.ts src/server/proxy-core/surfaces/sharedSurface.ts src/server/proxy-core/surfaces/sharedSurface.test.ts src/server/routes/api/accountTokens.ts src/server/routes/api/accounts.ts src/server/routes/api/oauth.test.ts src/server/routes/api/tokens.ts src/server/routes/proxy/downstreamClientContext.ts src/server/routes/proxy/responsesWebsocket.ts src/server/routes/proxy/upstreamEndpoint.ts src/server/services/accountMutationWorkflow.ts src/server/services/accountMutationWorkflow.test.ts src/server/services/backupService.ts src/server/services/modelService.discovery.test.ts src/server/services/modelService.ts src/server/services/oauth/oauthAccount.ts src/server/services/oauth/oauthAccount.test.ts src/server/services/oauth/quota.ts src/server/services/oauth/service.ts src/server/services/platforms/claude.ts src/server/services/platforms/cliproxyapi.ts src/server/services/platforms/gemini.ts src/server/services/platforms/llmUpstream.test.ts src/server/services/platforms/openai.ts src/server/services/platforms/standardApiProvider.ts src/server/services/platforms/standardApiProvider.test.ts src/server/services/proxyInputFileResolver.ts src/server/services/proxyInputFileResolver.test.ts src/server/services/siteProxy.ts src/server/services/tokenRouter.ts src/server/transformers/anthropic/messages/inbound.ts src/server/transformers/openai/responses/compatibility.ts src/server/transformers/openai/responses/conversion.test.ts src/server/transformers/openai/responses/conversion.ts src/server/transformers/openai/responses/normalization.ts src/shared/tokenRouteContract.d.ts src/shared/tokenRouteContract.js src/shared/tokenRouteContract.test.ts src/shared/tokenRoutePatterns.d.ts src/shared/tokenRoutePatterns.js src/shared/tokenRoutePatterns.test.ts src/web/api.ts src/web/api.test.ts src/web/pages/Accounts.tsx src/web/pages/Settings.tsx src/web/pages/Tokens.tsx src/web/pages/helpers/accountConnection.ts src/web/pages/helpers/accountConnection.test.ts src/web/pages/helpers/routeListVisibility.ts src/web/pages/token-routes/types.ts src/web/pages/token-routes/utils.ts
git commit -m "refactor: consolidate single-source routing and protocol helpers"
```

### Deferred After PR1

**Keep out of this PR:**
- `shared/chatFormatsCore.ts` breakup
- Gemini `generate-content` module boundary cleanup
- schema contract/introspection meta-rule unification
- `legacySchemaCompat.ts` feature compatibility dedupe
- mobile page scaffold extraction
- large-file decomposition for `Settings.tsx`, `ModelTester.tsx`, `tokenRouter.ts`, `modelService.ts`
