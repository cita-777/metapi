# Downstream Key UI And Site Links Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restyle the downstream key page to match the restrained management-console pages and standardize site buttons across pages using the accounts page interaction.

**Architecture:** Introduce one shared site link component based on the accounts page behavior, then update each affected page to consume it. Refactor downstream key layout styling toward existing `card`, `badge`, and `data-table` patterns without changing backend behavior.

**Tech Stack:** React, TypeScript, React Router, Vitest, React Test Renderer

---

### Task 1: Extract the shared site button

**Files:**
- Create: `src/web/components/SiteBadgeLink.tsx`
- Test: `src/web/components/site-badge-link.test.tsx`
- Modify: `src/web/pages/Accounts.tsx`
- Modify: `src/web/index.css`

**Step 1: Write the failing test**

Add a component test that renders a site badge link and asserts:
- it renders the site name,
- it has the shared interactive class,
- clicking navigates to `/sites?focusSiteId=<id>`.

**Step 2: Run test to verify it fails**

Run: `npm test -- src/web/components/site-badge-link.test.tsx`

Expected: FAIL because the component does not exist yet.

**Step 3: Write minimal implementation**

- Create a small component that wraps `Link` from `react-router-dom`.
- Accept `siteId`, `siteName`, and optional badge class props.
- Reproduce the accounts page badge-link styling and fallback behavior.
- Move the accounts page site badge rendering to this component.
- Add any missing shared CSS class if accounts currently relies on page-local styling.

**Step 4: Run test to verify it passes**

Run: `npm test -- src/web/components/site-badge-link.test.tsx src/web/pages/accounts.segmented-connections.test.tsx`

Expected: PASS

**Step 5: Commit**

```bash
git add src/web/components/SiteBadgeLink.tsx src/web/components/site-badge-link.test.tsx src/web/pages/Accounts.tsx src/web/index.css
git commit -m "refactor: extract shared site badge link"
```

### Task 2: Apply the shared site button across affected pages

**Files:**
- Modify: `src/web/pages/Models.tsx`
- Modify: `src/web/pages/ProxyLogs.tsx`
- Modify: `src/web/pages/TokenRoutes.tsx`
- Modify: `src/web/pages/DownstreamKeys.tsx`
- Test: `src/web/pages/Models.marketplace-text.test.tsx`
- Test: `src/web/pages/tokenRoutes.group-collapse.test.tsx`
- Test: `src/web/pages/DownstreamKeys.test.tsx`

**Step 1: Write failing assertions**

Add or update tests to assert the affected pages render the shared site button class and, where practical, point to the focused site management route.

**Step 2: Run test to verify it fails**

Run: `npm test -- src/web/pages/Models.marketplace-text.test.tsx src/web/pages/tokenRoutes.group-collapse.test.tsx src/web/pages/DownstreamKeys.test.tsx`

Expected: FAIL because the pages still use inconsistent site rendering.

**Step 3: Write minimal implementation**

- Replace page-local site label rendering with `SiteBadgeLink`.
- Only convert labels that represent navigable management-site references.
- Preserve non-site filters, external URLs, and unrelated badges.

**Step 4: Run test to verify it passes**

Run: `npm test -- src/web/pages/Models.marketplace-text.test.tsx src/web/pages/tokenRoutes.group-collapse.test.tsx src/web/pages/DownstreamKeys.test.tsx src/web/pages/ProxyLogs.server-driven.test.tsx`

Expected: PASS

**Step 5: Commit**

```bash
git add src/web/pages/Models.tsx src/web/pages/ProxyLogs.tsx src/web/pages/TokenRoutes.tsx src/web/pages/DownstreamKeys.tsx src/web/pages/Models.marketplace-text.test.tsx src/web/pages/tokenRoutes.group-collapse.test.tsx src/web/pages/DownstreamKeys.test.tsx
git commit -m "feat: unify site badge navigation across pages"
```

### Task 3: Restyle downstream keys page

**Files:**
- Modify: `src/web/pages/DownstreamKeys.tsx`
- Test: `src/web/pages/DownstreamKeys.test.tsx`
- Modify: `src/web/index.css`

**Step 1: Write failing assertions**

Add focused assertions for the downstream keys page structure where needed, such as shared management-page card classes, reduced bespoke styling hooks, or the new site badge placement.

**Step 2: Run test to verify it fails**

Run: `npm test -- src/web/pages/DownstreamKeys.test.tsx`

Expected: FAIL after adding assertions that reflect the updated restrained layout.

**Step 3: Write minimal implementation**

- Reduce the page’s dashboard-like presentation.
- Align summary, filters, and batch action sections with the same management-console card language used in sites/accounts.
- Reuse shared badge/link patterns instead of one-off visual treatments where practical.
- Keep operations, data fetching, and drawer behavior unchanged.

**Step 4: Run test to verify it passes**

Run: `npm test -- src/web/pages/DownstreamKeys.test.tsx`

Expected: PASS

**Step 5: Commit**

```bash
git add src/web/pages/DownstreamKeys.tsx src/web/pages/DownstreamKeys.test.tsx src/web/index.css
git commit -m "style: align downstream key page with management UI"
```

### Task 4: Final verification

**Files:**
- Modify: none

**Step 1: Run targeted verification**

Run:
- `npm test -- src/web/components/site-badge-link.test.tsx`
- `npm test -- src/web/pages/DownstreamKeys.test.tsx`
- `npm test -- src/web/pages/Models.marketplace-text.test.tsx`
- `npm test -- src/web/pages/tokenRoutes.group-collapse.test.tsx`
- `npm test -- src/web/pages/ProxyLogs.server-driven.test.tsx`
- `npm test -- src/web/pages/accounts.segmented-connections.test.tsx`

Expected: PASS

**Step 2: Run broader sanity verification if time permits**

Run: `npm test -- src/web/App.sidebar.test.ts src/web/App.sidebar-mobile.test.tsx`

Expected: PASS

**Step 3: Commit final polish**

```bash
git add -A
git commit -m "test: verify downstream key UI and site link consistency"
```
