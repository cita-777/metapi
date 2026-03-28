# Metapi Harness Engineering

This document captures the repo-level engineering taste that should remain true
even when future work is performed by autonomous agents. The goal is not to
replace feature tests. The goal is to keep the repository readable,
review-friendly, and hard to drift.

## Why This Exists

`metapi` already has strong local discipline in several areas:

- architecture tests that pin important boundaries
- schema parity and runtime bootstrap verification across databases
- shared protocol helpers that deliberately replace parallel implementations

What was still missing was one place that states the mechanical rules behind
those choices and a lightweight loop that continuously checks for drift. This
document is that shared contract.

## Golden Principles

### 1. One Invariant, One Source Of Truth

If a helper, contract, or workflow already owns an invariant, new work should
reuse that home instead of creating a second implementation.

Examples:

- protocol shaping and normalization belong in `src/server/transformers/**`
- endpoint fallback belongs in `src/server/routes/proxy/endpointFlow.ts`
- proxy success/failure bookkeeping belongs in
  `src/server/proxy-core/surfaces/sharedSurface.ts`
- schema heuristics belong in `src/server/db/schemaMetadata.ts`

### 2. Routes Are Adapters, Not Owners

`src/server/routes/**` should remain thin. Route files may register endpoints,
read Fastify request state, and delegate to shared orchestration. They should
not become the place where retry loops, protocol conversion, stream lifecycle,
or billing logic lives.

If a helper is imported outside a single route file, that helper should move to
`proxy-core`, `services`, `transformers`, or another neutral home.

### 3. Transformers Must Stay Protocol-Pure

Transformers are the protocol boundary. They may depend on canonical/shared
contracts, but they should not reach back into route files, Fastify handlers,
OAuth services, token routing, or runtime dispatch details.

In practice this means:

- `canonical` is the request truth source
- `shared/normalized` is the response truth source
- compatibility layers may orchestrate retries or fallback bodies, but they do
  not redefine protocol semantics

### 4. Proxy-Core Follows The Golden Path

Proxy orchestration should prefer shared, tested paths instead of bespoke
surface-local logic.

Current preferred path:

- endpoint ranking and request shaping via `upstreamEndpoint.ts`
- endpoint-attempt loops via `executeEndpointFlow()`
- whole-body response decoding via `readRuntimeResponseText()`
- OAuth refresh, sticky/lease behavior, billing, and proxy logging via
  `sharedSurface.ts`
- Codex header/session semantics via provider profiles and header utils
- Codex websocket transport via the dedicated websocket runtime, not generic
  fetch executors

### 5. Platform Capability Must Be Explicit

Platform behavior is easy to let drift because it spans adapters, discovery,
endpoint preference, and routing. Any platform-specific behavior that matters
at runtime should be stated once and reused, not re-inferred in multiple
subsystems.

Thin adapters should stay honest. Feature-complete adapters should be tested as
feature-complete. Do not silently “upgrade” support through generic defaults.

### 6. Database Changes Must Stay Contract-Driven

Schema work already has one of the strongest harnesses in the repo. Keep it
that way.

- update Drizzle schema and SQLite migration history together
- regenerate checked-in contract/artifacts together
- keep cross-dialect bootstrap/upgrade generation contract-driven
- keep legacy startup compatibility narrow and spec-owned

### 7. Web Pages Are Orchestration Surfaces

Top-level pages should not be reused as shared component libraries.

- no page-to-page imports for reusable UI
- mobile behavior should reuse shared primitives first
- extract repeated modals, drawers, and panels into domain subfolders early

## First-Wave Drift Checks

The first repo-level drift loop is intentionally small and high-signal. It
checks for:

- transformer imports from `routes/proxy`
- new proxy-core surface body reads that bypass `readRuntimeResponseText()`
- new imports from `routes/proxy` inside `proxy-core` beyond the current debt
  baseline
- new top-level page-to-page imports in the admin UI beyond the current debt
  baseline

These checks live in `scripts/dev/repo-drift-check.ts` and are wired into CI.

## Tracked Debt Vs New Violations

The repository already contains some known architectural debt, especially where
`proxy-core` still imports helpers from `routes/proxy` and where one admin page
reuses another page's export.

The harness uses a ratchet:

- tracked debt is reported so it stays visible
- new violations fail CI

This keeps the repo moving forward without forcing a risky “rewrite
everything first” migration.

## Garbage Collection Loop

The harness loop is intentionally conservative:

1. rules are encoded in repo docs and executable checks
2. CI blocks new drift
3. a scheduled workflow generates a drift report artifact
4. targeted cleanup PRs can remove tracked debt in small slices

The goal is steady principal payments on technical debt, not occasional heroic
cleanup sprints.
