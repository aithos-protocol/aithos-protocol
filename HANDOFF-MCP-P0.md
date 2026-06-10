# HANDOFF — MCP unification, Phase P0 (DONE)

> Branch: `feat/mcp-unification` · Repo: aithos-protocol · Date: 2026-06-10
> Plan: `PLAN-MCP-UNIFICATION-2026-06.md` (in `code/`, outside this repo)

## What landed

**P0.1 — `packages/agent-tools` (`@aithos/agent-tools` 0.1.0, new).**
Canonical catalogue (D1): 11 tool specs (names, snake_case args, normative
descriptions, JSON Schemas), `toolsForScopes()` exposure rules,
`LEGACY_TOOL_ALIASES` + `resolveLegacyToolCall()`, shared types
(`AgentToolSpec`, `DispatchOutcome`). Zero deps, `sideEffects: false`,
isomorphic. 9 tests.

**P0.2 — `packages/mcp` 0.9.0: isomorphic core.**
`createServer()` (server.ts) has no node builtins and no filesystem default.
Host capabilities are injected: `storage` (required), `io` (path-form
mandate/agent-key reads), `home`, `manifestPath`, `renderZone`
(protocol-core's `renderZoneMarkdown` — node-bound, so injected). bin.ts is
the node host (unchanged CLI surface). protocol-core consumed via node-free
granular entries (`/did`, `/mandate`) + type-only root imports; dep bumped
`^0.8.0 → ^0.10.0` (workspace link). Gate: `npm run check:browser` (esbuild
`--platform=browser` on the core graph; fails on any node builtin).

**P0.3 — mandate-scoped exposure + alias bridge.**
`createServer({ mandate: { scopes } })` filters `tools/list` via
`toolsForScopes`; per-call zone checks unchanged in handlers (defense in
depth). Legacy `aithos_*` names resolve at `tools/call` (never listed) by
wrapping the SDK's tools/call handler; deprecation warning on stderr;
`legacyAliases: false` disables; removal in 1.0.

**P0.4 — tests.** All green on Linux (node 22):

| Suite | What it locks |
|---|---|
| agent-tools `catalog.test.mjs` (9) | D1 names frozen, schema well-formedness, scope rules, alias map integrity |
| mcp `h1-inmemory.test.mjs` (7) | T10 parity server↔catalogue (descriptions + schemas), T4 exposure filtering, T5a/T5b zero-write guarantees, alias bridge on/off |
| mcp `e2e-write.test.mjs` (1) | Full v0.3 lifecycle over real stdio with canonical names + ONE legacy-alias call (camelCase args) through the bridge |

## Decisions taken while implementing

- **MCP SDK 1.29 behavior:** `client.callTool` surfaces protocol errors as
  `{isError: true}` results (does not reject) — tests assert accordingly.
- **Alias bridge** uses the SDK's private `_requestHandlers` map (no public
  hidden-tool facility). Pinned by the h1 alias regression test: an SDK bump
  that moves internals fails loudly, and the bridge degrades to
  canonical-only with a stderr notice (never breaks canonical calls).
- **`data_query`** is in the catalogue but not registered by this server
  (no data backend here yet) — T10 checks subset+parity, not equality.
- **`ZoneDoc` re-render** is host-injected (`renderZone`); browser hosts
  without it degrade to raw bytes / explanatory fallbacks.

## Verify on your Mac

```bash
git fetch && git checkout feat/mcp-unification && npm install
npm test --workspace=@aithos/agent-tools   # 9 pass
npm test --workspace=@aithos/mcp           # 8 pass (builds first)
npm run check:browser --workspace=@aithos/mcp
```

Claude Desktop/Code configs need no change (they reference the binary, not
tool names). Scripted clients calling `aithos_*` keep working until 1.0.

## Next (P1 — SDK becomes an MCP host, repo aithos-sdk)

1. `SdkStorage implements AithosStorage` wrapping `EthosClient` (reads
   decrypt local, writes staged).
2. `sdk.agent.run()` — in-process server via `InMemoryTransport`
   (`createServer` from `@aithos/mcp` core + `SdkStorage`), loop =
   `runAgenticLoopLocal`, dispatch = `client.callTool`, `invokeTurn`
   billing unchanged.
3. Browser smoke already de-risked (esbuild gate + earlier spike: SDK
   server+InMemoryTransport bundle clean, 139 KB gz).
4. Publishing order when merging: `@aithos/agent-tools` 0.1.0 → npm, then
   `@aithos/mcp` 0.9.0 (depends on it). protocol-core 0.10.1 is already
   the workspace version.
