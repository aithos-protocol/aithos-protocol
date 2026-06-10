# Changelog — @aithos/agent-tools

## 0.1.0 — 2026-06-10

Initial release. Canonical catalogue ratified per decision D1
(PLAN-MCP-UNIFICATION-2026-06):

- 11 canonical tool specs — `identity_list`, `identity_describe`,
  `ethos_list_sections`, `ethos_read_section`, `ethos_read_sections`,
  `ethos_verify`, `ethos_add_section`, `ethos_update_section`,
  `ethos_delete_section`, `mandate_verify`, `data_query` — snake_case names
  and argument keys, normative descriptions, JSON Schema inputs.
- Scope-exposure rules + `toolsForScopes()` (owner = full catalogue;
  mandate = intersection with `requires.anyOf`; `readOnly` / explicit
  `tools` filters).
- Legacy `aithos_*` alias map + `resolveLegacyToolCall()` (accepted at
  `tools/call` only — never listed; removal scheduled for @aithos/mcp 1.0).
- Shared types: `AgentToolSpec`, `DispatchOutcome`, `ScopeRule`,
  `LegacyAlias`.
- Zero runtime dependencies; `sideEffects: false`; isomorphic.
