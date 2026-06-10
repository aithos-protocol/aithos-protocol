# @aithos/agent-tools

The **canonical catalogue** of Aithos agent tools: names, normative
descriptions, input JSON Schemas, scope-exposure rules, and legacy aliases.

Every Aithos tool host consumes this package instead of maintaining its own
copy:

- `@aithos/mcp` — the standalone MCP server (stdio / Streamable HTTP)
- `aithos-sdk` — the in-app agent loop (browser, in-process MCP host)
- the platform compute-proxy tool registry (server-side converse loop)

A parity test in each host asserts that its registered tools are a subset of
— and structurally identical to — these specs. The catalogue is therefore the
single place where a tool can be added, renamed, or re-described.

## Contents

- `AGENT_TOOL_CATALOG` — every canonical `AgentToolSpec` (name, title,
  normative description, `input_schema`, scope rule, write flag).
- `toolsForScopes(scopes, opts?)` — the exposure rule: which tools a caller
  bearing a mandate's scopes may see (`undefined` = owner = everything).
  Exposure is the coarse gate for `tools/list`; hosts keep fine-grained
  per-zone enforcement at dispatch time (defense in depth).
- `LEGACY_TOOL_ALIASES` / `resolveLegacyToolCall(name, args)` — pre-0.9
  `aithos_*` names accepted at `tools/call` for one minor version (never
  listed). Removal scheduled for `@aithos/mcp` 1.0.
- `isWriteTool(name)`, `scopeAllowsTool(spec, scopes)`, shared types
  (`AgentToolSpec`, `DispatchOutcome`).

## Discipline

Tool names, argument schemas, **and descriptions** are part of the contract —
descriptions are shipped verbatim to calling models and shape their behavior.
Any change to them is a breaking change of this package: bump accordingly and
document it in the CHANGELOG (spec §10.10 transposed).

Zero runtime dependencies. Isomorphic by construction (no node builtins).

## License

Apache-2.0
