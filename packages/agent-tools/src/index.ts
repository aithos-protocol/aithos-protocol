// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

export type {
  AgentToolSpec,
  DispatchOutcome,
  JsonSchema,
  LegacyAlias,
  ScopeRule,
} from "./types.js";

export {
  AGENT_TOOL_CATALOG,
  ETHOS_READ_SCOPES,
  ETHOS_WRITE_SCOPES,
  ETHOS_ZONES,
  GAMMA_READ_SCOPE,
  getToolSpec,
  type EthosZone,
} from "./catalog.js";

export { isWriteTool, scopeAllowsTool, toolsForScopes } from "./scopes.js";

export { LEGACY_TOOL_ALIASES, resolveLegacyToolCall } from "./aliases.js";
