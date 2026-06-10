// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Legacy tool-name aliases (pre-0.9 `aithos_*` names → canonical D1 names).
 *
 * Contract: `tools/list` exposes ONLY canonical names; hosts accept the
 * legacy names at `tools/call` (resolving through this map, renaming
 * arguments shallowly) for ONE minor version, logging a deprecation warning.
 * Scheduled for removal in @aithos/mcp 1.0.
 */
import type { LegacyAlias } from "./types.js";

export const LEGACY_TOOL_ALIASES: Readonly<Record<string, LegacyAlias>> = {
  aithos_list_identities: { canonical: "identity_list" },
  aithos_show_identity: { canonical: "identity_describe" },
  aithos_ethos_list_sections: { canonical: "ethos_list_sections" },
  aithos_ethos_show_section: {
    canonical: "ethos_read_section",
    renameArgs: { sectionId: "section_id" },
  },
  aithos_ethos_read_sections: {
    canonical: "ethos_read_sections",
    renameArgs: { sectionIds: "section_ids" },
  },
  aithos_ethos_verify: { canonical: "ethos_verify" },
  aithos_ethos_add_section: {
    canonical: "ethos_add_section",
    renameArgs: { agentKey: "agent_key" },
  },
  aithos_ethos_modify_section: {
    canonical: "ethos_update_section",
    renameArgs: {
      sectionId: "section_id",
      clearTags: "clear_tags",
      agentKey: "agent_key",
    },
  },
  aithos_ethos_delete_section: {
    canonical: "ethos_delete_section",
    renameArgs: { sectionId: "section_id", agentKey: "agent_key" },
  },
  aithos_mandate_verify: { canonical: "mandate_verify" },
};

/**
 * Resolve a possibly-legacy tool call to its canonical form. Returns the
 * input unchanged when `name` is not a known alias.
 */
export function resolveLegacyToolCall(
  name: string,
  args: Record<string, unknown> | undefined,
): {
  name: string;
  args: Record<string, unknown> | undefined;
  wasAlias: boolean;
} {
  const alias = LEGACY_TOOL_ALIASES[name];
  if (!alias) return { name, args, wasAlias: false };
  let mapped = args;
  if (args && alias.renameArgs) {
    mapped = {};
    for (const [k, v] of Object.entries(args)) {
      mapped[alias.renameArgs[k] ?? k] = v;
    }
  }
  return { name: alias.canonical, args: mapped, wasAlias: true };
}
