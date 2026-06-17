// SPDX-License-Identifier: Apache-2.0
// T10 (self-consistency half): the canonical catalogue is well-formed and
// matches the ratified D1 decision. The cross-host parity halves live with
// each host (packages/mcp h1 test for the MCP server; aithos-sdk and the
// platform registry add theirs in P1/P6).
import test from "node:test";
import assert from "node:assert/strict";

import {
  AGENT_TOOL_CATALOG,
  ETHOS_READ_SCOPES,
  ETHOS_WRITE_SCOPES,
  LEGACY_TOOL_ALIASES,
  getToolSpec,
  isWriteTool,
  resolveLegacyToolCall,
  toolsForScopes,
} from "../dist/index.js";

// The ratified D1 table (2026-06-10; +introduce/briefing P6 2026-06-11).
// Renaming = breaking change.
const RATIFIED_NAMES = [
  "identity_list",
  "identity_describe",
  "ethos_list_sections",
  "ethos_read_section",
  "ethos_read_sections",
  "ethos_search",
  "ethos_context_pack",
  "ethos_diff_since",
  "ethos_verify",
  "ethos_add_section",
  "ethos_update_section",
  "ethos_append_section",
  "ethos_delete_section",
  "ethos_commit",
  "ethos_discard",
  "ethos_preflight_write",
  "mandate_verify",
  "mandate_describe",
  "ethos_introduce",
  "agent_briefing",
  "data_query",
  "linkedone_schedule_post",
];

test("catalogue exposes exactly the ratified D1 names, in order", () => {
  assert.deepEqual(
    AGENT_TOOL_CATALOG.map((t) => t.name),
    RATIFIED_NAMES,
  );
});

test("every spec is well-formed", () => {
  for (const t of AGENT_TOOL_CATALOG) {
    assert.match(t.name, /^[a-z]+(_[a-z]+)+$/, `${t.name}: snake_case`);
    assert.ok(t.title.length > 0, `${t.name}: title`);
    assert.ok(t.description.length >= 40, `${t.name}: normative description`);
    assert.equal(t.input_schema.type, "object", `${t.name}: object schema`);
    assert.ok("properties" in t.input_schema, `${t.name}: properties`);
    // snake_case argument keys only
    for (const key of Object.keys(t.input_schema.properties ?? {})) {
      assert.match(key, /^[a-z]+(_[a-z]+)*$/, `${t.name}.${key}: snake_case`);
    }
    // required ⊆ properties
    for (const r of t.input_schema.required ?? []) {
      assert.ok(
        r in (t.input_schema.properties ?? {}),
        `${t.name}: required '${r}' missing from properties`,
      );
    }
  }
});

test("write tools carry a write-scope rule; read tools never do", () => {
  // A write scope is either an ethos write scope or a data collection write
  // scope (`data.<collection>.write`). The latter admits third-party app
  // tools such as linkedone_schedule_post (provisional broker, cf. linkedone
  // PLAN-AITHOS-BROKER-MVP).
  const isWriteScope = (s) =>
    ETHOS_WRITE_SCOPES.includes(s) || /^data\.[a-z0-9-]+\.write$/.test(s);
  for (const t of AGENT_TOOL_CATALOG) {
    if (t.write) {
      assert.ok(t.requires, `${t.name}: write tool must be scope-gated`);
      assert.ok(
        t.requires.anyOf.every((s) => isWriteScope(s)),
        `${t.name}: write tool gated by write scopes`,
      );
    } else if (t.requires) {
      assert.ok(
        t.requires.anyOf.every((s) => !isWriteScope(s)),
        `${t.name}: read tool must not require write scopes`,
      );
    }
  }
  assert.equal(isWriteTool("ethos_add_section"), true);
  assert.equal(isWriteTool("ethos_read_section"), false);
});

test("toolsForScopes — owner sees everything", () => {
  assert.equal(toolsForScopes(undefined).length, AGENT_TOOL_CATALOG.length);
});

test("toolsForScopes — read-only mandate hides every write tool (T4 rule)", () => {
  const out = toolsForScopes(["ethos.read.public"]);
  const names = out.map((t) => t.name);
  assert.ok(names.includes("ethos_list_sections"));
  assert.ok(names.includes("ethos_read_section"));
  assert.ok(!names.includes("ethos_add_section"));
  assert.ok(!names.includes("ethos_update_section"));
  assert.ok(!names.includes("ethos_delete_section"));
  assert.ok(!names.includes("ethos_append_section"));
  assert.ok(!names.includes("ethos_commit"));
  assert.ok(!names.includes("ethos_discard"));
  // gamma-gated tool hidden without gamma.read
  assert.ok(!names.includes("data_query"));
  // ungated introspection stays
  assert.ok(names.includes("identity_list"));
  assert.ok(names.includes("mandate_verify"));
});

test("toolsForScopes — write mandate exposes write tools; readOnly drops them", () => {
  const scopes = ["ethos.read.public", "ethos.write.public"];
  const names = toolsForScopes(scopes).map((t) => t.name);
  assert.ok(names.includes("ethos_add_section"));
  const ro = toolsForScopes(scopes, { readOnly: true }).map((t) => t.name);
  assert.ok(!ro.includes("ethos_add_section"));
  assert.ok(ro.includes("ethos_read_section"));
});

test("toolsForScopes — explicit tool restriction intersects", () => {
  const out = toolsForScopes(undefined, {
    tools: ["ethos_read_section", "nope_unknown"],
  });
  assert.deepEqual(out.map((t) => t.name), ["ethos_read_section"]);
});

test("every legacy alias resolves to a canonical spec", () => {
  for (const [legacy, alias] of Object.entries(LEGACY_TOOL_ALIASES)) {
    assert.ok(
      getToolSpec(alias.canonical),
      `${legacy} → ${alias.canonical} must exist in the catalogue`,
    );
    // Renamed args must land on canonical schema properties.
    const spec = getToolSpec(alias.canonical);
    for (const target of Object.values(alias.renameArgs ?? {})) {
      assert.ok(
        target in (spec.input_schema.properties ?? {}),
        `${legacy}: rename target '${target}' not in ${alias.canonical} schema`,
      );
    }
  }
});

test("resolveLegacyToolCall maps names and renames args shallowly", () => {
  const r = resolveLegacyToolCall("aithos_ethos_modify_section", {
    zone: "public",
    sectionId: "sec_ab",
    clearTags: true,
    body: "x",
  });
  assert.equal(r.wasAlias, true);
  assert.equal(r.name, "ethos_update_section");
  assert.deepEqual(r.args, {
    zone: "public",
    section_id: "sec_ab",
    clear_tags: true,
    body: "x",
  });
  const noop = resolveLegacyToolCall("ethos_read_section", { section_id: "s" });
  assert.equal(noop.wasAlias, false);
  assert.equal(noop.name, "ethos_read_section");
});

test("P2 transactional trio: write-flagged, write-scope-gated, well-formed", () => {
  for (const name of ["ethos_append_section", "ethos_commit", "ethos_discard"]) {
    const spec = getToolSpec(name);
    assert.ok(spec, `${name} missing`);
    assert.equal(spec.write, true, `${name} must be a write tool`);
    assert.ok(isWriteTool(name));
    assert.deepEqual(spec.requires?.anyOf, [
      "ethos.write.public",
      "ethos.write.circle",
      "ethos.write.self",
    ]);
  }
  // append: journal-pattern schema
  const append = getToolSpec("ethos_append_section");
  assert.deepEqual([...append.input_schema.required].sort(), [
    "content",
    "section_id",
    "zone",
  ]);
  // commit/discard: no required args; commit takes an optional message
  assert.equal(getToolSpec("ethos_commit").input_schema.required, undefined);
  assert.ok(getToolSpec("ethos_commit").input_schema.properties.message);
  assert.equal(getToolSpec("ethos_discard").input_schema.required, undefined);
  // a write-scoped mandate sees the trio; readOnly drops it
  const w = toolsForScopes(["ethos.write.circle"]).map((t) => t.name);
  for (const n of ["ethos_append_section", "ethos_commit", "ethos_discard"]) {
    assert.ok(w.includes(n), `${n} exposed to a write mandate`);
  }
  const ro = toolsForScopes(undefined, { readOnly: true }).map((t) => t.name);
  for (const n of ["ethos_append_section", "ethos_commit", "ethos_discard"]) {
    assert.ok(!ro.includes(n), `${n} hidden in readOnly`);
  }
});

test("P3 contextualization tools: read-flagged, read-scope-gated, well-formed", () => {
  for (const name of ["ethos_search", "ethos_context_pack", "ethos_diff_since"]) {
    const spec = getToolSpec(name);
    assert.ok(spec, `${name} missing`);
    assert.equal(spec.write, false, `${name} is a read tool`);
    assert.ok(!isWriteTool(name));
    assert.deepEqual(spec.requires?.anyOf, [
      "ethos.read.public",
      "ethos.read.circle",
      "ethos.read.self",
    ]);
  }
  assert.deepEqual(getToolSpec("ethos_search").input_schema.required, ["query"]);
  assert.deepEqual(getToolSpec("ethos_context_pack").input_schema.required, ["task"]);
  assert.deepEqual(getToolSpec("ethos_diff_since").input_schema.required, ["height"]);
  // read-scoped mandates see them; readOnly keeps them (non-mutating).
  const r = toolsForScopes(["ethos.read.public"]).map((t) => t.name);
  for (const n of ["ethos_search", "ethos_context_pack", "ethos_diff_since"]) {
    assert.ok(r.includes(n), `${n} exposed to a read mandate`);
  }
  const ro = toolsForScopes(undefined, { readOnly: true }).map((t) => t.name);
  for (const n of ["ethos_search", "ethos_context_pack", "ethos_diff_since"]) {
    assert.ok(ro.includes(n), `${n} kept in readOnly`);
  }
});

test("P4 living-mandate tools: ungated introspection, read-flagged", () => {
  for (const name of ["mandate_describe", "ethos_preflight_write"]) {
    const spec = getToolSpec(name);
    assert.ok(spec, `${name} missing`);
    assert.equal(spec.write, false);
    assert.equal(spec.requires, undefined, `${name} is exposed to every session`);
    assert.ok(!isWriteTool(name));
  }
  assert.deepEqual(getToolSpec("ethos_preflight_write").input_schema.required, ["zone"]);
  assert.equal(getToolSpec("mandate_describe").input_schema.required, undefined);
  // exposed even to a minimal read mandate AND in readOnly mode.
  const r = toolsForScopes(["ethos.read.public"]).map((t) => t.name);
  const ro = toolsForScopes(undefined, { readOnly: true }).map((t) => t.name);
  for (const n of ["mandate_describe", "ethos_preflight_write"]) {
    assert.ok(r.includes(n) && ro.includes(n), `${n} always exposed`);
  }
});
