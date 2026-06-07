// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Unit tests for the ethos verb-scope grammar + authorization predicate
// (draft bundle-v0.3-section-verb-scopes.md, §4.8′). Pure functions — no
// keystore, no crypto.

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  parseEthosScope,
  matchSection,
  coversOperation,
  coversRead,
  hasReadBearingEthosScopeForZone,
  isEthosMutatingScope,
  hasEthosMutatingScope,
} from "../src/ethos-authz.js";

describe("parseEthosScope", () => {
  it("parses bare whole-zone scopes", () => {
    assert.deepEqual(parseEthosScope("ethos.read.self"), {
      verb: "read",
      zone: "self",
      selector: { kind: "all" },
    });
    assert.deepEqual(parseEthosScope("ethos.write.public"), {
      verb: "write",
      zone: "public",
      selector: { kind: "all" },
    });
  });

  it("parses the three selector kinds", () => {
    assert.deepEqual(parseEthosScope("ethos.edit.self#id=X"), {
      verb: "edit",
      zone: "self",
      selector: { kind: "id", id: "X" },
    });
    assert.deepEqual(parseEthosScope("ethos.append.self#prefix=gmail:"), {
      verb: "append",
      zone: "self",
      selector: { kind: "prefix", prefix: "gmail:" },
    });
    assert.deepEqual(parseEthosScope("ethos.read.circle#tag=bio"), {
      verb: "read",
      zone: "circle",
      selector: { kind: "tag", tag: "bio" },
    });
  });

  it("parses the legacy read-all", () => {
    assert.deepEqual(parseEthosScope("ethos.read.all"), {
      verb: "read",
      zone: "all",
      selector: { kind: "all" },
    });
  });

  it("fails closed (null) on malformed / non-ethos scopes", () => {
    for (const bad of [
      "data.notes.read", // not ethos
      "ethos.read", // missing zone
      "ethos.read.self.extra", // too many parts
      "ethos.frobnicate.self", // unknown verb
      "ethos.read.galaxy", // unknown zone
      "ethos.write.all", // all only valid for read
      "ethos.read.all#id=X", // selector on read-all is meaningless
      "ethos.edit.self#", // empty selector body
      "ethos.edit.self#id=", // empty selector value
      "ethos.edit.self#weird=X", // unknown selector key
      "ethos.edit.self#X", // selector without '='
    ]) {
      assert.equal(parseEthosScope(bad), null, `expected null for ${bad}`);
    }
  });
});

describe("matchSection", () => {
  it("matches by id / prefix / tag / all", () => {
    const s = { id: "gmail:123", tags: ["gmail", "inbox"] };
    assert.equal(matchSection(s, { kind: "all" }), true);
    assert.equal(matchSection(s, { kind: "id", id: "gmail:123" }), true);
    assert.equal(matchSection(s, { kind: "id", id: "other" }), false);
    assert.equal(matchSection(s, { kind: "prefix", prefix: "gmail:" }), true);
    assert.equal(matchSection(s, { kind: "prefix", prefix: "notes:" }), false);
    assert.equal(matchSection(s, { kind: "tag", tag: "gmail" }), true);
    assert.equal(matchSection(s, { kind: "tag", tag: "private" }), false);
  });

  it("a tag selector never matches when tags are unknown (encrypted self)", () => {
    assert.equal(matchSection({ id: "x" }, { kind: "tag", tag: "gmail" }), false);
  });
});

describe("coversOperation (§4.8.3′)", () => {
  const X = { id: "X" };
  const Y = { id: "Y" };

  it("V1: edit#id=X edits X but cannot delete or create", () => {
    const s = ["ethos.edit.self#id=X"];
    assert.equal(coversOperation(s, "self", "edit", X), true);
    assert.equal(coversOperation(s, "self", "delete", X), false);
    assert.equal(coversOperation(s, "self", "create", X), false);
    assert.equal(coversOperation(s, "self", "edit", Y), false); // out of perimeter
  });

  it("V3: write#id=X edits and deletes X; cannot create an out-of-perimeter section", () => {
    const s = ["ethos.write.self#id=X"];
    assert.equal(coversOperation(s, "self", "edit", X), true);
    assert.equal(coversOperation(s, "self", "delete", X), true);
    assert.equal(coversOperation(s, "self", "create", { id: "Z" }), false);
  });

  it("V4: append#prefix=gmail: creates and edits gmail:* but cannot delete, nor touch other prefixes", () => {
    const s = ["ethos.append.self#prefix=gmail:"];
    const g = { id: "gmail:1" };
    assert.equal(coversOperation(s, "self", "create", g), true);
    assert.equal(coversOperation(s, "self", "edit", g), true);
    assert.equal(coversOperation(s, "self", "delete", g), false);
    assert.equal(coversOperation(s, "self", "create", { id: "notes:1" }), false);
  });

  it("whole-zone write = full CRUD", () => {
    const s = ["ethos.write.self"];
    assert.equal(coversOperation(s, "self", "create", X), true);
    assert.equal(coversOperation(s, "self", "edit", X), true);
    assert.equal(coversOperation(s, "self", "delete", X), true);
  });

  it("read scopes authorize no write, and read.all never writes", () => {
    assert.equal(coversOperation(["ethos.read.self"], "self", "edit", X), false);
    assert.equal(coversOperation(["ethos.read.all"], "self", "edit", X), false);
  });

  it("V8: a tag write-perimeter does not match when tags are unknown (self at the provider)", () => {
    const s = ["ethos.edit.self#tag=gmail"];
    assert.equal(coversOperation(s, "self", "edit", { id: "a" }), false); // tags unknown
    assert.equal(coversOperation(s, "self", "edit", { id: "a", tags: ["gmail"] }), true); // tags clear
  });

  it("zone isolation: a self scope does not authorize circle", () => {
    assert.equal(coversOperation(["ethos.write.self"], "circle", "edit", X), false);
  });
});

describe("coversRead (§3.5.7′ recipient derivation)", () => {
  const X = { id: "X" };
  const Y = { id: "Y" };

  it("whole-zone read makes the holder a recipient of every section", () => {
    assert.equal(coversRead(["ethos.read.self"], "self", X), true);
    assert.equal(coversRead(["ethos.read.self"], "self", Y), true);
  });

  it("V9: edit#id=X makes the holder a recipient of X but not Y", () => {
    const s = ["ethos.edit.self#id=X"];
    assert.equal(coversRead(s, "self", X), true);
    assert.equal(coversRead(s, "self", Y), false);
  });

  it("delete alone does NOT bear read", () => {
    assert.equal(coversRead(["ethos.delete.self#id=X"], "self", X), false);
  });

  it("read.all is a recipient of every zone/section", () => {
    assert.equal(coversRead(["ethos.read.all"], "self", X), true);
    assert.equal(coversRead(["ethos.read.all"], "public", Y), true);
  });

  it("split perimeters (V5): read whole zone + edit one section ⇒ recipient of all", () => {
    const s = ["ethos.read.self", "ethos.edit.self#id=X"];
    assert.equal(coversRead(s, "self", X), true);
    assert.equal(coversRead(s, "self", Y), true); // the whole-zone read covers Y
  });
});

describe("scope-set helpers", () => {
  it("hasReadBearingEthosScopeForZone covers verbs and the legacy read-all", () => {
    assert.equal(hasReadBearingEthosScopeForZone(["ethos.read.self"], "self"), true);
    assert.equal(hasReadBearingEthosScopeForZone(["ethos.edit.self#id=X"], "self"), true);
    assert.equal(hasReadBearingEthosScopeForZone(["ethos.read.all"], "self"), true);
    assert.equal(hasReadBearingEthosScopeForZone(["ethos.delete.self#id=X"], "self"), false); // delete ≠ read
    assert.equal(hasReadBearingEthosScopeForZone(["ethos.read.circle"], "self"), false);
  });

  it("isEthosMutatingScope / hasEthosMutatingScope", () => {
    assert.equal(isEthosMutatingScope("ethos.edit.self#id=X"), true);
    assert.equal(isEthosMutatingScope("ethos.append.self#prefix=p"), true);
    assert.equal(isEthosMutatingScope("ethos.delete.self"), true);
    assert.equal(isEthosMutatingScope("ethos.write.public"), true);
    assert.equal(isEthosMutatingScope("ethos.read.self"), false);
    assert.equal(isEthosMutatingScope("ethos.read.all"), false);
    assert.equal(isEthosMutatingScope("data.notes.write"), false);
    assert.equal(hasEthosMutatingScope(["ethos.read.self", "ethos.edit.self#id=X"]), true);
    assert.equal(hasEthosMutatingScope(["ethos.read.self"]), false);
  });
});
