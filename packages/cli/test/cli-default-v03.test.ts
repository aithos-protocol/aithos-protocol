// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * End-to-end for the v0.3 default flip (lot 4b-3), driven through the built CLI:
 *
 *   - a fresh `init` produces a v0.3 (per-section) keystore, and the full
 *     section lifecycle (add / show / list / verify / pack) works on it;
 *   - `AITHOS_FORMAT=v0.2` opts a fresh install back into the legacy monolithic
 *     format;
 *   - a still-v0.2 keystore auto-migrates to v0.3 on the first owner write, and
 *     the prior v0.2 edition is archived under `history/`.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { freshHome, cleanupHome, runCli, runCliJson } from "./helpers.ts";

/** Path to the installed keystore manifest for a handle under an AITHOS_HOME. */
function manifestPath(home: string, handle: string): string {
  return join(home, "identities", handle, "ethos", "manifest.json");
}
function readAithos(home: string, handle: string): string {
  return (JSON.parse(readFileSync(manifestPath(home, handle), "utf8")) as { aithos: string }).aithos;
}

describe("aithos default write format (v0.3 flip)", () => {
  test("fresh init is v0.3 and supports the full section lifecycle", () => {
    const home = freshHome();
    try {
      runCli(["init", "--handle", "alice", "--display-name", "Alice"], { home });
      assert.equal(readAithos(home, "alice"), "0.3.0", "fresh init must be v0.3");

      // add-section keeps the keystore v0.3 and writes a per-section blob.
      const add = runCliJson<{ section_id: string; zone: string }>(
        ["ethos", "add-section", "--zone", "self", "--title", "Routine", "--body", "Up at six.", "--handle", "alice"],
        { home },
      );
      assert.ok(add.section_id.startsWith("sec_"));
      assert.equal(readAithos(home, "alice"), "0.3.0");
      const selfDir = join(home, "identities", "alice", "ethos", "self");
      assert.ok(existsSync(selfDir) && readdirSync(selfDir).some((f) => f.endsWith(".enc")), "self/<id>.enc written");

      // A second section in another zone.
      runCli(["ethos", "add-section", "--zone", "circle", "--title", "Rate", "--body", "1200/day.", "--handle", "alice"], { home });

      // show reads the decrypted index (dispatches to the v0.3 read path).
      const show = runCli(["ethos", "show", "--handle", "alice"], { home }).stdout;
      assert.match(show, /Routine/);

      // list shows both sections.
      const list = runCliJson<{ rows: Array<{ zone: string; title: string }> }>(
        ["ethos", "list", "--handle", "alice"],
        { home },
      );
      assert.equal(list.rows.length, 2);
      assert.deepEqual(list.rows.map((r) => r.title).sort(), ["Rate", "Routine"]);

      // verify --handle accepts the v0.3 keystore.
      const verify = runCliJson<{ ok: boolean; format?: string; errors: string[] }>(
        ["ethos", "verify", "--handle", "alice"],
        { home },
      );
      assert.ok(verify.ok, `v0.3 verify failed: ${verify.errors.join(", ")}`);
      assert.equal(verify.format, "v0.3");

      // pack emits a .ethos that the v0.3 verifier + reader accept.
      const bundle = join(home, "alice.ethos");
      runCli(["ethos", "pack", "--out", bundle, "--handle", "alice"], { home });
      assert.ok(existsSync(bundle));
      const vpath = runCliJson<{ ok: boolean; bundle_id: string }>(["ethos", "verify", "--path", bundle], { home });
      assert.ok(vpath.ok, "packed v0.3 bundle must verify via --path");

      const read = runCliJson<{ zones: Record<string, { sections: Array<{ title?: string; title_hidden: boolean }> }> }>(
        ["ethos", "read", "--path", bundle, "--index", "--handle", "alice"],
        { home },
      );
      assert.equal(read.zones.self.sections[0].title, "Routine");
    } finally {
      cleanupHome(home);
    }
  });

  test("AITHOS_FORMAT=v0.2 opts a fresh install back into the legacy format", () => {
    const home = freshHome();
    const v02 = { home, env: { AITHOS_FORMAT: "v0.2" } };
    try {
      runCli(["init", "--handle", "bob", "--display-name", "Bob"], v02);
      assert.equal(readAithos(home, "bob"), "0.2.0", "AITHOS_FORMAT=v0.2 must keep v0.2");

      // A write under the same opt-out keeps it v0.2 (no auto-migration).
      runCli(["ethos", "add-section", "--zone", "public", "--title", "Bio", "--body", "Hi.", "--handle", "bob"], v02);
      assert.equal(readAithos(home, "bob"), "0.2.0");
    } finally {
      cleanupHome(home);
    }
  });

  test("a v0.2 keystore auto-migrates to v0.3 on the first owner write", () => {
    const home = freshHome();
    const v02 = { home, env: { AITHOS_FORMAT: "v0.2" } };
    try {
      // Seed a v0.2 install with one section.
      runCli(["init", "--handle", "carol", "--display-name", "Carol"], v02);
      runCli(["ethos", "add-section", "--zone", "self", "--title", "Old", "--body", "Pre-flip.", "--handle", "carol"], v02);
      assert.equal(readAithos(home, "carol"), "0.2.0");

      // Next owner write WITHOUT the opt-out → auto-migrates to v0.3.
      const res = runCli(
        ["ethos", "add-section", "--zone", "self", "--title", "New", "--body", "Post-flip.", "--handle", "carol"],
        { home },
      );
      assert.match(res.stderr, /auto-migrated to v0\.3/i, "must announce the auto-migration");
      assert.equal(readAithos(home, "carol"), "0.3.0", "keystore must now be v0.3");

      // The prior v0.2 edition is archived.
      const histDir = join(home, "identities", "carol", "ethos", "history");
      assert.ok(existsSync(histDir) && readdirSync(histDir).some((f) => f.endsWith(".manifest.json")), "prior edition archived");

      // Both the pre- and post-migration sections are present and readable.
      const list = runCliJson<{ rows: Array<{ title: string }> }>(["ethos", "list", "--handle", "carol"], { home });
      assert.deepEqual(list.rows.map((r) => r.title).sort(), ["New", "Old"]);
    } finally {
      cleanupHome(home);
    }
  });
});
