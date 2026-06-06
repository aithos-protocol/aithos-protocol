// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * End-to-end: `aithos ethos read` over a migrated v0.3 bundle.
 *
 * Verifies the circle-clear / self-private compromise through the CLI: a host
 * (no key) sees circle titles but the self titles are hidden; the subject
 * (with key) decrypts the self index and fetches one or several sections by id.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { join } from "node:path";

import { freshHome, cleanupHome, runCli, runCliJson } from "./helpers.ts";

interface IndexRow {
  section_id: string;
  title?: string;
  title_hidden: boolean;
}
interface IndexJson {
  zones: Record<string, { index_encrypted: boolean; sections: IndexRow[] }>;
}
interface ReadJson {
  sections: Array<{
    zone?: string;
    section_id: string;
    accessible: boolean;
    title?: string;
    body?: string;
  }>;
}

describe("aithos ethos read (CLI e2e — encrypted self index)", () => {
  test("host sees circle titles but not self; owner decrypts + reads by id array", () => {
    const home = freshHome();
    // Seed a v0.2 ethos, then exercise the v0.3 read surface over the bundle
    // produced by `migrate-to-v0.3` (fresh installs now default to v0.3, so the
    // seeding commands pin the legacy format).
    const v02 = { home, env: { AITHOS_FORMAT: "v0.2" } };
    try {
      runCli(["init", "--handle", "demo", "--display-name", "Demo"], v02);
      runCli(["ethos", "add-section", "--handle", "demo", "--zone", "circle", "--title", "Tarif jour", "--body", "1200 EUR/jour."], v02);
      runCli(["ethos", "add-section", "--handle", "demo", "--zone", "self", "--title", "Routine", "--body", "Lever 6h."], v02);
      runCli(["ethos", "add-section", "--handle", "demo", "--zone", "self", "--title", "Objectifs", "--body", "Lancer v0.3."], v02);

      const bundle = join(home, "demo-v03");
      runCli(["ethos", "migrate-to-v0.3", "--handle", "demo", "--out", bundle], { home });

      // Host view (no key): pass a handle with no keystore entry.
      const host = runCliJson<IndexJson>(["ethos", "read", "--path", bundle, "--index", "--handle", "nobody"], { home });
      assert.equal(host.zones.circle.index_encrypted, false);
      assert.equal(host.zones.circle.sections[0].title, "Tarif jour");
      assert.equal(host.zones.self.index_encrypted, true);
      assert.deepEqual(host.zones.self.sections.map((s) => s.title_hidden), [true, true]);
      assert.deepEqual(host.zones.self.sections.map((s) => s.title), [undefined, undefined]);

      // Owner view (with key): self titles decrypt.
      const owner = runCliJson<IndexJson>(["ethos", "read", "--path", bundle, "--index", "--handle", "demo"], { home });
      const selfTitles = owner.zones.self.sections.map((s) => s.title);
      assert.deepEqual(selfTitles, ["Routine", "Objectifs"]);

      // Fetch BOTH self sections at once via an id array.
      const ids = owner.zones.self.sections.map((s) => s.section_id).join(",");
      const read = runCliJson<ReadJson>(["ethos", "read", "--path", bundle, "--handle", "demo", "--section", ids], { home });
      assert.equal(read.sections.length, 2);
      assert.ok(read.sections.every((s) => s.accessible && s.zone === "self"));
      assert.deepEqual(read.sections.map((s) => s.title).sort(), ["Objectifs", "Routine"]);
      const routine = read.sections.find((s) => s.title === "Routine");
      assert.equal(routine!.body, "Lever 6h.");

      // A host trying to fetch a self section by id gets it as inaccessible.
      const hostRead = runCliJson<ReadJson>(["ethos", "read", "--path", bundle, "--handle", "nobody", "--section", owner.zones.self.sections[0].section_id], { home });
      assert.equal(hostRead.sections[0].accessible, false);
    } finally {
      cleanupHome(home);
    }
  });
});
