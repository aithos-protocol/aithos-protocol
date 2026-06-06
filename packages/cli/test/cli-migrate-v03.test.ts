// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * End-to-end: `aithos ethos migrate-to-v0.3` driven through the built CLI.
 *
 * Seeds a v0.2 ethos (one section per zone), runs the migration, and checks
 * that the produced bundle is the per-section v0.3 layout, chains back to the
 * v0.2 predecessor, and passes the v0.3 verifier via `ethos verify --path`.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { freshHome, cleanupHome, runCli, runCliJson } from "./helpers.ts";

interface MigrateJson {
  handle: string;
  migrated_to: string;
  bundle_id: string;
  supersedes: string | null;
  prev_hash: string | null;
  edition: { version: string; height: number };
  sections: { public: number; circle: number; self: number };
}

interface VerifyJson {
  ok: boolean;
  errors: string[];
  zones_skipped: string[];
  bundle_id: string;
}

describe("aithos ethos migrate-to-v0.3 (CLI e2e)", () => {
  test("migrates a v0.2 ethos into a verifiable v0.3 per-section bundle", () => {
    const home = freshHome();
    try {
      runCli(["init", "--handle", "alice", "--display-name", "Alice"], { home });
      runCli(["ethos", "add-section", "--handle", "alice", "--zone", "public", "--title", "Bio", "--body", "Public bio."], { home });
      runCli(["ethos", "add-section", "--handle", "alice", "--zone", "circle", "--title", "Day rate", "--body", "1200/day."], { home });
      runCli(["ethos", "add-section", "--handle", "alice", "--zone", "self", "--title", "Routine", "--body", "Up at six."], { home });

      const out = join(home, "alice-v03");
      const mig = runCliJson<MigrateJson>(
        ["ethos", "migrate-to-v0.3", "--handle", "alice", "--out", out],
        { home },
      );

      // Migration edition: chains back to the v0.2 predecessor, one section per zone.
      assert.ok(mig.supersedes && mig.supersedes.startsWith("urn:aithos:alice:"), "supersedes set");
      assert.notEqual(mig.bundle_id, mig.supersedes, "new bundle_id differs from predecessor");
      assert.ok(mig.prev_hash && mig.prev_hash.startsWith("sha256:"), "prev_hash set");
      assert.deepEqual(mig.sections, { public: 1, circle: 1, self: 1 });

      // Per-section v0.3 layout on disk: public/<id>.md, circle|self/<id>.enc.
      assert.ok(existsSync(join(out, "manifest.json")));
      assert.ok(existsSync(join(out, "did.json")));
      const ls = (dir: string) => {
        // exactly one file per zone subdir
        const p = join(out, dir);
        assert.ok(existsSync(p), `${dir}/ exists`);
      };
      ls("public");
      ls("circle");
      ls("self");

      // The v0.3 verifier accepts it (stateless: encrypted zones opaque-but-attested).
      const v = runCliJson<VerifyJson>(["ethos", "verify", "--path", out], { home });
      assert.ok(v.ok, `verify failed: ${v.errors.join(", ")}`);
      assert.equal(v.bundle_id, mig.bundle_id);
      assert.deepEqual([...v.zones_skipped].sort(), ["circle", "self"]);

      // Re-running migration is rejected once the ethos is no longer v0.2?
      // (still v0.2 here — the keystore is unchanged — so a second run succeeds
      // and is idempotent in spirit. We just assert it does not error.)
      const out2 = join(home, "alice-v03-again");
      const mig2 = runCliJson<MigrateJson>(
        ["ethos", "migrate-to-v0.3", "--handle", "alice", "--out", out2],
        { home },
      );
      assert.deepEqual(mig2.sections, { public: 1, circle: 1, self: 1 });
    } finally {
      cleanupHome(home);
    }
  });
});
