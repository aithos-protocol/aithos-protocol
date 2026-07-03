// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Security regression: `aithos ethos unpack` must not write outside its target
 * directory (zip-slip / CWE-22). .ethos bundles are explicitly designed to be
 * imported from third parties, so every zip entry name is untrusted.
 *
 * These tests build crafted zips in-memory with adm-zip and drive
 * `runEthosUnpack` directly (deterministic, no network, no spawned binary).
 * The malicious cases must throw AND leave no file outside the out dir; the
 * legitimate case (nested public/ dir) must still extract correctly.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import AdmZip from "adm-zip";

import { runEthosUnpack } from "../src/commands/ethos-pack.ts";

function tmp(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe("ethos unpack — zip-slip guard", () => {
  test("rejects a relative traversal entry (../) and writes nothing outside out", () => {
    const work = tmp("aithos-zipslip-");
    const out = join(work, "extracted");
    const zipPath = join(work, "evil.ethos");

    // adm-zip canonicalizes `../` in addFile(), so force the traversal name
    // onto the stored entry to simulate a hand-crafted malicious zip.
    const zip = new AdmZip();
    zip.addFile("manifest.json", Buffer.from("{}"));
    zip.addFile("pwned.txt", Buffer.from("owned"));
    const evil = zip.getEntries().find((e) => e.entryName === "pwned.txt")!;
    evil.entryName = "../../pwned.txt";
    zip.writeZip(zipPath);

    assert.throws(
      () => runEthosUnpack({ path: zipPath, out, json: true }),
      /traversal|escapes/i,
    );
    // The sibling target the payload aimed at must not exist.
    assert.equal(existsSync(resolve(work, "..", "pwned.txt")), false);
    assert.equal(existsSync(join(work, "pwned.txt")), false);

    try { rmSync(work, { recursive: true, force: true }); } catch { /* best-effort temp cleanup */ }
  });

  test("rejects an absolute-path entry", () => {
    const work = tmp("aithos-zipslip-abs-");
    const out = join(work, "extracted");
    const zipPath = join(work, "evil-abs.ethos");
    const victim = join(work, "victim-should-not-be-written.txt");

    // adm-zip normalizes entryName; set it explicitly to an absolute path.
    const zip = new AdmZip();
    zip.addFile("manifest.json", Buffer.from("{}"));
    const entry = zip.getEntries()[0];
    // Add a second entry then force its name to an absolute path.
    zip.addFile("placeholder", Buffer.from("x"));
    const evil = zip.getEntries().find((e) => e.entryName === "placeholder")!;
    evil.entryName = victim; // absolute
    zip.writeZip(zipPath);

    assert.throws(
      () => runEthosUnpack({ path: zipPath, out, json: true }),
      /absolute|escapes|traversal/i,
    );
    assert.equal(existsSync(victim), false);

    try { rmSync(work, { recursive: true, force: true }); } catch { /* best-effort temp cleanup */ }
    void entry;
  });

  test("extracts a legitimate bundle with a nested public/ directory", () => {
    const work = tmp("aithos-legit-");
    const out = join(work, "extracted");
    const zipPath = join(work, "ok.ethos");

    const zip = new AdmZip();
    zip.addFile(
      "manifest.json",
      Buffer.from(
        JSON.stringify({
          bundle_id: "test",
          edition: { version: "0.3", height: 1 },
        }),
      ),
    );
    zip.addFile("did.json", Buffer.from("{}"));
    zip.addFile("public/intro.md", Buffer.from("# hello"));
    zip.writeZip(zipPath);

    // Should not throw, and files land under out/.
    runEthosUnpack({ path: zipPath, out, json: true });
    assert.equal(existsSync(join(out, "manifest.json")), true);
    assert.equal(existsSync(join(out, "public", "intro.md")), true);

    try { rmSync(work, { recursive: true, force: true }); } catch { /* best-effort temp cleanup */ }
  });

  test("still rejects a forbidden plaintext zone file (existing guard intact)", () => {
    const work = tmp("aithos-forbidden-");
    const out = join(work, "extracted");
    const zipPath = join(work, "leak.ethos");

    const zip = new AdmZip();
    zip.addFile("manifest.json", Buffer.from("{}"));
    zip.addFile("self.md", Buffer.from("secret body")); // not public.md / public/*
    zip.writeZip(zipPath);

    assert.throws(
      () => runEthosUnpack({ path: zipPath, out, json: true }),
      /Forbidden plaintext/i,
    );

    try { rmSync(work, { recursive: true, force: true }); } catch { /* best-effort temp cleanup */ }
  });
});

// Keep an unused import from tripping noUnusedLocals in strict builds.
void writeFileSync;
