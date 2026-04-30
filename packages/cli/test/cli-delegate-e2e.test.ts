// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * End-to-end: distant-delegate scenario driven through the built CLI.
 *
 * This test spawns the real `aithos` binary (dist/index.js) against a fresh
 * AITHOS_HOME, so every failure mode the commander wiring, argument parsing,
 * and subcommand error handling can hit is on the hook.
 *
 * Scenario (mirror of protocol-core's delegate-e2e.test.ts, one level up):
 *
 *   1. Alice `aithos init --handle alice` on home-A.
 *   2. Alice `aithos ethos add-section --zone circle …` to seed circle.
 *   3. Alice `aithos delegate-key --out …` + `aithos grant agent:bob
 *      --sphere circle --scope ethos.write.circle,ethos.read.circle
 *      --ttl 1d --pubkey <k>`  — the grant step must silently rewrap the
 *      circle zone DEK + gamma DEK to include the delegate.
 *   4. Alice `aithos ethos pack --out bundle.ethos`.
 *   5. Delegate (home-B, fresh AITHOS_HOME, same test process but different
 *      env var): `aithos ethos install bundle.ethos --as alice-tracked
 *      --set-default`.
 *   6. Delegate imports the mandate JSON (`aithos mandate add`), then
 *      `aithos ethos add-section … --mandate <id> --agent-key <keyfile>` on
 *      the tracked install — this is the step that collapses on v0.2.0.
 *   7. Delegate packs the updated bundle; Alice re-installs it (--force) and
 *      runs `aithos ethos verify --handle alice`. Must be OK: verifyEthos
 *      resolves `authorized_by` via the local mandate.
 *   8. Alice revokes the mandate (`aithos revoke <id>`). The revoke path
 *      silently repins the circle zone and gamma DEKs.
 *   9. Alice packs a post-revocation bundle, the delegate installs it, and
 *      a new delegate-side `ethos add-section` attempt must fail — the
 *      delegate is no longer a DEK recipient.
 */

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { mkdirSync, readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

import { freshHome, cleanupHome, runCli, runCliJson } from "./helpers.ts";

/* -------------------------------------------------------------------------- */
/*  Tiny JSON result shapes (narrow — we only read what we need)              */
/* -------------------------------------------------------------------------- */

interface DelegateKeyJson {
  out: string;
  pubkey: string;
}

interface GrantJson {
  mandate: {
    id: string;
    issuer: string;
    [k: string]: unknown;
  };
  path: string;
  rewrapped: boolean;
}

interface EthosPackJson {
  bundle: string;
  bundle_id: string;
}

interface InstallJson {
  installed: boolean;
  handle: string;
  did: string;
  edition: string;
  tracked: boolean;
  dir: string;
}

interface EthosVerifyJson {
  mode: string;
  ok: boolean;
  errors?: string[];
  warnings?: string[];
}

interface RevokeJson {
  revocation: { mandate_id: string; reason: string };
  path: string;
  repinned: { version: string; height: number } | null;
}

/* -------------------------------------------------------------------------- */
/*  Fixtures                                                                  */
/* -------------------------------------------------------------------------- */

const OWNER_HANDLE = "alice";
const TRACKED_HANDLE = "alice-tracked";

/* -------------------------------------------------------------------------- */
/*  Test                                                                      */
/* -------------------------------------------------------------------------- */

describe("CLI delegate-on-tracked end-to-end", () => {
  test("full scenario through the built aithos binary", () => {
    const ownerHome = freshHome();
    const delegateHome = freshHome();

    try {
      /* ---------------------------------------------------------------- */
      /*  1. Owner: init + seed circle section                            */
      /* ---------------------------------------------------------------- */

      runCli(
        ["init", "--handle", OWNER_HANDLE, "--display-name", "Alice"],
        { home: ownerHome },
      );

      runCli(
        [
          "ethos",
          "add-section",
          "--zone",
          "circle",
          "--title",
          "Friends",
          "--body",
          "Close friends only.",
          "--handle",
          OWNER_HANDLE,
        ],
        { home: ownerHome },
      );

      /* ---------------------------------------------------------------- */
      /*  2. Delegate key + write mandate (triggers DEK rewrap)           */
      /* ---------------------------------------------------------------- */

      const keyfilePath = join(ownerHome, "delegate.json");
      const keyJson = runCliJson<DelegateKeyJson>(
        ["delegate-key", "--out", keyfilePath, "--id", "agent:bob"],
        { home: ownerHome },
      );
      assert.ok(keyJson.pubkey.startsWith("z"), "delegate pubkey is multibase");

      const grant = runCliJson<GrantJson>(
        [
          "grant",
          "agent:bob",
          "--sphere",
          "circle",
          "--scope",
          "ethos.write.circle,ethos.read.circle",
          "--ttl",
          "1d",
          "--pubkey",
          keyJson.pubkey,
          "--label",
          "Bob",
          "--handle",
          OWNER_HANDLE,
        ],
        { home: ownerHome },
      );
      assert.ok(grant.mandate.id.startsWith("mandate_"));
      assert.equal(
        grant.rewrapped,
        true,
        "issuing a write-mandate on an encrypted zone must trigger DEK rewrap",
      );

      const mandateId = grant.mandate.id;
      const mandatePath = grant.path;

      /* ---------------------------------------------------------------- */
      /*  3. Owner: pack the bundle                                        */
      /* ---------------------------------------------------------------- */

      const ownerOutbox = join(ownerHome, "outbox");
      mkdirSync(ownerOutbox, { recursive: true });
      const firstBundle = join(ownerOutbox, "alice-v1.ethos");
      runCliJson<EthosPackJson>(
        ["ethos", "pack", "--out", firstBundle, "--handle", OWNER_HANDLE],
        { home: ownerHome },
      );
      assert.ok(existsSync(firstBundle), "bundle file exists on disk");

      /* ---------------------------------------------------------------- */
      /*  4. Delegate home: install bundle + mandate                      */
      /* ---------------------------------------------------------------- */

      const installed = runCliJson<InstallJson>(
        [
          "ethos",
          "install",
          firstBundle,
          "--as",
          TRACKED_HANDLE,
          "--set-default",
        ],
        { home: delegateHome },
      );
      assert.equal(installed.tracked, true, "install is a tracked identity");
      assert.equal(installed.handle, TRACKED_HANDLE);

      // Copy the mandate JSON over and import it. `mandate add` auto-resolves
      // the issuer's DID doc from the tracked install we just created.
      const delegateMandateSrc = join(delegateHome, `${mandateId}.json`);
      writeFileSync(delegateMandateSrc, readFileSync(mandatePath));
      runCli(
        ["mandate", "add", delegateMandateSrc],
        { home: delegateHome },
      );

      // Copy the delegate keyfile over too.
      const delegateKeyfile = join(delegateHome, "delegate.json");
      writeFileSync(delegateKeyfile, readFileSync(keyfilePath));

      /* ---------------------------------------------------------------- */
      /*  5. Delegate writes a circle section under the mandate           */
      /* ---------------------------------------------------------------- */

      runCli(
        [
          "ethos",
          "add-section",
          "--zone",
          "circle",
          "--title",
          "Logged by delegate",
          "--body",
          "Action note added by agent:bob.",
          "--mandate",
          mandateId,
          "--agent-key",
          delegateKeyfile,
          "--handle",
          TRACKED_HANDLE,
        ],
        { home: delegateHome },
      );

      // Re-pack from the delegate's side.
      const returnOutbox = join(delegateHome, "returnbox");
      mkdirSync(returnOutbox, { recursive: true });
      const returnBundle = join(returnOutbox, "alice-v2.ethos");
      runCliJson<EthosPackJson>(
        ["ethos", "pack", "--out", returnBundle, "--handle", TRACKED_HANDLE],
        { home: delegateHome },
      );

      /* ---------------------------------------------------------------- */
      /*  6. Owner re-installs + verifies delegate-signed entries         */
      /* ---------------------------------------------------------------- */

      runCliJson<InstallJson>(
        [
          "ethos",
          "install",
          returnBundle,
          "--as",
          OWNER_HANDLE,
          "--force",
        ],
        { home: ownerHome },
      );

      const verify = runCliJson<EthosVerifyJson>(
        ["ethos", "verify", "--handle", OWNER_HANDLE],
        { home: ownerHome },
      );
      assert.ok(
        verify.ok,
        `ethos verify must accept delegate signatures: ${JSON.stringify(verify.errors ?? [])}`,
      );

      // Owner can read the delegate's section.
      const showOut = runCli(
        [
          "ethos",
          "show",
          "--zone",
          "circle",
          "--handle",
          OWNER_HANDLE,
        ],
        { home: ownerHome },
      ).stdout;
      assert.match(
        showOut,
        /Logged by delegate/,
        "owner must see the delegate's section after reinstall",
      );

      /* ---------------------------------------------------------------- */
      /*  7. Owner revokes — revoke path must repin ethos DEKs            */
      /* ---------------------------------------------------------------- */

      const revoke = runCliJson<RevokeJson>(
        ["revoke", mandateId, "--reason", "test_end", "--handle", OWNER_HANDLE],
        { home: ownerHome },
      );
      assert.equal(revoke.revocation.mandate_id, mandateId);
      assert.ok(revoke.repinned, "revoke must repin when ethos zones are touched");

      /* ---------------------------------------------------------------- */
      /*  8. Owner packs a post-revocation bundle; delegate cannot write */
      /* ---------------------------------------------------------------- */

      const postRevOutbox = join(ownerHome, "post-rev");
      mkdirSync(postRevOutbox, { recursive: true });
      const postRevBundle = join(postRevOutbox, "alice-v3.ethos");
      runCliJson<EthosPackJson>(
        ["ethos", "pack", "--out", postRevBundle, "--handle", OWNER_HANDLE],
        { home: ownerHome },
      );

      runCliJson<InstallJson>(
        [
          "ethos",
          "install",
          postRevBundle,
          "--as",
          TRACKED_HANDLE,
          "--force",
        ],
        { home: delegateHome },
      );

      // A fresh delegate write must now fail — the delegate is no longer a
      // recipient on the current edition's DEK wrap list.
      const forbidden = runCli(
        [
          "ethos",
          "add-section",
          "--zone",
          "circle",
          "--title",
          "Should fail",
          "--body",
          "Revocation should stop me.",
          "--mandate",
          mandateId,
          "--agent-key",
          delegateKeyfile,
          "--handle",
          TRACKED_HANDLE,
        ],
        { home: delegateHome, expectOk: false },
      );
      assert.notEqual(
        forbidden.status,
        0,
        "post-revocation delegate write must exit non-zero",
      );
      assert.match(
        forbidden.stderr + forbidden.stdout,
        /wrap|unwrap|decrypt|recipient|revoked/i,
        `delegate failure must be a wrap/decrypt/revocation error; got:\n` +
          `  stdout: ${forbidden.stdout}\n  stderr: ${forbidden.stderr}`,
      );
    } finally {
      cleanupHome(ownerHome);
      cleanupHome(delegateHome);
    }
  });
});
