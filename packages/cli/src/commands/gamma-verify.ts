/**
 * `aithos gamma verify` — end-to-end integrity check of the gamma log.
 *
 * Checks:
 *   1. Every entry: self-hash matches, signature verifies against the
 *      resolved key (sphere key from the DID doc, or a delegate key via a
 *      mandate loaded from ~/.aithos/mandates/).
 *   2. Chain linkage: every entry's `prev_gamma_hash` equals the previous
 *      entry's `hash`, and `at` strictly increases along the chain.
 *   3. Anchor: the manifest's `gamma.head` equals the on-disk log's head
 *      hash, and `gamma.count` matches the number of entries.
 *
 * Exit codes:
 *   - 0 → valid
 *   - 1 → one or more checks failed
 *   - 2 → parse error (caller converts thrown errors)
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  loadIdentity,
  loadConfig,
  ethosDir,
  identityDir,
  readJson,
  readGammaLog,
  verifyGammaLog,
  readManifest,
  loadMandate,
  type DidDocument,
} from "@aithos/protocol-core";

export interface GammaVerifyOpts {
  handle?: string;
  json?: boolean;
}

export function runGammaVerify(opts: GammaVerifyOpts): void {
  const handle = opts.handle ?? loadConfig().default_handle;
  if (!handle) throw new Error("No identity handle. Pass --handle <h>.");
  if (!existsSync(ethosDir(handle))) {
    throw new Error(`No ethos for "${handle}".`);
  }
  const identity = loadIdentity(handle);
  const didDoc = readJson<DidDocument>(join(identityDir(handle), "did.json"));
  const entries = readGammaLog(handle, identity);

  const chain = verifyGammaLog(entries, didDoc, {
    resolveDelegatePubkey: (_keyId, mandateId) => {
      const mandate = loadMandate(mandateId);
      if (!mandate.grantee.pubkey) {
        throw new Error(
          `Mandate ${mandateId} has no grantee.pubkey — cannot resolve delegate`,
        );
      }
      return multibaseToRaw(mandate.grantee.pubkey);
    },
  });

  // Anchor check against the manifest.
  const manifest = safeReadManifest(handle);
  const actualHead = entries.length > 0 ? entries[entries.length - 1].hash : null;
  const manifestHead = manifest?.gamma?.head ?? null;
  const manifestCount = manifest?.gamma?.count ?? null;

  const anchorErrors: string[] = [];
  if (manifest && manifest.gamma) {
    if (manifestHead !== actualHead) {
      anchorErrors.push(
        `manifest.gamma.head=${manifestHead ?? "(null)"} but actual head=${actualHead ?? "(null)"}`,
      );
    }
    if (manifestCount !== entries.length) {
      anchorErrors.push(
        `manifest.gamma.count=${manifestCount} but actual count=${entries.length}`,
      );
    }
  } else if (entries.length > 0) {
    anchorErrors.push("log has entries but manifest has no gamma anchor");
  }

  const ok = chain.ok && anchorErrors.length === 0;

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          ok,
          count: entries.length,
          head: actualHead,
          manifest: manifest?.gamma ?? null,
          chain_errors: chain.errors,
          anchor_errors: anchorErrors,
        },
        null,
        2,
      ),
    );
    if (!ok) process.exit(1);
    return;
  }

  console.log(`[handle=${handle}] gamma verify`);
  console.log(`  entries:  ${entries.length}`);
  console.log(`  head:     ${actualHead ?? "(none)"}`);
  if (manifest?.gamma) {
    console.log(`  manifest: head=${manifest.gamma.head ?? "(null)"} count=${manifest.gamma.count}`);
  } else {
    console.log(`  manifest: (no gamma anchor)`);
  }
  console.log("");
  if (chain.errors.length > 0) {
    console.log(`  chain:    FAIL`);
    for (const e of chain.errors) {
      console.log(`    [${e.index}] ${e.entryId}: ${e.error}`);
    }
  } else {
    console.log(`  chain:    ok (${entries.length} entries)`);
  }
  if (anchorErrors.length > 0) {
    console.log(`  anchor:   FAIL`);
    for (const a of anchorErrors) console.log(`    ${a}`);
  } else {
    console.log(`  anchor:   ok`);
  }
  console.log("");
  console.log(`  result:   ${ok ? "PASS" : "FAIL"}`);

  if (!ok) process.exit(1);
}

function safeReadManifest(handle: string) {
  try {
    return readManifest(handle);
  } catch {
    return null;
  }
}

/**
 * Decode a multibase-encoded Ed25519 public key (as used in mandate grantee
 * pubkey fields) into raw 32 bytes.
 *
 * The canonical helper lives in protocol-core but is not re-exported; we
 * duplicate a minimal base58 decoder here to keep the CLI dependency-light.
 */
function multibaseToRaw(mb: string): Uint8Array {
  if (!mb.startsWith("z")) throw new Error(`Expected multibase z-prefix: ${mb}`);
  const decoded = base58decode(mb.slice(1));
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("Not an Ed25519 multicodec-prefixed multibase key");
  }
  return decoded.slice(2);
}

function base58decode(s: string): Uint8Array {
  const ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map = new Map<string, number>();
  for (let i = 0; i < ALPHA.length; i++) map.set(ALPHA[i], i);

  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;

  const b256: number[] = [];
  for (let i = zeros; i < s.length; i++) {
    const c = s[i];
    const v = map.get(c);
    if (v === undefined) throw new Error(`Invalid base58 char: ${c}`);
    let carry = v;
    for (let j = 0; j < b256.length; j++) {
      carry += b256[j] * 58;
      b256[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      b256.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + b256.length);
  for (let i = 0; i < b256.length; i++) out[zeros + b256.length - 1 - i] = b256[i];
  return out;
}
