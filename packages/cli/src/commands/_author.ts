// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Shared author resolution for CLI section ops (add / modify / delete).
 *
 * Two paths converge into one `Author`:
 *
 *   - Owner path: `loadIdentity(handle)` + `ownerAuthor(id)`. Requires all
 *     four sealed seeds; throws `TrackedIdentityError` on tracked installs.
 *
 *   - Delegate path: `--mandate <id> --agent-key <path>`. Works on tracked
 *     installs (only `did.json` is required) because a `DelegateAuthor` only
 *     holds its own Ed25519 seed plus the subject's public metadata. All
 *     validations (scope match, pubkey match, window, revocation) happen
 *     here, before the mutation runs.
 */

import { Buffer } from "node:buffer";
import {
  type Author,
  type Mandate,
  type Sphere,
  delegateAuthor,
  findRevocation,
  loadIdentity,
  loadIdentityMetadata,
  loadMandate,
  ownerAuthor,
  readJson,
} from "@aithos/protocol-core";

/**
 * On-disk shape of the keyfile emitted by `aithos delegate-key`. Kept in
 * sync with packages/cli/src/commands/delegate-key.ts.
 */
export interface DelegateKeyfile {
  aithos?: string;
  id: string;
  seed_hex: string;
  pubkey_multibase: string;
}

export interface ResolveAuthorOpts {
  handle: string;
  /**
   * Zone the resolved Author is about to act on. When set, the mandate
   * must carry the matching scope (`ethos.write.<zone>` for `op="write"`,
   * `ethos.read.<zone>` for `op="read"`). Omit to skip the scope check.
   */
  zone?: Sphere;
  /**
   * The kind of operation. Defaults to `"write"` (the historical caller
   * shape — section add/modify/delete). Pass `"read"` for read-only ops
   * like `ethos show --zone <z>`, which require `ethos.read.<zone>`.
   */
  op?: "read" | "write";
  /** Mandate id — set iff the caller passed `--mandate`. */
  mandate?: string;
  /** Delegate keyfile path — required when `mandate` is set. */
  agentKey?: string;
}

export interface ResolvedAuthor {
  author: Author;
  /** The live mandate, present on the delegate path only. */
  mandate?: Mandate;
}

/**
 * Build an `Author` from CLI flags. Delegate path when `--mandate` is set,
 * owner path otherwise.
 */
export function resolveAuthor(opts: ResolveAuthorOpts): ResolvedAuthor {
  if (opts.mandate) {
    if (!opts.agentKey) {
      throw new Error("--mandate requires --agent-key <path>");
    }
    const key = readJson<DelegateKeyfile>(opts.agentKey);
    const mandate = loadMandate(opts.mandate);

    if (opts.zone) {
      const op = opts.op ?? "write";
      const requiredScope = `ethos.${op}.${opts.zone}` as const;
      if (!mandate.scopes.includes(requiredScope)) {
        throw new Error(
          `Mandate ${opts.mandate} does not include scope ${requiredScope}`,
        );
      }
      // The mandate's actor_sphere must match the zone, in both directions:
      //   - write: the new edition is signed under that sphere key.
      //   - read:  the DEK wrap that lets the delegate decrypt was created
      //            under that sphere's wrap recipient list.
      if (mandate.actor_sphere !== opts.zone) {
        throw new Error(
          `Mandate ${opts.mandate} actor_sphere=${mandate.actor_sphere} ` +
            `does not match target zone ${opts.zone}`,
        );
      }
    }
    if (mandate.grantee.pubkey && mandate.grantee.pubkey !== key.pubkey_multibase) {
      throw new Error("Mandate grantee.pubkey does not match agent keyfile");
    }

    const now = new Date();
    if (now < new Date(mandate.not_before)) {
      throw new Error(
        `Mandate ${opts.mandate} is not yet valid (not_before=${mandate.not_before})`,
      );
    }
    if (now >= new Date(mandate.not_after)) {
      throw new Error(
        `Mandate ${opts.mandate} has expired (not_after=${mandate.not_after})`,
      );
    }
    const revocation = findRevocation(opts.mandate);
    if (revocation) {
      throw new Error(
        `Mandate ${opts.mandate} was revoked at ${revocation.revoked_at} ` +
          `(reason: ${revocation.reason})`,
      );
    }

    // did.json is enough — a DelegateAuthor never touches sealed seeds.
    // This is the move that makes tracked installs work.
    const subject = loadIdentityMetadata(opts.handle);
    const author = delegateAuthor({
      subject,
      seed: Uint8Array.from(Buffer.from(key.seed_hex, "hex")),
      pubkeyMultibase: key.pubkey_multibase,
      mandate,
    });
    return { author, mandate };
  }

  const identity = loadIdentity(opts.handle);
  return { author: ownerAuthor(identity) };
}
