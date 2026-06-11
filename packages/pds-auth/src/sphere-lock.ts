// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

import type { SignedEnvelope } from "@aithos/protocol-core/envelope";

import { RpcError } from "./errors.js";

/**
 * Sphere lock for OWNER-mode data/asset ops. The hole this closes: an Ethos
 * sphere key (#public/#circle/#self) writing data/assets. We REJECT those three
 * spheres and allow everything else a verified envelope can carry:
 *   - #data  — the protocol-intended owner data key (the normal path);
 *   - #root  — the cold master (legacy CMK migration / rotate_cmk);
 *   - a did:key canonical VM (#<multibase>) — throwaway demo identities.
 * The signature itself is already verified by verifyEnvelope; this is the
 * policy gate on WHICH sphere may sign (spec/data/02-key-hierarchy.md).
 * Throws RpcError(-32012) on an Ethos-sphere signature.
 */
const ETHOS_SPHERES = new Set(["public", "circle", "self"]);

export function assertOwnerDataSphere(envelope: SignedEnvelope): void {
  const vm =
    (envelope as { proof?: { verificationMethod?: unknown } }).proof
      ?.verificationMethod;
  const vmStr = typeof vm === "string" ? vm : "";
  const hash = vmStr.lastIndexOf("#");
  const fragment = hash >= 0 ? vmStr.slice(hash + 1) : "";
  if (ETHOS_SPHERES.has(fragment)) {
    throw new RpcError(
      -32012,
      `AITHOS_WRONG_SPHERE: owner data/asset operations cannot be signed under ` +
        `the Ethos sphere #${fragment}; use the #data sphere ` +
        `(auth.ownerDataClient() signs #data).`,
    );
  }
}
