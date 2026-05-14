// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Handler for `aithos.data.list_gamma_entries`.
 *
 * Spec ref: `spec/data/08-audit.md` §8.7.
 *
 * Owner-only in v0.1. A delegate might be granted read access via a
 * `gamma.read` scope in a future revision; until then only the
 * subject can audit their own chain.
 */

import { RpcError } from "../jsonrpc.js";
import {
  requireSubjectMatch,
  type Caller,
} from "../auth/authenticate.js";
import { listEntries, verifyChain } from "../gamma/store.js";
import { validateRequired } from "./collections.js";

interface ListGammaEntriesParams {
  subject_did?: string;
  limit?: number;
  /** Optional: filter entries by op prefix (e.g. "data.record" → record-level only). */
  op_prefix?: string;
  /** Optional: include a chain verification result in the response. */
  verify?: boolean;
}

export async function listGammaEntriesHandler(caller: Caller): Promise<unknown> {
  const p = caller.params as ListGammaEntriesParams;
  validateRequired(p, ["subject_did"]);
  requireSubjectMatch(caller, p.subject_did!);

  if (caller.mode !== "owner") {
    throw new RpcError(
      -32042,
      "AITHOS_INSUFFICIENT_SCOPE: list_gamma_entries is owner-only in v0.1",
    );
  }

  const limit = Math.min(p.limit ?? 100, 1000);
  let entries = await listEntries(p.subject_did!, limit);
  if (p.op_prefix) {
    entries = entries.filter((e) => e.op.startsWith(p.op_prefix!));
  }

  const result: Record<string, unknown> = { items: entries };
  if (p.verify) {
    const v = await verifyChain(p.subject_did!);
    result.verification = v;
  }

  return result;
}
