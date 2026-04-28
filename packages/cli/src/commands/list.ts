// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Mathieu Colla. Licensed under the Business Source License 1.1;
// see LICENSE in this package. Change Date: 2030-12-31; Change License: Apache-2.0.

/**
 * `aithos list <identities|mandates|revocations>` — list local artifacts.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  listIdentities,
  listMandates,
  listRevocations,
  mandatesDir,
  revocationsDir,
  identityDir,
  loadConfig,
  isTrackedIdentity,
} from "@aithos/protocol-core";

export type ListKind = "identities" | "mandates" | "revocations";

export function runList(kind: ListKind, json = false): void {
  if (kind === "identities") {
    const ids = listIdentities();
    const config = loadConfig();
    if (json) {
      console.log(
        JSON.stringify(
          ids.map((h) => ({
            handle: h,
            default: h === config.default_handle,
            tracked: isTrackedIdentity(h),
            did: tryReadDid(h),
            path: identityDir(h),
          })),
          null,
          2,
        ),
      );
      return;
    }
    if (ids.length === 0) {
      console.log("(no identities)");
      return;
    }
    for (const h of ids) {
      const marker = h === config.default_handle ? "* " : "  ";
      const did = tryReadDid(h) ?? "(no did.json)";
      const trackedTag = isTrackedIdentity(h) ? "  [tracked]" : "";
      console.log(`${marker}${h.padEnd(20)} ${did}${trackedTag}`);
    }
    return;
  }

  if (kind === "mandates") {
    const files = listMandates();
    if (json) {
      console.log(
        JSON.stringify(
          files.map((f) => ({
            id: f.replace(/\.json$/, ""),
            ...tryReadJson(join(mandatesDir(), f)),
          })),
          null,
          2,
        ),
      );
      return;
    }
    if (files.length === 0) {
      console.log("(no mandates)");
      return;
    }
    for (const f of files) {
      const m = tryReadJson(join(mandatesDir(), f));
      if (!m) {
        console.log(`  ${f}  (unreadable)`);
        continue;
      }
      console.log(
        `  ${(m.id as string).padEnd(35)} sphere=${m.actor_sphere}  scopes=${(m.scopes as string[]).join(",")}`,
      );
      console.log(`    ${m.not_before} → ${m.not_after}`);
      console.log(`    grantee: ${(m.grantee as { id: string }).id}`);
    }
    return;
  }

  if (kind === "revocations") {
    const files = listRevocations();
    if (json) {
      console.log(
        JSON.stringify(
          files.map((f) => tryReadJson(join(revocationsDir(), f))),
          null,
          2,
        ),
      );
      return;
    }
    if (files.length === 0) {
      console.log("(no revocations)");
      return;
    }
    for (const f of files) {
      const r = tryReadJson(join(revocationsDir(), f));
      if (!r) {
        console.log(`  ${f}  (unreadable)`);
        continue;
      }
      console.log(`  ${r.mandate_id}  revoked ${r.revoked_at}  (${r.reason})`);
    }
    return;
  }

  throw new Error(`Unknown kind: ${kind}`);
}

function tryReadDid(handle: string): string | null {
  try {
    const doc = JSON.parse(readFileSync(join(identityDir(handle), "did.json"), "utf8"));
    return doc.id ?? null;
  } catch {
    return null;
  }
}

function tryReadJson(path: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}
