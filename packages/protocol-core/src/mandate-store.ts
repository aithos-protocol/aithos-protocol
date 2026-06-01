// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Filesystem keystore for mandates and revocations (CLI / Node only).
 *
 * Split out of mandate.ts so the verification primitives (verifyMandate,
 * createMandate, scope helpers) stay free of node:fs/path — that keeps the
 * envelope/mandate verify path bundleable in the browser. Anything that reads
 * or writes the local `~/.aithos` keystore lives here and is Node-only.
 */

import { join } from "node:path";
import { existsSync } from "node:fs";

import {
  mandatesDir,
  revocationsDir,
  ensureDir,
  writeJson,
  readJson,
} from "./storage.js";
import type { Mandate, Revocation } from "./mandate.js";

export function writeMandate(m: Mandate): string {
  ensureDir(mandatesDir());
  const path = join(mandatesDir(), `${m.id}.json`);
  writeJson(path, m, 0o600);
  return path;
}

export function loadMandate(mandateId: string): Mandate {
  const path = join(mandatesDir(), `${mandateId}.json`);
  if (!existsSync(path)) throw new Error(`Mandate not found: ${mandateId}`);
  return readJson<Mandate>(path);
}

export function writeRevocation(r: Revocation): string {
  ensureDir(revocationsDir());
  const path = join(
    revocationsDir(),
    `revocation_${r.mandate_id.replace(/^mandate_/, "")}.json`,
  );
  writeJson(path, r, 0o600);
  return path;
}

export function loadRevocation(path: string): Revocation {
  return readJson<Revocation>(path);
}

/**
 * Return the local revocation for a mandate id, or null if none is on disk.
 *
 * The expected on-disk name is `revocation_<ULID>.json` in `revocationsDir()`,
 * where `<ULID>` is the mandate id with its `mandate_` prefix stripped — this
 * matches what `writeRevocation` produces.
 */
export function findRevocation(mandateId: string): Revocation | null {
  const ulidPart = mandateId.replace(/^mandate_/, "");
  const path = join(revocationsDir(), `revocation_${ulidPart}.json`);
  if (!existsSync(path)) return null;
  return readJson<Revocation>(path);
}
