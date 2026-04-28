// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Mathieu Colla. Licensed under the Business Source License 1.1;
// see LICENSE in this package. Change Date: 2030-12-31; Change License: Apache-2.0.

/**
 * Filesystem layout for the local Aithos keystore.
 *
 *   ~/.aithos/
 *   ├── config.json
 *   ├── identities/
 *   │   └── <handle>/
 *   │       ├── did.json                   (signed DID document)
 *   │       ├── root.sealed.json           (sealed root seed — v0.1.0 stores cleartext, see SECURITY NOTE)
 *   │       ├── public.sealed.json
 *   │       ├── circle.sealed.json
 *   │       └── self.sealed.json
 *   ├── mandates/<mandate_id>.json
 *   └── revocations/<revocation_id>.json
 *
 * SECURITY NOTE: This reference CLI stores seeds as *plaintext* JSON files on
 * disk in v0.1.0, protected only by filesystem permissions (mode 0600). This
 * is WRONG for anything but a developer preview. A production implementation
 * MUST seal seeds under a passphrase using Argon2id + XChaCha20-Poly1305 as
 * specified in §1.4.3 of the protocol. That is a one-screen change, but it
 * requires a WASM libsodium dependency that keeps the CLI free-standing for
 * the proof-of-concept. The sealed format is defined in §1.4.3.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  readdirSync,
  chmodSync,
} from "node:fs";

export const AITHOS_HOME = process.env.AITHOS_HOME ?? join(homedir(), ".aithos");

export function ensureDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
}

export function identityDir(handle: string): string {
  return join(AITHOS_HOME, "identities", handle);
}

export function configPath(): string {
  return join(AITHOS_HOME, "config.json");
}

export function mandatesDir(): string {
  return join(AITHOS_HOME, "mandates");
}

export function revocationsDir(): string {
  return join(AITHOS_HOME, "revocations");
}

export function writeJson(path: string, value: unknown, mode: number = 0o600): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { mode });
  chmodSync(path, mode);
}

export function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export interface Config {
  version: string;
  default_handle: string | null;
  created_at: string;
}

export function loadConfig(): Config {
  if (!existsSync(configPath())) {
    return { version: "0.1.0", default_handle: null, created_at: new Date().toISOString() };
  }
  return readJson<Config>(configPath());
}

export function saveConfig(c: Config): void {
  ensureDir(AITHOS_HOME);
  writeJson(configPath(), c);
}

export function listIdentities(): string[] {
  const dir = join(AITHOS_HOME, "identities");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((n) => !n.startsWith("."));
}

export function listMandates(): string[] {
  if (!existsSync(mandatesDir())) return [];
  return readdirSync(mandatesDir()).filter((n) => n.endsWith(".json"));
}

export function listRevocations(): string[] {
  if (!existsSync(revocationsDir())) return [];
  return readdirSync(revocationsDir()).filter((n) => n.endsWith(".json"));
}
