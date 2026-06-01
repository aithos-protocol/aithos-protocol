// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * FilesystemStorage — the default {@link AithosStorage} backed by
 * `$AITHOS_HOME` on disk.
 *
 * This is a thin adapter over the existing filesystem helpers in
 * `storage.ts`, `identity.ts`, `ethos.ts`, and `mandate.ts`. It adds no new
 * protocol logic; every method is a synchronous call wrapped in an async
 * shell so the interface is natural for remote impls as well.
 *
 * The direct filesystem helpers (`loadIdentity`, `readManifest`,
 * `addSection`, …) remain exported from the package root — callers that
 * know they are on the filesystem and want synchronous semantics (CLI
 * commands, snapshot tools) may keep using them. Protocol hosts that want
 * to stay backend-agnostic should go through the `AithosStorage` surface.
 */

import fs from "node:fs";
import path from "node:path";

import type { AithosStorage, WriteAuth, SectionWriteResult } from "./backend.js";
import type { Sphere } from "./did.js";
import {
  type DidDocument,
  type Identity,
  type IdentityMetadata,
  isTrackedIdentity,
  loadIdentity,
  loadIdentityMetadata,
} from "./identity.js";
import {
  addSection as coreAddSection,
  ethosZoneFile,
  loadZoneDoc,
  modifySection as coreModifySection,
  readManifest,
  verifyEthos,
  type AddSectionArgs as CoreAddSectionArgs,
  type Manifest,
  type ModifySectionArgs as CoreModifySectionArgs,
  type VerifyEthosResult,
  type ZoneDoc,
} from "./ethos.js";
import { type Mandate, type Revocation } from "./mandate.js";
import { findRevocation, loadMandate } from "./mandate-store.js";
import {
  identityDir,
  listIdentities,
  loadConfig,
  readJson,
} from "./storage.js";

/* -------------------------------------------------------------------------- */
/*  FilesystemStorage                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Default on-disk backend. Single-instance; reads `$AITHOS_HOME` from
 * `storage.ts` at call-time so the env variable can still be overridden
 * for tests that point the home at a scratch directory.
 */
export class FilesystemStorage implements AithosStorage {
  /* -------- identity domain -------------------------------------------- */

  async listHandles(): Promise<string[]> {
    return listIdentities();
  }

  async loadIdentityMetadata(handle: string): Promise<IdentityMetadata> {
    return loadIdentityMetadata(handle);
  }

  async loadIdentity(handle: string): Promise<Identity> {
    return loadIdentity(handle);
  }

  async loadDidDocument(handle: string): Promise<DidDocument> {
    return readJson<DidDocument>(path.join(identityDir(handle), "did.json"));
  }

  async isTrackedIdentity(handle: string): Promise<boolean> {
    return isTrackedIdentity(handle);
  }

  /* -------- ethos domain (reads) --------------------------------------- */

  async readManifest(handle: string): Promise<Manifest> {
    return readManifest(handle);
  }

  async readZoneDoc(
    handle: string,
    zone: Sphere,
    opts?: { identity?: Identity; manifest?: Manifest },
  ): Promise<ZoneDoc> {
    return loadZoneDoc(handle, zone, opts?.identity, opts?.manifest);
  }

  async readZoneBytes(handle: string, zone: Sphere): Promise<Uint8Array> {
    return new Uint8Array(fs.readFileSync(ethosZoneFile(handle, zone)));
  }

  /* -------- ethos domain (writes) -------------------------------------- */

  async addSection(
    args: Omit<CoreAddSectionArgs, "identity" | "author" | "delegate">,
    auth: WriteAuth,
  ): Promise<SectionWriteResult> {
    const identity = requireIdentity(auth, "addSection");
    const result = coreAddSection({
      ...args,
      identity,
      delegate: auth.delegate,
    });
    return toSectionWriteResult(result);
  }

  async modifySection(
    args: Omit<CoreModifySectionArgs, "identity" | "author" | "delegate">,
    auth: WriteAuth,
  ): Promise<SectionWriteResult> {
    const identity = requireIdentity(auth, "modifySection");
    const result = coreModifySection({
      ...args,
      identity,
      delegate: auth.delegate,
    });
    return toSectionWriteResult(result);
  }

  /* -------- ethos verification ----------------------------------------- */

  async verifyEthos(
    handle: string,
    identity: Identity | null,
    didDoc: DidDocument,
  ): Promise<VerifyEthosResult> {
    return verifyEthos(handle, identity, didDoc);
  }

  /* -------- mandate domain --------------------------------------------- */

  async loadMandate(id: string): Promise<Mandate> {
    return loadMandate(id);
  }

  async findRevocation(mandateId: string): Promise<Revocation | null> {
    return findRevocation(mandateId);
  }

  /* -------- backend-instance state ------------------------------------- */

  async defaultHandle(): Promise<string | null> {
    return loadConfig().default_handle;
  }
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

function requireIdentity(auth: WriteAuth, op: string): Identity {
  if (!auth.identity) {
    throw new Error(
      `FilesystemStorage.${op}: auth.identity is required (the subject's ` +
        `manifest signing key must be on disk). For delegate-only writes, ` +
        `use a RemoteStorage backend or load the subject identity locally.`,
    );
  }
  return auth.identity;
}

function toSectionWriteResult(result: {
  section: { id: string; title: string; gamma_ref: string; tags?: string[] };
  manifest: Manifest;
  gammaEntry: SectionWriteResult["gammaEntry"];
}): SectionWriteResult {
  const { section, manifest, gammaEntry } = result;
  return {
    section: {
      id: section.id,
      title: section.title,
      gamma_ref: section.gamma_ref,
      tags: section.tags ?? [],
    },
    manifest,
    gammaEntry,
  };
}
