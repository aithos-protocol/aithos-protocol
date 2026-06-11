// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla
//
// Bundle v0.4 — node-side crypto half: zone-key generate/seal/open, enc_dek
// and title-v2 AEADs, manifest sign/verify. Reference implementation used by
// the platform and the conformance tests; BROWSERS use protocol-client's
// mirror (crypto/bundle-v04.ts) and must never import this module (it retains
// ethos/author/identity and their node-bound chains).

import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";

import { canonicalize } from "./canonical.js";
import { base64url, base64urlDecode } from "./encoding.js";
import {
  type Sphere,
  multibaseToEd25519PublicKey,
  sphereDidUrl,
  signWithSphere,
} from "./did.js";
import { type Identity, type DidDocument } from "./identity.js";
import {
  type ManifestSignature,
  wrapDek,
  unwrapDek,
} from "./ethos.js";
import { type Author, ownerAuthor } from "./author.js";
import {
  canonicalManifestV04Bytes,
  dekAadV04,
  titleAadV2,
  type EncDekV04,
  type KeyRingWrapV04,
  type ManifestV04,
  type TitleCipherV2,
} from "./bundle-v04.js";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/* -------------------------------------------------------------------------- */
/*  Zone master keys (N3/N4)                                                  */
/* -------------------------------------------------------------------------- */

export interface ZoneKeyV04 {
  kid: string;
  /** 32-byte XChaCha20-Poly1305 key. Caller owns zeroization. */
  key: Uint8Array;
}

export function generateZoneKeyV04(): ZoneKeyV04 {
  const kid = "zk" + Buffer.from(randomBytes(8)).toString("hex");
  return { kid, key: new Uint8Array(randomBytes(32)) };
}

/** Seal the zone key to one recipient — §3.6 wrap over jcs({kid, zone_key}). */
export function sealZoneKeyV04(
  zk: ZoneKeyV04,
  recipientLabel: string,
  recipientKexPk: Uint8Array,
): KeyRingWrapV04 {
  const payload = new TextEncoder().encode(
    canonicalize({ kid: zk.kid, zone_key: base64url(zk.key) }),
  );
  return { recipient: recipientLabel, wrap: wrapDek(payload, recipientLabel, recipientKexPk) };
}

/** Open a keyring wrap with my X25519 secret → {kid, key}. Throws on mismatch. */
export function openZoneKeyV04(entry: KeyRingWrapV04, myKexSk: Uint8Array): ZoneKeyV04 {
  const payload = unwrapDek(entry.wrap, myKexSk);
  const parsed = JSON.parse(new TextDecoder().decode(payload)) as {
    kid?: unknown;
    zone_key?: unknown;
  };
  if (typeof parsed.kid !== "string" || typeof parsed.zone_key !== "string") {
    throw new Error("keyring wrap payload malformed (expected {kid, zone_key})");
  }
  return { kid: parsed.kid, key: base64urlDecode(parsed.zone_key) };
}

/* -------------------------------------------------------------------------- */
/*  enc_dek (N3)                                                              */
/* -------------------------------------------------------------------------- */


export function encryptDekV04(
  zk: ZoneKeyV04,
  dek: Uint8Array,
  subjectDid: string,
  zone: Sphere,
  sectionId: string,
): EncDekV04 {
  const nonce = new Uint8Array(randomBytes(24));
  const aead = new XChaCha20Poly1305(zk.key);
  const c = aead.seal(nonce, dek, dekAadV04(subjectDid, zone, sectionId, zk.kid));
  return { kid: zk.kid, n: base64url(nonce), c: base64url(c) };
}

/** Throws when the AAD/kid/key don't match (tamper or wrong zone key). */
export function decryptDekV04(
  zoneKey: Uint8Array,
  encDek: EncDekV04,
  subjectDid: string,
  zone: Sphere,
  sectionId: string,
): Uint8Array {
  const aead = new XChaCha20Poly1305(zoneKey);
  const pt = aead.open(
    base64urlDecode(encDek.n),
    base64urlDecode(encDek.c),
    dekAadV04(subjectDid, zone, sectionId, encDek.kid),
  );
  if (!pt) throw new Error(`enc_dek open failed for section ${sectionId} (kid ${encDek.kid})`);
  return pt;
}

/* -------------------------------------------------------------------------- */
/*  Title cipher v2 (N2 — self)                                               */

/* -------------------------------------------------------------------------- */
/*  Title cipher v2 + manifest sign/verify                                    */
/* -------------------------------------------------------------------------- */

export function encryptTitleV2(
  dek: Uint8Array,
  subjectDid: string,
  sectionId: string,
  title: { title: string; tags?: string[] },
): TitleCipherV2 {
  const nonce = new Uint8Array(randomBytes(24));
  const aead = new XChaCha20Poly1305(dek);
  const ct = aead.seal(
    nonce,
    new TextEncoder().encode(canonicalize(title)),
    titleAadV2(subjectDid, sectionId),
  );
  return { n: base64url(nonce), ct: base64url(ct) };
}

export function decryptTitleV2(
  dek: Uint8Array,
  subjectDid: string,
  sectionId: string,
  tc: TitleCipherV2,
): { title: string; tags?: string[] } {
  const aead = new XChaCha20Poly1305(dek);
  const pt = aead.open(base64urlDecode(tc.n), base64urlDecode(tc.ct), titleAadV2(subjectDid, sectionId));
  if (!pt) throw new Error(`title_cipher open failed for section ${sectionId}`);
  return JSON.parse(new TextDecoder().decode(pt)) as { title: string; tags?: string[] };
}

function toAuthor(subject: Identity | Author): Author {
  const a = subject as Author;
  if (a.kind === "owner" || a.kind === "delegate") return a;
  return ownerAuthor(subject as Identity);
}

export function signManifestV04(subject: Identity | Author, m: ManifestV04): ManifestV04 {
  const author = toAuthor(subject);
  const baseSig: ManifestSignature =
    author.kind === "owner"
      ? { alg: "ed25519", key: sphereDidUrl(author.identity, "public"), value: "" }
      : {
          alg: "ed25519",
          key: author.pubkeyMultibase,
          value: "",
          authorized_by: author.mandate.id,
        };
  const base: ManifestV04 = {
    ...m,
    integrity: { ...m.integrity, manifest_signature: baseSig },
  };
  const bytes = new TextEncoder().encode(canonicalize(base));
  const rawSig =
    author.kind === "owner"
      ? signWithSphere(author.identity, "public", bytes)
      : ed.sign(bytes, author.seed);
  return {
    ...base,
    integrity: {
      ...base.integrity,
      manifest_signature: { ...baseSig, value: base64url(rawSig) },
    },
  };
}

export interface VerifyV04SignatureOpts {
  resolveDelegatePubkey?: (keyId: string, mandateId: string) => Uint8Array;
}

export function verifyManifestSignatureV04(
  m: ManifestV04,
  didDoc: DidDocument,
  opts: VerifyV04SignatureOpts = {},
): { ok: boolean; error?: string } {
  const sig = m.integrity.manifest_signature;
  let pk: Uint8Array;
  if (sig.authorized_by !== undefined) {
    if (!opts.resolveDelegatePubkey) {
      return {
        ok: false,
        error: `manifest is delegate-signed (authorized_by=${sig.authorized_by}) but no resolveDelegatePubkey provided`,
      };
    }
    try {
      pk = opts.resolveDelegatePubkey(sig.key, sig.authorized_by);
    } catch (e) {
      return { ok: false, error: `delegate key resolution failed: ${(e as Error).message}` };
    }
  } else {
    const vm = didDoc.verificationMethod.find((v) => v.id === sig.key);
    if (!vm) return { ok: false, error: `No verificationMethod for ${sig.key}` };
    pk = multibaseToEd25519PublicKey(vm.publicKeyMultibase);
  }
  const bytes = canonicalManifestV04Bytes(m);
  return ed.verify(base64urlDecode(sig.value), bytes, pk)
    ? { ok: true }
    : { ok: false, error: "manifest signature failed to verify" };
}
