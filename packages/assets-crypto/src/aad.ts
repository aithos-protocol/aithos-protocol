// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * AAD (Additional Authenticated Data) construction for the assets
 * sub-protocol.
 *
 * Two AADs are used:
 *
 *  1. Asset bytes encryption (§2.3.2):
 *
 *       "aithos-asset-v1\0" ‖ utf8(asset_urn)
 *
 *     Binds the AEAD ciphertext to the asset URN. Prevents replay of
 *     a ciphertext into a different asset_id within the same bundle.
 *
 *  2. AMK wrap encryption (§2.3.3):
 *
 *       "aithos-assets-amk-v1\0" ‖ utf8(asset_urn) ‖ "\0" ‖ utf8(recipient_did_url)
 *
 *     Binds a wrap to (asset_urn, recipient_did_url). Prevents a wrap
 *     from being replayed across assets or across recipients within the
 *     same asset.
 *
 * The prefixes deliberately differ from the data sub-protocol's
 * (`aithos-data-record-v1\0`, `aithos-data-cmk-v1\0`) to make
 * cross-sub-protocol confusion fail loudly at the AEAD layer.
 */

const ASSET_BYTES_PREFIX = utf8("aithos-asset-v1\0");
const AMK_WRAP_PREFIX = utf8("aithos-assets-amk-v1\0");

/**
 * Compose the AEAD AAD bytes for the asset's byte encryption (§2.3.2):
 *
 *   "aithos-asset-v1\0" ‖ utf8(asset_urn)
 */
export function aadForAssetBytes(assetUrn: string): Uint8Array {
  const u = utf8(assetUrn);
  const out = new Uint8Array(ASSET_BYTES_PREFIX.length + u.length);
  out.set(ASSET_BYTES_PREFIX, 0);
  out.set(u, ASSET_BYTES_PREFIX.length);
  return out;
}

/**
 * Compose the AEAD AAD bytes for an AMK wrap (§2.3.3):
 *
 *   "aithos-assets-amk-v1\0" ‖ utf8(asset_urn) ‖ "\0" ‖ utf8(recipient_did_url)
 */
export function aadForAMKWrap(
  assetUrn: string,
  recipientDidUrl: string,
): Uint8Array {
  const a = utf8(assetUrn);
  const r = utf8(recipientDidUrl);
  const sep = new Uint8Array([0]);
  const total = AMK_WRAP_PREFIX.length + a.length + sep.length + r.length;
  const out = new Uint8Array(total);
  let off = 0;
  out.set(AMK_WRAP_PREFIX, off);
  off += AMK_WRAP_PREFIX.length;
  out.set(a, off);
  off += a.length;
  out.set(sep, off);
  off += sep.length;
  out.set(r, off);
  return out;
}

/**
 * HKDF salt for wrap-key derivation. Spec §2.3.3:
 *
 *   salt = "aithos-assets-amk-wrap-v1"
 */
export const HKDF_WRAP_SALT = utf8("aithos-assets-amk-wrap-v1");

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
