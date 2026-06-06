// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Write-format helpers shared by the section-mutation commands.
 *
 * With v0.3 as the default on-disk format (lot 4b-3), the first *owner* write to
 * a still-v0.2 keystore migrates it in place to the per-section layout. Delegate
 * writers can't migrate (they hold no sphere keys), so they keep writing through
 * the v0.2 path until the owner upgrades the install. Set `AITHOS_FORMAT=v0.2`
 * to suppress the auto-migration entirely.
 */

import {
  autoMigrateKeystoreIfDefault,
  loadIdentity,
} from "@aithos/protocol-core";

/**
 * On the owner write path, migrate a v0.2 keystore to v0.3 when v0.3 is the
 * default format. No-op for delegate writers and when already v0.3 / opted out.
 * Returns true iff a migration ran (so the caller can print a one-time notice).
 */
export function autoMigrateOwnerWrite(handle: string, isDelegate: boolean): boolean {
  if (isDelegate) return false;
  return autoMigrateKeystoreIfDefault({ handle, identity: loadIdentity(handle) });
}
