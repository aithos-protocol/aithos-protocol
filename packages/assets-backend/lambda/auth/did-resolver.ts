// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// The DID resolver now lives in @aithos/pds-auth (shared with data-backend —
// audit M3). This convergence also drops the legacy `_subject_sphere_pubkeys`
// caller-supplied override (`withSphereOverride`) that the data backend had
// already removed: sphere keys come only from the published, root-signed
// did.json, never from caller input.
export {
  resolveIssuerDoc,
  invalidateDidCache,
} from "@aithos/pds-auth";
