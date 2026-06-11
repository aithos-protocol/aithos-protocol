// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// The DID resolver implementation now lives in @aithos/pds-auth (shared by the
// data and assets PDS backends — audit M3, ends the divergent duplicate). This
// module is kept as a stable local path for in-package imports and tests.
export {
  resolveIssuerDoc,
  invalidateDidCache,
} from "@aithos/pds-auth";
