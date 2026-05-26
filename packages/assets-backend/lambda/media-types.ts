// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Media-type allow-list and forbidden-set.
 *
 * Kept separate from `deps.ts` so that lightweight tests (without
 * AWS-SDK imports) can validate the allow-list logic in isolation.
 */

const DEFAULT_ALLOWED_MEDIA_TYPES = new Set<string>([
  // Images
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
  "image/svg+xml",
  "image/avif",
  // Documents
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "text/markdown",
  "text/plain",
  "text/csv",
  // Audio
  "audio/mpeg",
  "audio/wav",
  "audio/ogg",
  "audio/flac",
  "audio/aac",
  "audio/mp4",
  // Video
  "video/mp4",
  "video/webm",
  "video/quicktime",
  // Archives
  "application/zip",
]);

/** Forbidden media types (active content risks). Always rejected. */
const FORBIDDEN_MEDIA_TYPES = new Set<string>([
  "text/html",
  "application/javascript",
  "text/javascript",
  "application/xhtml+xml",
  "application/x-shockwave-flash",
]);

export function isMediaTypeAllowed(mediaType: string): boolean {
  if (FORBIDDEN_MEDIA_TYPES.has(mediaType)) return false;
  return DEFAULT_ALLOWED_MEDIA_TYPES.has(mediaType);
}
