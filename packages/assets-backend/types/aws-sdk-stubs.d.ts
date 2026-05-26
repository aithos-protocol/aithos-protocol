// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Minimal type stubs for `@aws-sdk/client-s3` and
 * `@aws-sdk/s3-request-presigner` so the assets-backend TypeScript code
 * can type-check in environments where these packages are not yet
 * installed (typically: the dev sandbox with constrained disk).
 *
 * **NOT a runtime substitute.** At deploy time (Phase 8), the real
 * packages MUST be installed via `npm install`; they provide the actual
 * implementation and richer types.
 *
 * Why this exists: the `@aws-sdk/client-s3` package is ~50 MB on disk;
 * not installing it shaves the install footprint when we only need to
 * type-check the source. The stubs cover only the symbols actually used
 * by `s3-presign.ts` and `deps.ts`.
 */

declare module "@aws-sdk/client-s3" {
  export interface S3ClientConfig {
    readonly region?: string;
  }
  export class S3Client {
    constructor(config?: S3ClientConfig);
    send<T>(command: unknown): Promise<T>;
  }
  export interface PutObjectCommandInput {
    Bucket: string;
    Key: string;
    ContentType?: string;
    ContentLength?: number;
    Body?: Uint8Array | string;
  }
  export class PutObjectCommand {
    constructor(input: PutObjectCommandInput);
    readonly input: PutObjectCommandInput;
  }
  export interface GetObjectCommandInput {
    Bucket: string;
    Key: string;
    ResponseContentDisposition?: string;
  }
  export class GetObjectCommand {
    constructor(input: GetObjectCommandInput);
    readonly input: GetObjectCommandInput;
  }
  export interface HeadObjectCommandInput {
    Bucket: string;
    Key: string;
  }
  export interface HeadObjectCommandOutput {
    ContentLength?: number;
    ContentType?: string;
    ETag?: string;
    LastModified?: Date;
  }
  export class HeadObjectCommand {
    constructor(input: HeadObjectCommandInput);
    readonly input: HeadObjectCommandInput;
  }
  export interface DeleteObjectCommandInput {
    Bucket: string;
    Key: string;
  }
  export class DeleteObjectCommand {
    constructor(input: DeleteObjectCommandInput);
    readonly input: DeleteObjectCommandInput;
  }
}

declare module "@aws-sdk/s3-request-presigner" {
  import type { S3Client } from "@aws-sdk/client-s3";
  export interface RequestPresigningArguments {
    readonly expiresIn?: number;
    readonly signableHeaders?: Set<string>;
  }
  export function getSignedUrl(
    client: S3Client,
    command: unknown,
    options?: RequestPresigningArguments,
  ): Promise<string>;
}
