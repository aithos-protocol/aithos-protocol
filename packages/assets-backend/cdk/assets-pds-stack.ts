// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * AithosAssetsPdsStack — the AWS infrastructure for the Aithos assets
 * sub-protocol PDS.
 *
 * Components:
 *
 *   - S3 bucket `aithos-assets-pds-dev` — stores asset bytes
 *       Layout: <subject_did>/<asset_id>/raw.bin
 *       Versioned, KMS (AWS-managed), public-block enforced.
 *       Public assets served via CloudFront with Origin Access Control.
 *
 *   - DynamoDB table `aithos-assets-pds-dev` — asset metadata index
 *       PK = subject_did
 *       SK = asset_id  (sorts chronologically via ULID)
 *       GSI1: PK = subject_did, SK = sha256_of_plaintext  (dedup probe)
 *       GSI2: PK = global_purge_bucket, SK = last_referenced_at  (purge scheduler — out of scope v0.1 implem, kept for v0.2)
 *
 *   - DynamoDB table `aithos-assets-pds-nonces-dev` — anti-replay
 *       PK = nonce_key  (envelope nonce + iss)
 *       TTL on `expires_at_epoch`
 *
 *   - DynamoDB table `aithos-assets-pds-gamma-dev` — audit chain
 *       PK = subject_did
 *       SK = entry_id  (ULID)
 *
 *   - DynamoDB table `aithos-assets-pds-uploads-dev` — pending uploads
 *       PK = upload_session
 *       TTL on `expires_at_epoch`
 *       Holds init_upload state until complete_upload.
 *
 *   - Lambda router (Node 20 ARM64, esbuild-bundled)
 *       single function dispatches over JSON-RPC method name.
 *       Permissions: read/write all four Dynamo tables + S3 put/get/delete +
 *       S3 presign (signed via Lambda execution role).
 *
 *   - HTTP API Gateway (CORS enabled)
 *       routes: POST /mcp/primitives/read, POST /mcp/primitives/write, GET /healthz
 *
 *   - CloudFront distribution for public assets
 *       Origin Access Control (OAC) to read from S3 bucket directly
 *       Stable URL: https://<dist-domain>/<subject_did>/<asset_id>/raw.bin
 *
 * Notes for v0.1 dev:
 *   - On-demand billing on all tables — no capacity planning needed.
 *   - PITR enabled on metadata + gamma tables (audit-critical).
 *   - removalPolicy=DESTROY so `cdk destroy` cleans up entirely.
 *   - Lambda authorizer is intentionally absent in this iteration; the
 *     handler verifies envelope + sphere key inline (owner-only auth in
 *     v0.1; mandates land in v0.2).
 */

import {
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
  CfnOutput,
} from "aws-cdk-lib";
import {
  AttributeType,
  BillingMode,
  Table,
  TableEncryption,
  ProjectionType,
} from "aws-cdk-lib/aws-dynamodb";
import {
  HttpApi,
  HttpMethod,
  CorsHttpMethod,
} from "aws-cdk-lib/aws-apigatewayv2";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import { Runtime, LoggingFormat, Architecture } from "aws-cdk-lib/aws-lambda";
import {
  NodejsFunction,
  OutputFormat,
} from "aws-cdk-lib/aws-lambda-nodejs";
import { RetentionDays } from "aws-cdk-lib/aws-logs";
import {
  Bucket,
  BucketEncryption,
  BlockPublicAccess,
  ObjectOwnership,
  HttpMethods as S3HttpMethods,
} from "aws-cdk-lib/aws-s3";
import {
  Distribution,
  AllowedMethods,
  CachedMethods,
  ViewerProtocolPolicy,
  ResponseHeadersPolicy,
  CachePolicy,
  HeadersFrameOption,
  HeadersReferrerPolicy,
} from "aws-cdk-lib/aws-cloudfront";
import { S3BucketOrigin } from "aws-cdk-lib/aws-cloudfront-origins";
import type { Construct } from "constructs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface AithosAssetsPdsStackProps extends StackProps {
  /**
   * Per-subject quota in bytes. Default 5 GB. Configurable per
   * deployment.
   *
   * Spec ref: spec/assets/10-open-questions.md §10.13 (locked decision).
   */
  readonly perSubjectQuotaBytes?: number;
  /**
   * Per-asset cap in bytes. Default 100 MB.
   *
   * Spec ref: spec/assets/01-data-model.md §1.6.
   */
  readonly perAssetCapBytes?: number;
  /**
   * TTL for presigned URLs (PUT and GET). Default 900 seconds (15 min).
   */
  readonly presignedUrlTtlSeconds?: number;
}

export class AithosAssetsPdsStack extends Stack {
  constructor(
    scope: Construct,
    id: string,
    props?: AithosAssetsPdsStackProps,
  ) {
    super(scope, id, props);

    const perSubjectQuotaBytes = props?.perSubjectQuotaBytes ?? 5 * 1024 * 1024 * 1024; // 5 GB
    const perAssetCapBytes = props?.perAssetCapBytes ?? 100 * 1024 * 1024; // 100 MB
    const presignedUrlTtlSeconds = props?.presignedUrlTtlSeconds ?? 900; // 15 min

    /* -------------------------------------------------------------------- */
    /*  S3 bucket — asset bytes                                              */
    /* -------------------------------------------------------------------- */

    // Note: autoDeleteObjects intentionally NOT enabled even in dev.
    // It would (a) require a custom resource Lambda that prevents
    // `cdk synth` on read-only / FUSE filesystems, and (b) is a foot-gun
    // in production where an accidental `cdk destroy` would wipe user
    // bytes. Operators who need to tear down should empty the bucket
    // manually via the AWS console or CLI before `cdk destroy`.
    const assetsBucket = new Bucket(this, "AssetsBucket", {
      bucketName: `aithos-assets-pds-dev-${this.account}`,
      versioned: true,
      encryption: BucketEncryption.S3_MANAGED,
      blockPublicAccess: BlockPublicAccess.BLOCK_ALL,
      objectOwnership: ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: RemovalPolicy.RETAIN,
      cors: [
        {
          // Allow the SDK to PUT directly to presigned URLs from browsers.
          allowedMethods: [
            S3HttpMethods.PUT,
            S3HttpMethods.GET,
            S3HttpMethods.HEAD,
          ],
          allowedOrigins: ["*"],
          allowedHeaders: ["*"],
          exposedHeaders: ["ETag", "x-amz-version-id"],
          maxAge: 3600,
        },
      ],
    });

    /* -------------------------------------------------------------------- */
    /*  DynamoDB — asset metadata index                                      */
    /* -------------------------------------------------------------------- */

    const assetsTable = new Table(this, "AssetsTable", {
      tableName: "aithos-assets-pds-dev",
      partitionKey: { name: "pk", type: AttributeType.STRING }, // subject_did
      sortKey: { name: "sk", type: AttributeType.STRING }, // asset_id
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // GSI1 — dedup probe: (subject_did, sha256_of_plaintext) → asset_id
    assetsTable.addGlobalSecondaryIndex({
      indexName: "gsi1_by_subject_sha",
      partitionKey: { name: "gsi1pk", type: AttributeType.STRING }, // = subject_did
      sortKey: { name: "gsi1sk", type: AttributeType.STRING }, // = sha256_of_plaintext
      projectionType: ProjectionType.KEYS_ONLY,
    });

    // GSI2 — purge scheduler: shard partition + last_referenced_at
    // PK = "purge#<shard>" (so we can scan in parallel), SK = ISO 8601 timestamp
    // Out of scope for v0.1 implementation; the schema slot is reserved.
    assetsTable.addGlobalSecondaryIndex({
      indexName: "gsi2_purge_by_age",
      partitionKey: { name: "gsi2pk", type: AttributeType.STRING },
      sortKey: { name: "gsi2sk", type: AttributeType.STRING },
      projectionType: ProjectionType.KEYS_ONLY,
    });

    /* -------------------------------------------------------------------- */
    /*  DynamoDB — anti-replay nonces                                        */
    /* -------------------------------------------------------------------- */

    const nonceTable = new Table(this, "NonceTable", {
      tableName: "aithos-assets-pds-nonces-dev",
      partitionKey: { name: "pk", type: AttributeType.STRING }, // <iss>#<nonce>
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: "expires_at_epoch",
      removalPolicy: RemovalPolicy.DESTROY,
    });

    /* -------------------------------------------------------------------- */
    /*  DynamoDB — gamma log                                                 */
    /* -------------------------------------------------------------------- */
    //
    // PK = subject_did; SK = entry_id (ULID, chronological order).
    // Latest head per subject = Query(PK=subject, ScanIndexForward=false,
    // Limit=1). No extra index needed.

    const gammaTable = new Table(this, "GammaTable", {
      tableName: "aithos-assets-pds-gamma-dev",
      partitionKey: { name: "subject_did", type: AttributeType.STRING },
      sortKey: { name: "entry_id", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    /* -------------------------------------------------------------------- */
    /*  DynamoDB — pending uploads                                           */
    /* -------------------------------------------------------------------- */

    const uploadsTable = new Table(this, "UploadsTable", {
      tableName: "aithos-assets-pds-uploads-dev",
      partitionKey: { name: "upload_session", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: "expires_at_epoch",
      removalPolicy: RemovalPolicy.DESTROY,
    });

    /* -------------------------------------------------------------------- */
    /*  Lambda router                                                        */
    /* -------------------------------------------------------------------- */

    const router = new NodejsFunction(this, "RouterFn", {
      functionName: "aithos-assets-pds-router-dev",
      runtime: Runtime.NODEJS_20_X,
      architecture: Architecture.ARM_64,
      entry: path.join(__dirname, "..", "lambda", "router.ts"),
      depsLockFilePath:
        process.env.AITHOS_DEPS_LOCK_FILE ??
        path.join(__dirname, "..", "..", "..", "package-lock.json"),
      handler: "handler",
      memorySize: 512,
      timeout: Duration.seconds(15),
      loggingFormat: LoggingFormat.JSON,
      logRetention: RetentionDays.ONE_WEEK,
      environment: {
        ASSETS_BUCKET_NAME: assetsBucket.bucketName,
        ASSETS_TABLE_NAME: assetsTable.tableName,
        NONCE_TABLE_NAME: nonceTable.tableName,
        GAMMA_TABLE_NAME: gammaTable.tableName,
        UPLOADS_TABLE_NAME: uploadsTable.tableName,
        PER_SUBJECT_QUOTA_BYTES: String(perSubjectQuotaBytes),
        PER_ASSET_CAP_BYTES: String(perAssetCapBytes),
        PRESIGNED_URL_TTL_SECONDS: String(presignedUrlTtlSeconds),
        AITHOS_ASSETS_PROTOCOL_VERSION: "0.1.0",
      },
      bundling: {
        target: "node20",
        format: OutputFormat.ESM,
        mainFields: ["module", "main"],
        externalModules: ["@aws-sdk/*"],
        banner:
          "import { createRequire } from 'module'; const require = createRequire(import.meta.url);",
      },
    });

    // IAM grants
    assetsTable.grantReadWriteData(router);
    nonceTable.grantReadWriteData(router);
    gammaTable.grantReadWriteData(router);
    uploadsTable.grantReadWriteData(router);
    assetsBucket.grantReadWrite(router);
    assetsBucket.grantDelete(router);

    /* -------------------------------------------------------------------- */
    /*  HTTP API Gateway                                                     */
    /* -------------------------------------------------------------------- */

    const api = new HttpApi(this, "AssetsPdsApi", {
      apiName: "aithos-assets-pds-dev",
      description: "Aithos assets sub-protocol PDS — dev API",
      corsPreflight: {
        allowOrigins: ["*"],
        allowMethods: [CorsHttpMethod.POST, CorsHttpMethod.GET, CorsHttpMethod.OPTIONS],
        allowHeaders: ["content-type", "authorization"],
        maxAge: Duration.hours(1),
      },
    });

    const integration = new HttpLambdaIntegration(
      "RouterIntegration",
      router,
    );

    api.addRoutes({
      path: "/mcp/primitives/read",
      methods: [HttpMethod.POST],
      integration,
    });
    api.addRoutes({
      path: "/mcp/primitives/write",
      methods: [HttpMethod.POST],
      integration,
    });
    api.addRoutes({
      path: "/healthz",
      methods: [HttpMethod.GET],
      integration,
    });

    /* -------------------------------------------------------------------- */
    /*  CloudFront — public asset distribution                               */
    /* -------------------------------------------------------------------- */

    // Strict security headers for public asset delivery.
    const publicAssetResponseHeaders = new ResponseHeadersPolicy(
      this,
      "PublicAssetResponseHeaders",
      {
        responseHeadersPolicyName: "aithos-assets-public-headers-dev",
        comment:
          "Security headers for public asset delivery — no sniff, attachment disposition, strict referrer.",
        securityHeadersBehavior: {
          contentTypeOptions: { override: true },
          frameOptions: {
            frameOption: HeadersFrameOption.DENY,
            override: true,
          },
          referrerPolicy: {
            referrerPolicy: HeadersReferrerPolicy.NO_REFERRER,
            override: true,
          },
        },
        // Additional Content-Disposition handled per-object via Metadata
        // at upload time (see lambda/handlers/uploads.ts).
      },
    );

    const distribution = new Distribution(this, "PublicAssetsCDN", {
      comment: "Aithos public assets CDN — dev",
      defaultBehavior: {
        origin: S3BucketOrigin.withOriginAccessControl(assetsBucket),
        viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: AllowedMethods.ALLOW_GET_HEAD,
        cachedMethods: CachedMethods.CACHE_GET_HEAD,
        cachePolicy: CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: publicAssetResponseHeaders,
        compress: true,
      },
      enabled: true,
      // Limit to North America + Europe for v0.1; expand later if needed.
      // No explicit priceClass set — uses CloudFront's default (PriceClass_All).
    });

    /* -------------------------------------------------------------------- */
    /*  Outputs                                                              */
    /* -------------------------------------------------------------------- */

    new CfnOutput(this, "AssetsPdsApiUrl", {
      value: api.apiEndpoint,
      description: "Base URL for the Aithos assets PDS API",
      exportName: "AithosAssetsPdsApiUrl",
    });

    new CfnOutput(this, "AssetsBucketName", {
      value: assetsBucket.bucketName,
      description: "S3 bucket holding asset bytes",
    });

    new CfnOutput(this, "AssetsTableName", {
      value: assetsTable.tableName,
      description: "DynamoDB table holding asset metadata",
    });

    new CfnOutput(this, "PublicAssetsCDNDomain", {
      value: distribution.distributionDomainName,
      description: "CloudFront domain for serving public assets",
      exportName: "AithosAssetsPublicCDN",
    });

    new CfnOutput(this, "PublicAssetsCDNDistributionId", {
      value: distribution.distributionId,
      description: "CloudFront distribution ID (for invalidations)",
    });

    new CfnOutput(this, "RouterFnArn", {
      value: router.functionArn,
      description: "ARN of the router Lambda",
    });
  }
}
