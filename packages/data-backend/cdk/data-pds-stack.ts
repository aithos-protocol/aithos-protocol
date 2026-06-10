// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * AithosDataPdsStack — the AWS infrastructure for the Aithos data
 * sub-protocol PDS (Personal Data Server).
 *
 * Components:
 *   - DynamoDB table (single-table design)
 *       PK = subject_did               (partition key)
 *       SK = collection#record_id      (sort key; collection metadata sits at "<col>#")
 *       GSI1: PK = subject_did#collection, SK = metadata.modified_at
 *         (enables list_records filtered by collection, sorted by mtime)
 *
 *   - Lambda router (Node 20, esbuild-bundled)
 *       single function dispatches over JSON-RPC method name
 *
 *   - HTTP API Gateway (cheaper than REST, sufficient for our needs)
 *       routes: POST /mcp/primitives/read, POST /mcp/primitives/write
 *
 * Notes for v0.1 dev:
 *   - On-demand billing on the table — no capacity planning needed.
 *   - PITR enabled for recovery in case of accidental delete during dev.
 *   - removalPolicy=DESTROY so `cdk destroy` cleans up entirely (no
 *     orphan tables surviving teardown).
 *   - Lambda authorizer is intentionally absent in this iteration; the
 *     handler trusts the caller. Sub-jalon 3.2 wires the real envelope
 *     + mandate verification.
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
import type { Construct } from "constructs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class AithosDataPdsStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    /* -------------------------------------------------------------------- */
    /*  DynamoDB — single-table design                                      */
    /* -------------------------------------------------------------------- */

    const table = new Table(this, "DataTable", {
      tableName: "aithos-data-pds-dev",
      partitionKey: { name: "pk", type: AttributeType.STRING },
      sortKey: { name: "sk", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // GSI1: list records in a collection sorted by modified_at desc
    // PK = subject_did#collection
    // SK = metadata.modified_at  (ISO 8601 string, sorts chronologically)
    table.addGlobalSecondaryIndex({
      indexName: "gsi1_by_collection_mtime",
      partitionKey: { name: "gsi1pk", type: AttributeType.STRING },
      sortKey: { name: "gsi1sk", type: AttributeType.STRING },
      projectionType: ProjectionType.ALL,
    });

    /* -------------------------------------------------------------------- */
    /*  Replay-cache table (anti-replay for envelope nonces, spec §11.5)    */
    /* -------------------------------------------------------------------- */

    const nonceTable = new Table(this, "NonceTable", {
      tableName: "aithos-data-pds-nonces-dev",
      partitionKey: { name: "pk", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: "expires_at_epoch",
      removalPolicy: RemovalPolicy.DESTROY,
    });

    /* -------------------------------------------------------------------- */
    /*  Revocations table (mandate revocations, spec §4.6)                  */
    /* -------------------------------------------------------------------- */

    const revocationsTable = new Table(this, "RevocationsTable", {
      tableName: "aithos-data-pds-revocations-dev",
      partitionKey: { name: "mandate_id", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    /* -------------------------------------------------------------------- */
    /*  Gamma log table (audit chain, spec/data §8)                         */
    /* -------------------------------------------------------------------- */
    //
    // PK = subject_did (one chain per subject; data and Ethos gamma
    //                   share the same logical chain per spec §8.2 but
    //                   live in separate tables here for clarity)
    // SK = entry_id   (ULID, sorts chronologically)
    //
    // Optional GSI for `latest head per subject` is computed by the
    // store's `getHead()` doing a Query(PK=subject, ScanIndexForward=false,
    // Limit=1). No extra index needed.

    const gammaTable = new Table(this, "GammaTable", {
      tableName: "aithos-data-pds-gamma-dev",
      partitionKey: { name: "subject_did", type: AttributeType.STRING },
      sortKey: { name: "entry_id", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    /* -------------------------------------------------------------------- */
    /*  Schemas table (A2b — per-owner vendor schema self-registration,     */
    /*  spec/data §3.7.4)                                                    */
    /* -------------------------------------------------------------------- */
    //
    // PK = owner_did             (one partition per subject)
    // SK = schema_id             (e.g. "aithos.x.linkedone.post.v1")
    //
    // Stores the immutable JSON Schema 2020-12 document published by the
    // owner for vendor schemas (`aithos.x.<vendor>.<name>.v<N>`). The
    // record handlers fall back to this table when resolving a schema
    // that isn't in the bundled core REGISTRY. Per spec §3.5 a schema
    // doc is immutable once published — the handler enforces this via
    // doc_hash equality check, returning AITHOS_DATA_SCHEMA_IMMUTABLE
    // (-32082) on conflict.

    const schemasTable = new Table(this, "SchemasTable", {
      tableName: "aithos-data-pds-schemas-dev",
      partitionKey: { name: "pk", type: AttributeType.STRING },
      sortKey: { name: "sk", type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      pointInTimeRecovery: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    /* -------------------------------------------------------------------- */
    /*  Lambda router                                                        */
    /* -------------------------------------------------------------------- */

    const router = new NodejsFunction(this, "RouterFn", {
      functionName: "aithos-data-pds-router-dev",
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
        DATA_TABLE_NAME: table.tableName,
        NONCE_TABLE_NAME: nonceTable.tableName,
        REVOCATIONS_TABLE_NAME: revocationsTable.tableName,
        GAMMA_TABLE_NAME: gammaTable.tableName,
        SCHEMAS_TABLE_NAME: schemasTable.tableName,
        AITHOS_DATA_PROTOCOL_VERSION: "0.1.0",
        // Public vanity host fronting this PDS through CloudFront. Enables
        // dual-aud verification (vanity + execute-api origin) during the edge
        // migration — see lambda/router.ts buildExpectedAud. Override via the
        // PDS_PUBLIC_HOST shell env at synth time if the domain differs.
        PDS_PUBLIC_HOST: process.env.PDS_PUBLIC_HOST ?? "pds.dev.aithos.be",
        // Ethos identity registry the resolver calls to fetch a real, root-
        // signed did.json for did:aithos subjects (so owner data envelopes can
        // sign under the dedicated #data sphere instead of #root). See
        // lambda/auth/did-resolver.ts. Override via ETHOS_RESOLVER_URL at synth.
        ETHOS_RESOLVER_URL:
          process.env.ETHOS_RESOLVER_URL ?? "https://api.dev.aithos.be",
      },
      bundling: {
        target: "node20",
        format: OutputFormat.ESM,
        mainFields: ["module", "main"],
        externalModules: ["@aws-sdk/*"],
        // ESM workaround: emit a require() shim so esbuild-bundled
        // CommonJS deps still resolve at runtime.
        banner:
          "import { createRequire } from 'module'; const require = createRequire(import.meta.url);",
      },
    });

    table.grantReadWriteData(router);
    nonceTable.grantReadWriteData(router);
    revocationsTable.grantReadWriteData(router);
    gammaTable.grantReadWriteData(router);
    schemasTable.grantReadWriteData(router);

    /* -------------------------------------------------------------------- */
    /*  HTTP API Gateway                                                     */
    /* -------------------------------------------------------------------- */

    const api = new HttpApi(this, "DataPdsApi", {
      apiName: "aithos-data-pds-dev",
      description: "Aithos data sub-protocol PDS — dev API",
      corsPreflight: {
        allowOrigins: ["*"],
        allowMethods: [CorsHttpMethod.POST, CorsHttpMethod.OPTIONS],
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
    /*  Outputs                                                              */
    /* -------------------------------------------------------------------- */

    new CfnOutput(this, "DataPdsApiUrl", {
      value: api.apiEndpoint,
      description: "Base URL for the Aithos data PDS API",
      exportName: "AithosDataPdsApiUrl",
    });

    new CfnOutput(this, "DataTableName", {
      value: table.tableName,
      description: "DynamoDB table name for the data PDS",
    });

    new CfnOutput(this, "SchemasTableName", {
      value: schemasTable.tableName,
      description: "DynamoDB table name for vendor schema self-registration (A2b)",
    });

    new CfnOutput(this, "RouterFnArn", {
      value: router.functionArn,
      description: "ARN of the router Lambda",
    });
  }
}
