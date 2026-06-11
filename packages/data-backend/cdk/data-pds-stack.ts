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
import { StringParameter } from "aws-cdk-lib/aws-ssm";
import type { Construct } from "constructs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export type AithosEnv = "dev" | "staging" | "prod";

export interface AithosDataPdsStackProps extends StackProps {
  /** Deployment environment. Drives resource names, the public host and the
   * resolver URL. (Distinct from StackProps.env, which is the AWS
   * account/region.) */
  readonly envName: AithosEnv;
  /** Public domain for this env: prod → aithos.be, else <env>.aithos.be. */
  readonly domain: string;
}

export class AithosDataPdsStack extends Stack {
  constructor(scope: Construct, id: string, props: AithosDataPdsStackProps) {
    super(scope, id, props);

    const env = props.envName;
    const domain = props.domain;

    // Resource-name suffix. `-${env}` keeps dev names byte-identical to the
    // pre-multienv stack (`aithos-data-pds-dev`), so `cdk diff -c env=dev` is a
    // no-op. ⚠️ PROD: confirm the ACTUAL deployed resource + stack names
    // (PLAN-MULTIENV Phase 0, host slpknok0md) BEFORE any prod synth — a name
    // change forces a replacement (new execute-api = outage). Do not assume.
    const sfx = `-${env}`;
    // Public vanity host + Ethos resolver, derived from the env domain.
    // Shell-env overrides remain as an escape hatch (transition / preview).
    const publicHost = process.env.PDS_PUBLIC_HOST ?? `pds.${domain}`;
    const resolverUrl =
      process.env.ETHOS_RESOLVER_URL ?? `https://api.${domain}`;

    /* -------------------------------------------------------------------- */
    /*  DynamoDB — single-table design                                      */
    /* -------------------------------------------------------------------- */

    const table = new Table(this, "DataTable", {
      tableName: `aithos-data-pds${sfx}`,
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
      tableName: `aithos-data-pds-nonces${sfx}`,
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
      tableName: `aithos-data-pds-revocations${sfx}`,
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
      tableName: `aithos-data-pds-gamma${sfx}`,
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
      tableName: `aithos-data-pds-schemas${sfx}`,
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
      functionName: `aithos-data-pds-router${sfx}`,
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
        // Env surfaced on /healthz so callers (and the dev-isolation e2e) can
        // confirm which environment an origin actually serves.
        AITHOS_ENV: env,
        // Public vanity host fronting this PDS through CloudFront. Enables
        // dual-aud verification (vanity + execute-api origin) during the edge
        // migration — see lambda/router.ts buildExpectedAud. Derived from the
        // env domain (pds.<domain>); PDS_PUBLIC_HOST shell env overrides.
        PDS_PUBLIC_HOST: publicHost,
        // Ethos identity registry the resolver calls to fetch a real, root-
        // signed did.json for did:aithos subjects (so owner data envelopes can
        // sign under the dedicated #data sphere instead of #root). See
        // lambda/auth/did-resolver.ts. Derived from the env domain
        // (https://api.<domain>); ETHOS_RESOLVER_URL shell env overrides.
        ETHOS_RESOLVER_URL: resolverUrl,
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
      apiName: `aithos-data-pds${sfx}`,
      description: `Aithos data sub-protocol PDS — ${env} API`,
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

    // execute-api origin host (no scheme/path) — what CloudFront points its
    // origin at. Published to SSM per env so Terraform reads it instead of a
    // hardcoded host (PLAN-MULTIENV Phase 1/2; closes audit B1). Order matters:
    // CDK must run before `terraform plan` or the param won't exist yet.
    const originHost = `${api.apiId}.execute-api.${this.region}.amazonaws.com`;
    new StringParameter(this, "DataPdsOriginHost", {
      parameterName: `/aithos/${env}/data-pds/origin-host`,
      stringValue: originHost,
      description: `Origin host for the ${env} data PDS (consumed by Terraform CloudFront)`,
    });

    new CfnOutput(this, "DataPdsApiUrl", {
      value: api.apiEndpoint,
      description: "Base URL for the Aithos data PDS API",
      // Stable export name (exports are unique per account+region, and each env
      // is its own account) — unchanged so `cdk diff -c env=dev` stays a no-op.
      exportName: "AithosDataPdsApiUrl",
    });

    new CfnOutput(this, "DataPdsOriginHostOut", {
      value: originHost,
      description: "execute-api origin host (for the SSM/CloudFront seam)",
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
