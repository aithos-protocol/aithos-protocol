// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * CDK app entry point — defines the Aithos data sub-protocol PDS stack.
 *
 * Usage:
 *   npm run cdk:synth     # generate CloudFormation template
 *   npm run cdk:diff      # show diff vs deployed stack
 *   npm run cdk:deploy    # deploy to AWS
 *   npm run cdk:destroy   # tear down (irreversible)
 *
 * Environment:
 *   AWS_REGION — defaults to eu-west-3 (Paris)
 *   AWS_ACCOUNT_ID — derived from STS get-caller-identity by CDK
 */

import { App, Tags } from "aws-cdk-lib";

import { AithosDataPdsStack, type AithosEnv } from "../cdk/data-pds-stack.js";

const app = new App();

// `env` context selects the whole environment: it derives the domain, resource
// names, env-vars and the SSM param. The AWS ACCOUNT comes from the deploy
// profile (CDK_DEFAULT_ACCOUNT), never hardcoded. Usage: `-c env=dev|prod`.
const deployEnv = (app.node.tryGetContext("env") as AithosEnv) ?? "dev";
const domain = deployEnv === "prod" ? "aithos.be" : `${deployEnv}.aithos.be`;

const awsEnv = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? "eu-west-3",
};

// Stack id. dev keeps its historical name (`AithosDataPdsDev`) so the existing
// dev stack updates in place (no replacement). ⚠️ PROD: set this to the EXACT
// name of the already-deployed prod stack (PLAN-MULTIENV Phase 0) before the
// first prod deploy — a new id provisions a NEW execute-api (outage).
const stackId = deployEnv === "dev" ? "AithosDataPdsDev" : `AithosDataPds-${deployEnv}`;

new AithosDataPdsStack(app, stackId, {
  env: awsEnv,
  envName: deployEnv,
  domain,
  description: `Aithos data sub-protocol PDS — ${deployEnv} environment. See spec/data/.`,
});

// Apply project-wide tags
Tags.of(app).add("Project", "aithos");
Tags.of(app).add("Component", "data-pds");
Tags.of(app).add("Environment", deployEnv);
Tags.of(app).add("ManagedBy", "cdk");
