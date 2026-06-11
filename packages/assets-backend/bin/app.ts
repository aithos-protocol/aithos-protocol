// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * CDK app entry point — defines the Aithos assets sub-protocol PDS
 * stack.
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

import { AithosAssetsPdsStack, type AithosEnv } from "../cdk/assets-pds-stack.js";

const app = new App();

// `env` context selects the whole environment (domain, names, env-vars, SSM).
// The AWS account comes from the deploy profile. Usage: `-c env=dev|prod`.
const deployEnv = (app.node.tryGetContext("env") as AithosEnv) ?? "dev";
const domain = deployEnv === "prod" ? "aithos.be" : `${deployEnv}.aithos.be`;

const awsEnv = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? "eu-west-3",
};

// Stack id. dev keeps its historical name (`AithosAssetsPdsDev`) so the dev
// stack updates in place. ⚠️ PROD: set this to the EXACT already-deployed prod
// stack name (PLAN-MULTIENV Phase 0) before the first prod deploy.
const stackId = deployEnv === "dev" ? "AithosAssetsPdsDev" : `AithosAssetsPds-${deployEnv}`;

new AithosAssetsPdsStack(app, stackId, {
  env: awsEnv,
  envName: deployEnv,
  domain,
  description: `Aithos assets sub-protocol PDS — ${deployEnv} environment. See spec/assets/.`,
});

// Apply project-wide tags
Tags.of(app).add("Project", "aithos");
Tags.of(app).add("Component", "assets-pds");
Tags.of(app).add("Environment", deployEnv);
Tags.of(app).add("ManagedBy", "cdk");
