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

import { AithosAssetsPdsStack } from "../cdk/assets-pds-stack.js";

const app = new App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? "eu-west-3",
};

new AithosAssetsPdsStack(app, "AithosAssetsPdsDev", {
  env,
  description:
    "Aithos assets sub-protocol PDS — dev environment. See spec/assets/.",
});

// Apply project-wide tags
Tags.of(app).add("Project", "aithos");
Tags.of(app).add("Component", "assets-pds");
Tags.of(app).add("Environment", "dev");
Tags.of(app).add("ManagedBy", "cdk");
