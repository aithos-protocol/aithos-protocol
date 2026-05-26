# Deploy notes — AithosAssetsPdsDev

First deployment of the `@aithos/assets-backend` stack on AWS.

## Stack

| Field | Value |
|---|---|
| Stack name | `AithosAssetsPdsDev` |
| Region | `eu-west-3` (Paris) |
| Account | `446503126111` |
| Deployed at | `2026-05-26T05:54Z` |
| CloudFormation template hash | `96f9d4ee0d2474f6b1d69fbab4d1a126735aef27bc701da4cf67fb787381a835` |

## Outputs

| Key | Value |
|---|---|
| `AssetsPdsApiUrl` | `https://yfzex613w3.execute-api.eu-west-3.amazonaws.com` |
| `AssetsBucketName` | `aithos-assets-pds-dev-446503126111` |
| `AssetsTableName` | `aithos-assets-pds-dev` |
| `PublicAssetsCDNDomain` | `d3sc3ay3heqzig.cloudfront.net` |
| `PublicAssetsCDNDistributionId` | `E24NXU5DI2I1QI` |
| `RouterFnArn` | `arn:aws:lambda:eu-west-3:446503126111:function:aithos-assets-pds-router-dev` |

## Smoke tests passed

```
GET /healthz
→ HTTP 200
  {"ok":true,"protocol":"aithos.assets","version":"0.1.0",
   "authentication":"envelope required on /mcp/primitives/write..."}

POST aithos.assets.get_public_asset (anonyme, asset inexistant)
→ HTTP 404
  {"jsonrpc":"2.0","id":"test-1","error":{"code":-32020,"message":"asset not found"}}
```

## Resources created

- S3 bucket `aithos-assets-pds-dev-446503126111` (versioned, KMS, block-public-access)
- 4 DynamoDB tables : `aithos-assets-pds-dev` (+ 2 GSIs), `-nonces-dev`, `-gamma-dev`, `-uploads-dev`
- 1 Lambda function `aithos-assets-pds-router-dev` (Node 20 ARM64, 97 KB bundled)
- 1 HTTP API Gateway with 3 routes (`POST /mcp/primitives/{read,write}`, `GET /healthz`)
- 1 CloudFront distribution with Origin Access Control + security headers
- 2 IAM roles + 2 policies (Lambda execution + log retention)

## Side-channel deploy note

`cdk deploy` did not pick up AWS credentials from environment variables
in the Cowork sandbox. Workaround used: `cdk synth` to generate the
template + bundle the Lambda, then manual `aws s3 cp` of the assets to
the bootstrap bucket and `aws cloudformation create-stack` directly
against the uploaded template. This avoided the CDK CLI credential-
resolution issue while still using the exact synth output. Investigation
of the root cause and a proper fix is tracked separately.

## Next steps

- Wire `sdk.assets` to point at `https://yfzex613w3.execute-api.eu-west-3.amazonaws.com`
- Run the real E2E test suite (`packages/assets-backend/test-e2e/`) against this deployment
- Configure a CloudWatch alarm for unusual Lambda errors / DynamoDB throttling
- Document the manual deploy procedure as a fallback for CI before CDK CLI fix is available
