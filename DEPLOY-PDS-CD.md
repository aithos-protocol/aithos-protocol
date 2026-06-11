# PDS continuous deploy (CDK + GitHub OIDC)

`.github/workflows/deploy-pds.yml` brings the PDS backends (data + assets) under
CI/CD — the CDK counterpart of `aithos-provider`'s Terraform `deploy-dev` /
`deploy-prod`. It ends the "manual `cdk deploy`" gap.

## Behaviour

- **push to `main`** touching `packages/{data-backend,assets-backend,pds-auth,protocol-core}/**`
  or the workflow itself → **auto-deploy DEV** (`cdk deploy --all -c env=dev` for
  both backends). `main` is Aithos-protocol's integration branch (the analogue of
  the provider's `develop`).
- **workflow_dispatch** → pick `env` (dev|prod) and `action` (diff|deploy).
  Defaults to `diff`. `prod` runs under the `production` GitHub Environment so
  required reviewers gate it (same as the provider's `deploy-prod`).

## One-time prerequisite (maintainer — AWS/IAM)

The IAM role is now defined as code in
`aithos-provider/platform/infra/terraform-ci-oidc` (resource
`aws_iam_role.pds_ci_deploy`, role name `aithos-pds-ci-deploy`) — a sibling of
the provider's own deploy role. That stack is applied MANUALLY (bootstrap, not
in CI), once per account:

```
# dev account
AWS_PROFILE=innoestate-aithos-dev terraform apply        # env=dev  -> trusts main ref + development env
# prod account (when ready)
AWS_PROFILE=innoestate-aithos     terraform apply -var env=prod   # trusts the production env only
```

Each apply outputs `pds_ci_deploy_role_arn`. Then, in the **aithos-protocol**
repo, set the role ARN as an **Environment-scoped variable** named
`AWS_PDS_DEPLOY_ROLE_ARN` (same pattern as the provider's AWS_DEPLOY_ROLE_ARN):

- GitHub → aithos-protocol → Settings → Environments → **development** →
  variable `AWS_PDS_DEPLOY_ROLE_ARN` = the DEV-account role ARN.
- … → Environments → **production** → variable `AWS_PDS_DEPLOY_ROLE_ARN` =
  the PROD-account role ARN.

(Create the `development` and `production` Environments in aithos-protocol if
they don't exist — the workflow references them; `production` should carry
required-reviewer protection, mirroring the provider.)

The role grants AdministratorAccess (same as the provider's deploy role); the
dev account is isolated, scope prod later if desired. It needs:

1. **Trust policy** — the GitHub OIDC provider, scoped to this repo + environment:
   ```json
   {
     "Effect": "Allow",
     "Principal": { "Federated": "arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com" },
     "Action": "sts:AssumeRoleWithWebIdentity",
     "Condition": {
       "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
       "StringLike": { "token.actions.githubusercontent.com:sub": "repo:aithos-protocol/aithos-protocol:environment:development" }
     }
   }
   ```
   Add a second statement (or a second role) for `:environment:production`.

2. **Permissions** — enough to `cdk deploy`: either the same permission set as the
   provider's `AWS_DEPLOY_ROLE_ARN`, or `sts:AssumeRole` on the CDK bootstrap
   roles (`cdk-*-deploy-role-*`, `cdk-*-file-publishing-role-*`, `cdk-*-cfn-exec-role-*`)
   in the target account + `cloudformation:*` on the PDS stacks. The dev account
   (139316821077) is isolated, so a broad role there is acceptable; scope prod.

3. **Accounts must be CDK-bootstrapped** (they are — manual deploys worked).

Reuse vs new role: the provider's `AWS_DEPLOY_ROLE_ARN` trust is almost certainly
scoped to `repo:aithos-provider/platform`, so it will NOT match this repo. Either
add a trust statement for `aithos-protocol/aithos-protocol`, or (cleaner) create a
dedicated role and set `AWS_PDS_DEPLOY_ROLE_ARN`.

## Merge order

Do NOT merge this workflow to `main` until `AWS_PDS_DEPLOY_ROLE_ARN` exists —
otherwise the first PDS-touching push to main would trigger `deploy-dev` and fail
at the credentials step (red CI, harmless but noisy). Sequence:
1. Create the role + repo variable.
2. Merge `claude/pds-cd`.
3. The next PDS push to main auto-deploys dev (or trigger it now via dispatch
   `env=dev action=deploy`).

## Prod caveat

Before the FIRST prod deploy, confirm the prod stack id in each `bin/app.ts`
matches the already-deployed prod stack (PLAN-MULTIENV Phase 0; current prod
hosts slpknok0md / yfzex613w3). A new stack id provisions a NEW execute-api
(outage). Until reconciled, use dispatch `env=prod action=diff` only.
