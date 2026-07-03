# PLAN — Infra multi-environnement (dev / staging / prod)

> But : une infra propre, paramétrée par `env`, sans hostname codé en dur, où
> ajouter un environnement = un compte + un fichier tfvars + un flag CDK.
> Aucun changement de code n'est appliqué tant que ce plan n'est pas validé.

## Décisions validées

- **1 compte AWS par env** : dev = `139316821077`, staging = nouveau compte, prod = compte `innoestate-aithos`.
- **Domaines** : prod = `aithos.be`, dev = `dev.aithos.be`, staging = `staging.aithos.be`.
- **Couture CDK → Terraform** : le host execute-api transite par **SSM Parameter Store**, par env.
- **Ownership** : backends PDS (data + assets) = **CDK** (`Aithos-protocol`). Edge + registre + DNS + certs = **Terraform** (`aithos-provider`, branche `develop`).

## Conventions (source de vérité)

| Élément | Règle |
|---|---|
| `env` | `dev` \| `staging` \| `prod` |
| `domain(env)` | `prod → aithos.be` ; sinon `<env>.aithos.be` |
| Profil AWS | `prod → innoestate-aithos` ; `dev → innoestate-aithos-dev` ; `staging → innoestate-aithos-staging` |
| SSM (data) | `/aithos/<env>/data-pds/origin-host` |
| SSM (assets) | `/aithos/<env>/assets-pds/origin-host` |
| `PDS_PUBLIC_HOST` | `pds.<domain(env)>` (assets : `assets.<domain(env)>`) |
| `ETHOS_RESOLVER_URL` | `https://api.<domain(env)>` |

## Principes non négociables

1. **`env` est le seul levier** : il dérive noms, domaine, env-vars, SSM. Le compte vient du profil AWS au déploiement.
2. **Zéro hostname codé en dur** : Terraform lit l'origin depuis SSM.
3. **Prod = no-op** après refacto : valider par `cdk diff` / `terraform plan` AVANT tout apply prod.
4. **Ordre** : CDK **avant** Terraform (le paramètre SSM doit exister avant que TF le lise).

---

## Phase 0 — Filets de sécurité (avant de toucher au code)

- [ ] Confirmer où vit le PDS prod actuel (host `slpknok0md`) :
  ```bash
  AWS_PROFILE=innoestate-aithos     aws apigatewayv2 get-apis --region eu-west-3 \
    --query "Items[?ApiId=='slpknok0md'].[ApiId,Name]" --output text
  AWS_PROFILE=innoestate-aithos-dev aws apigatewayv2 get-apis --region eu-west-3 \
    --query "Items[?ApiId=='5m8aahggfc'].[ApiId,Name]" --output text
  ```
- [ ] **Noter le nom exact de la stack CloudFormation prod** du data PDS (pour ne PAS la renommer → éviter un remplacement = nouvelle execute-api = coupure).
- [ ] Noter les valeurs actuelles d'origin (`slpknok0md`, assets `yfzex613w3`) — référence pour le seed SSM prod.
- [ ] Committer l'état git courant (bumps en attente) sur des branches dédiées dans chaque repo.

---

## Phase 1 — `data-backend` (CDK) env-aware
**Repo : `Aithos-protocol/packages/data-backend`** (puis répéter à l'identique sur `assets-backend`).

- [ ] **`bin/app.ts`** : lire l'env du contexte, dériver le domaine, nommer la stack.
  ```ts
  const env = app.node.tryGetContext("env") ?? "dev";        // dev|staging|prod
  const domain = env === "prod" ? "aithos.be" : `${env}.aithos.be`;
  new AithosDataPdsStack(app, stackName(env), { env, domain, ...});
  ```
  > ⚠️ **Nom de stack** : pour **prod**, reprendre le nom EXACT relevé en Phase 0 (sinon remplacement). Pour dev/staging (jetables), `AithosDataPds-<env>` est OK.

- [ ] **`cdk/data-pds-stack.ts`** :
  - Props `{ env, domain }`.
  - Suffixer les noms de tables/Lambda par `env` (retirer le `-dev` codé en dur).
  - `PDS_PUBLIC_HOST = "pds." + domain` ; `ETHOS_RESOLVER_URL = "https://api." + domain` (retirer les défauts prod ; garder l'override shell optionnel en secours).
  - **Publier le host dans SSM** + output :
    ```ts
    new ssm.StringParameter(this, "DataPdsOriginHost", {
      parameterName: `/aithos/${env}/data-pds/origin-host`,
      stringValue: `${api.apiId}.execute-api.${this.region}.amazonaws.com`,
    });
    new CfnOutput(this, "DataPdsOriginHost", { value: `${api.apiId}.execute-api.${this.region}.amazonaws.com` });
    ```
- [ ] **`assets-backend`** : idem (`PDS_PUBLIC_HOST = "assets." + domain`, SSM `/aithos/<env>/assets-pds/origin-host`).
- [ ] **Vérifs** : `cdk synth -c env=dev` puis `-c env=prod` ; `cdk diff` prod ≈ no-op (hormis l'ajout du paramètre SSM).
- [ ] **Retirer le pansement** : l'edit actuel (`data-pds-stack.ts` défauts `pds.dev.aithos.be`) est remplacé par la version dérivée de `domain`.

---

## Phase 2 — Terraform : couture SSM
**Repo : `aithos-provider/platform/infra/terraform-runtime`**

- [ ] **`cloudfront-pds.tf`** : remplacer les variables `*_origin_host` (défaut codé en dur) par une lecture SSM par env :
  ```hcl
  data "aws_ssm_parameter" "data_pds_host"   { name = "/aithos/${var.env}/data-pds/origin-host" }
  data "aws_ssm_parameter" "assets_pds_host" { name = "/aithos/${var.env}/assets-pds/origin-host" }
  # origin { domain_name = data.aws_ssm_parameter.data_pds_host.value ... }
  ```
  Garder une variable d'override optionnelle (fallback de secours).
- [ ] Vérifier que le `state_bucket` / backend pointe bien le compte de l'env (pas de fuite dev↔prod).

---

## Phase 3 — tfvars par env
**Repo : `aithos-provider/platform/infra/{terraform-runtime,terraform-web,terraform-dev-dns}`**

- [ ] Créer `envs/dev.tfvars`, `envs/staging.tfvars`, `envs/prod.tfvars` :
  ```hcl
  env             = "dev"
  domain          = "dev.aithos.be"
  aws_profile     = "innoestate-aithos-dev"
  state_bucket    = "innoestate-aithos-platform-tfstate-dev"
  certs_state_key = "dev-dns/terraform.tfstate"
  enable_cur      = false
  ```
- [ ] Standardiser : `terraform apply -var-file=envs/<env>.tfvars` (option : Makefile `make plan ENV=dev`).

---

## Phase 4 — Dérouler DEV de bout en bout

- [ ] `AWS_PROFILE=innoestate-aithos-dev cdk deploy -c env=dev` (data + assets) → remplit le SSM dev.
- [ ] `terraform apply -var-file=envs/dev.tfvars` (terraform-runtime) → CloudFront `pds.dev` repointé sur l'origin dev via SSM.
- [ ] Re-test app sur `pds.dev.aithos.be` : `register_schema` / `list_collections` → `aud` OK, puis résolution `#data` via `api.dev`.
- [ ] Vérifier que l'identité + `#data` sont publiés sur `api.dev` (self-heal SDK, `auth.apiBaseUrl = api.dev.aithos.be`).
- [ ] Supprimer la stack CDK orpheline si renommage (`cdk destroy` de l'ancienne `AithosDataPdsDev`).

---

## Phase 5 — PROD (sans risque) puis STAGING

**Prod** — l'objectif est un changement quasi nul :
- [ ] **Seed SSM prod** avec la valeur ACTUELLE pour que TF reste no-op :
  ```bash
  AWS_PROFILE=innoestate-aithos aws ssm put-parameter --region eu-west-3 \
    --name /aithos/prod/data-pds/origin-host --type String \
    --value slpknok0md.execute-api.eu-west-3.amazonaws.com --overwrite
  # idem assets : yfzex613w3...
  ```
  (ou : `cdk deploy -c env=prod` d'abord, qui écrit le SSM — au choix, mais seed manuel = plus sûr en transition.)
- [ ] `cdk diff -c env=prod` puis `terraform plan -var-file=envs/prod.tfvars` → **vérifier que c'est vide** avant tout apply.
- [ ] Appliquer.

**Staging** :
- [ ] Créer le compte + profil `innoestate-aithos-staging`, `cdk bootstrap`.
- [ ] `cdk deploy -c env=staging` ; DNS staging ; `terraform apply -var-file=envs/staging.tfvars`.

---

## Points de vigilance

- **Renommage de stack = remplacement** (nouvelle execute-api). OK en dev/staging, **interdit en prod** sans plan : garder le nom prod stable (Phase 0).
- **Ordre CDK→TF** : si le paramètre SSM n'existe pas, `terraform plan` échoue (`ParameterNotFound`). Toujours CDK d'abord (ou seed manuel).
- **Cross-account éliminé** : chaque CloudFront pointe l'execute-api de SON compte. Fini le `pds.dev` → PDS prod.
- **assets-backend** : ne pas l'oublier (même patron que data).
- **`name_suffix` prod = ""** doit rester inchangé côté Terraform (no-op prod).

## Rollback

Chaque phase est réversible : fallback `var` d'override côté TF, redeploy de l'ancienne config côté CDK, SSM = simple valeur écrasable.
