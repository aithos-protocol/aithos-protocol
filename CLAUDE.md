# Notes Claude — `Aithos-protocol`

## ⚠️ Mount FUSE Math17 — workflow git contraint

Ce dépôt vit sur le drive Math17 dont le filesystem **interdit `unlink(2)`
depuis le sandbox Cowork**. Concrètement : un `git commit` direct depuis le
mount laisse un `.git/index.lock` résiduel qui bloque toute opération git
suivante.

→ **Lire impérativement `../CLAUDE.md`** (= `/Volumes/Math17/aithos/code/CLAUDE.md`)
avant tout commit. Le workflow autonome y est documenté.

**TL;DR** : commits depuis un `git clone --shared` dans `/tmp/<repo>-work`,
push vers `claude/<topic>` côté origin si la branche cible est checked out
côté Math17.

## Tests

`npm test` depuis `packages/protocol-core/` ou `packages/cli/`. Test runner :
`node --import tsx --test`. Tests écrits avec `node:test` + `node:assert`.

Pour `packages/data-crypto/` : pareil, `npm test` lance les 17 tests du
POC crypto + un benchmark via `npm run bench`.

Pour `packages/data-backend/` : pas de tests unit, ce sont des handlers
Lambda. Les tests E2E live vivent dans `test-e2e/` et hitent le déploiement
dev (`npm run cdk:deploy` puis `node test-e2e/*.mjs`).

## Sous-protocole `aithos.data.v0.1` (PDS)

Ajouté pendant la session du 14 mai 2026. Tout vit sous `spec/data/`
(spec normative) + `packages/data-crypto/` (POC) + `packages/data-backend/`
(reference AWS CDK). Le SDK consommateur (`@aithos/sdk@0.1.0-alpha.26+`)
ne dépend PAS de `packages/data-crypto/` — il a sa propre copie inline
des primitives, browser-compat. Voir la note de dette technique dans
`protocol-client/CLAUDE.md` pour la migration future vers un module
unifié.

Le PDS dev est déployé sur un compte AWS de dev (voir docs/internal/, non publié) :
- Stack `AithosDataPdsDev`
- API : endpoint API Gateway dev (URL dans la config d'environnement locale)
- 4 tables DDB (`aithos-data-pds-dev`, `…-nonces-dev`, `…-revocations-dev`,
  `…-gamma-dev`)
- `cdk destroy` depuis `packages/data-backend/` pour tout démanteler.
