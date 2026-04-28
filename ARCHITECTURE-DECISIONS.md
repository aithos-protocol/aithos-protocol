# Architecture Decisions — Aithos Protocol

> **Document de référence.** Ce fichier capture les décisions architecturales et stratégiques
> majeures prises sur le projet Aithos. Son objectif est d'éviter de re-débattre de sujets déjà
> tranchés, et de donner à tout nouveau contributeur (ou à nous-mêmes dans six mois) un contexte
> suffisant pour comprendre pourquoi les choses sont ce qu'elles sont.
>
> Format léger — pas d'outil ADR formel, un fichier unique mis à jour au fil des sessions.

---

## ADR-0001 — Architecture de délégation : Modèle B

**Date :** 2026-04-24  
**Statut :** Accepté

### Décision

L'Ethos d'un utilisateur vit exclusivement sur `aithos.be` (ou tout hôte compatible avec le
protocole). Les extensions de navigateur (Gmail, LinkedIn, X, Meta, Discord…) sont des
**délégués purs** : elles ne stockent pas l'Ethos, elles communiquent avec l'hôte via des
mandats signés pour chaque action.

### Contexte

Deux modèles étaient à l'étude :

- **Modèle A** : L'Ethos est stocké localement dans l'extension. Simple à bootstrapper, mais
  fragile (état lié à un navigateur, sync complexe, surface d'attaque locale).
- **Modèle B** : L'Ethos vit sur l'hôte, les extensions sont de simples délégués. Plus robuste,
  un seul point de vérité, cohérence garantie entre toutes les extensions.

### Conséquences

- `MAIL-ROADMAP §M2` doit être relu à la lumière du Modèle B (les extensions ne "possèdent" pas
  l'Ethos, elles demandent des mandats à l'hôte).
- Le protocole de mandats (§04) et de transport (§06) est le contrat central entre extension et
  hôte.
- Toute future extension (LinkedIn, X, etc.) respecte ce même contrat : pas de fork de logique
  Ethos dans le client.

---

## ADR-0002 — Stratégie d'écosystème : une extension par plateforme

**Date :** 2026-04-24  
**Statut :** Accepté

### Décision

Une extension Chrome distincte par plateforme cible (Gmail, LinkedIn, X, Meta, Discord…),
plutôt qu'une extension "universelle" qui tente de s'adapter au contexte actif.

### Raisonnement

- Chaque plateforme a une surface DOM / API spécifique. Une extension monolithique devient
  ingérable rapidement.
- Des extensions dédiées peuvent être publiées et auditées séparément sur le Chrome Web Store.
- L'utilisateur installe uniquement ce dont il a besoin — principe de moindre emprise.
- Le packaging `@aithos/extension-kit` fournit les primitives communes (keystore, messaging,
  OAuth wrapper) ; chaque extension les consomme sans dupliquer la logique protocolaire.

---

## ADR-0003 — Deux packages publics dans `aithos-protocol`

**Date :** 2026-04-24  
**Statut :** Accepté

> **Révision licence (2026-04-28).** Pour `@aithos/protocol-core`, le CLI `aithos`,
> et `@aithos/mcp`, la licence effective est celle d’**ADR-0006** (BSL 1.1 → Apache 2.0
> au 2030-12-31). Le tableau et la note « protocol-core reste Apache 2.0 » dans cette
> section reflètent la décision du 2026-04-24 et sont conservés pour l’historique.

### Décision

Deux packages publics seront extraits du monorepo et publiés sur npm sous l'organisation
`@aithos/` dans le repo GitHub `aithos-protocol` :

| Package | Rôle | Licence |
|---|---|---|
| `@aithos/protocol-client` | Client fonctionnel haut niveau pour parler au host Aithos (auth, mandats, gamma, send) | **BSL 1.1** (voir ADR-0004) |
| `@aithos/extension-kit` | Kit de développement pour les extensions : keystore IndexedDB, messaging helpers, OAuth wrapper générique | **BSL 1.1** (voir ADR-0004) |

Note : `@aithos/protocol-core` (format wire, primitives cryptographiques) reste **Apache 2.0** —
c'est le format ouvert qui permet l'interopérabilité. Notre avantage commercial est un cran
plus haut, au niveau du client fonctionnel et de l'hébergement.

### Stratification de la licence

```
[protocol-core]  Apache 2.0  — format ouvert, interopérabilité maximale
[protocol-client] BSL 1.1    — client fonctionnel, restriction temporaire
[extension-kit]   BSL 1.1    — kit extensions, restriction temporaire
[aithos.be infra] Propriétaire — hôte, inférence, indexation, App Store
```

### Plan d'extraction (4 sessions estimées)

1. Créer `aithos-protocol/packages/protocol-client`, appliquer BSL, CI + publish npm.
2. Publier `@aithos/protocol-client@0.1.0`, brancher sur `aithos/mail/extension`.
3. Créer `aithos-protocol/packages/extension-kit`, scaffolder depuis `keystore.ts` + helpers.
4. Publier `@aithos/extension-kit@0.1.0`, mettre à jour les extensions consommatrices.

---

## ADR-0004 — Licence : Business Source License 1.1

**Date :** 2026-04-24  
**Statut :** Accepté

> **Révision (2026-04-28).** Les paramètres concrets (Licensor, Change Date, périmètre des
> packages) pour le code déjà dans ce dépôt sont ceux d’**ADR-0006**. Le texte ci-dessous
> reste la justification du choix BSL ; les dates et le nom du Licensor dans l’extrait
> paramétré ne sont plus à jour.

### Décision

Les packages `@aithos/protocol-client` et `@aithos/extension-kit` sont publiés sous
**Business Source License 1.1** avec les paramètres suivants :

```
Licensor:             innoestate / Aithos
Licensed Work:        @aithos/protocol-client, @aithos/extension-kit
Change Date:          2030-04-24
Change License:       Apache License 2.0
Additional Use Grant: You may use the Licensed Work in production for any
                      purpose, EXCEPT to provide a hosted or managed service
                      to third parties that competes with Aithos's hosted
                      platform.
```

Le texte complet paramétré se trouve dans le fichier `LICENSE` de chaque package concerné
(voir **ADR-0006** pour le périmètre actuel du monorepo).

### Pourquoi BSL plutôt qu'une autre licence ?

- **SSPL (MongoDB)** : rejetée explicitement par l'OSI comme "non open source". Red Hat, Debian,
  Fedora ont viré MongoDB de leurs dépôts. Ce n'est pas le signal qu'on veut envoyer.
- **ELv2 (Elastic)** : solide, mais plus jeune, moins de jurisprudence, moins consensuel.
- **BSL 1.1** : utilisée par MariaDB depuis 2010, CockroachDB depuis 2019, HashiCorp (Terraform)
  depuis 2023. Éprouvée juridiquement, comprise par les devs, acceptée par les entreprises.

### Ce que la BSL autorise concrètement

✅ Un développeur construit son extension Chrome / app mobile / CLI alternatif pour Aithos.  
✅ Une agence intègre Aithos dans un produit client final qu'elle vend.  
✅ Un indépendant lance son propre service pour vendre des tokens Aithos Mail.  
❌ AWS / Google / équivalent forke `@aithos/protocol-client` et lance "AWS Ethos Hosting"
   en concurrence directe de `api.aithos.be` — interdit pendant 4 ans.

### La clause de conversion automatique

Le **2030-04-24**, les packages basculent automatiquement en **Apache 2.0** sans aucune action
requise. Ce détail change le positionnement : Aithos n'est pas "un truc fermé qui fait semblant
d'être open". C'est "ouvert avec une restriction temporaire de concurrence, documentée,
qui disparaît automatiquement". Les développeurs sérieux lisent ce signal positivement.

### Réversibilité

- Chaque release peut ajuster sa propre licence (v0.x BSL, v1.0 ELv2 si on veut resserrer).
- La `Change Date` peut être avancée unilatéralement si la traction explose et qu'on veut
  capitaliser sur l'ouverture totale plus tôt.
- Impossible de "reculer" la date (engagement de bonne foi envers la communauté).

---

## ADR-0005 — Monétisation : hébergement, pas client

**Date :** 2026-04-24  
**Statut :** Accepté

### Décision

Le moat commercial d'Aithos est au niveau :
- **Hébergement** (`api.aithos.be`) — uptime, SLA, conformité RGPD
- **Inférence** — accès aux modèles, contexte long, personnalisation
- **Indexation** — historique, recherche sémantique dans le gamma store
- **App Store** — marketplace d'extensions tierces certifiées

Le client (`protocol-client`, `extension-kit`) est rendu public précisément parce que
**l'ouverture est une condition de la traction et de la crédibilité**. Un protocole fermé
n'attire pas les intégrateurs tiers, ne se fait pas auditer, et ne convainc pas les entreprises
de lui confier leurs données.

---

## ADR-0006 — BSL 1.1 sur les packages référence du monorepo

**Date :** 2026-04-28  
**Statut :** Accepté

### Décision

Les packages npm déjà présents dans `aithos-protocol` — **`@aithos/protocol-core`**,
**`aithos`** (CLI), et **`@aithos/mcp`** — sont publiés sous **Business Source License 1.1**
(**BSL 1.1**) avec les paramètres suivants :

```
Licensor:             Mathieu Colla
Licensed Work:        voir le fichier LICENSE de chaque package (description du périmètre)
Change Date:          2030-12-31
Change License:       Apache License, Version 2.0
Additional Use Grant: (texte intégral dans chaque LICENSE — restriction d'offre de
                      service d'hébergement / médiation d'Ethos pour des tiers)
```

La **spécification** (`spec/`, `SPEC.md`, `WHITEPAPER.md`) reste lisible et réutilisable
sous **CC BY 4.0** (voir `LICENSE` à la racine du dépôt) — le protocole documenté n’est pas
« fermé » au même titre que la référence logicielle.

### Contexte

Objectif : empêcher qu’un concurrent ne **monétise l’hébergement d’Ethos** (stockage,
synchronisation, exposition MCP/HTTP des identités et mandats pour le compte de tiers) en
forkant la référence, tout en conservant une **conversion automatique** vers Apache 2.0 à
échéance fixe (fin d’année civile 2030).

### Conséquences

- Les versions **déjà distribuées** sous Apache 2.0 restent sous cette licence pour quiconque
  a obtenu ces artefacts ; seules les **nouvelles releases** sont couvertes par la BSL.
- Les paquets `@aithos/protocol-client` et `@aithos/extension-kit` (ADR-0003) suivront la même
  BSL lors de leur création.
- **ADR-0003** et **ADR-0004** (qui plaçaient `protocol-core` en Apache 2.0) sont supplantés
  sur ce point par la présente décision ; les fichiers sont annotés en conséquence.

---

*Dernière mise à jour : 2026-04-28 — BSL sur protocol-core, CLI, MCP + spec en CC BY 4.0*
