# Plan — `aithos.data.v0.1` (PDS sous-protocole)

Document de travail. Trace la cible, les jalons, et les décisions ouvertes pour
le sous-protocole de données opérationnelles owned par l'utilisateur, accessible
aux applications par mandat.

Ce plan accompagne la rédaction de la RFC dans `spec/data/`. Il n'est pas
normatif. Il vit en racine de repo pour servir de référence partagée entre
sessions et collaborateurs.

## 0 — Contexte et motivation

L'Ethos (chapitres 1–4 de la spec) porte ce qui décrit le sujet : sa voix, ses
préférences, son tarif, son contexte. Sections markdown, mutations lentes,
descriptif narratif.

Une `tier-2` de données existe en parallèle dans la vie numérique d'un sujet :
des **données opérationnelles structurées** — prospects, messages, événements,
documents. Schéma déclaré, mutations rapides, volume potentiellement élevé,
queries indexées attendues.

Forcer ce second tier dans le modèle Ethos casse trois propriétés :

- Coût d'écriture (chaque mutation publie une nouvelle édition signée + entrée
  gamma) prohibitif sur des records à haute fréquence.
- Absence de schéma normatif — les bodies markdown sont du parsing fragile.
- Pas d'index serveur — full scan + déchiffrement à chaque query.

`aithos.data.v0.1` introduit un sous-protocole dédié, qui réutilise les
primitives cryptographiques d'Aithos (sphere keys, mandates, AEAD per-unit,
gamma log) mais expose un modèle adapté aux records structurés indexables :
**Collections** de **Records**, avec hiérarchie de clés `sphere → CMK → DEK`
permettant l'autorisation d'applications en `O(1)`.

L'usage cible immédiat : `switchia` (qualification de prospects pour TPE/PME)
comme premier consommateur, suivi à terme d'applications tierces (mail,
calendrier, documents) lisant les mêmes collections sous mandat de l'user.

## 1 — Principes directeurs

**P1. Le user possède sa donnée.** Aucune application n'a un store séparé pour
des données opérationnelles d'un user Aithos. Toute donnée vit dans le PDS
sous l'identité de l'user. Une application accède via un mandat révocable.

**P2. Le serveur ne voit que ce qui doit fuiter pour fonctionner.** Les
payloads sont chiffrés client-side, AEAD per-record. Seules les métadonnées
explicitement marquées `indexable` dans le schéma fuitent au serveur, pour
permettre les queries indexées et la pagination native.

**P3. L'autorisation est en O(1).** Ajouter ou retirer un mandat sur une
collection entière ne demande pas N opérations sur N records. La hiérarchie
de clés (CMK par collection) y pourvoit.

**P4. Le protocole est portable.** Une collection peut être exportée comme
artefact signé `.data` (ZIP), réimporté tel quel sur une autre instance
Aithos sans dépendance d'infrastructure. L'utilisateur n'est jamais captif.

**P5. Les schémas standardisent l'interop.** Un schéma `aithos.<collection>.vN`
est versionné, publié, immuable une fois publié. Les apps qui se conforment
au même schéma lisent et écrivent la même donnée — c'est ce qui rend la
portabilité réelle plutôt que cosmétique.

**P6. La DX est le produit.** Le SDK expose une API à grain dev (`client.data
('contacts').list({ filter, limit })`) ; les concepts protocolaires (DID,
sphere keys, gamma, wraps) restent accessibles mais invisibles par défaut.

## 2 — Modèle de données (résumé)

```
User Aithos (subject_did)
└── Collection "contacts" (schema: aithos.contacts.v1)
    ├── CMK (Collection Master Key)
    │   ├── wrap pour owner sphere key (#data ou #public)
    │   ├── wrap pour switchia (mandate_01J…)
    │   └── wrap pour email-app (mandate_01K…)
    │
    └── Records
        ├── record_01J…
        │   ├── metadata_clear { name, email, status, tags, … }
        │   ├── DEK (wrapped pour CMK uniquement)
        │   └── payload_ciphertext (chiffré par DEK)
        ├── record_01K…
        └── …
```

- **Collection** : conteneur logique scopé à un schéma, possédant une CMK.
  Une user peut avoir N collections (`contacts`, `messages`, `calendar`, …).
- **Record** : unité de données conformante au schéma de la collection.
  Identifié par un ULID. Chiffré individuellement.
- **CMK** : clé symétrique 32 bytes, une par collection. Sert d'intermédiaire
  entre la sphere key de l'owner (qui la wrap) et les DEK des records
  (qu'elle wrap à son tour).
- **DEK** : clé symétrique 32 bytes, une par record. Chiffre le payload.

## 3 — Hiérarchie de clés (résumé)

Trois niveaux, chacun avec un rôle distinct :

1. **Sphere key de l'owner** — stable à l'échelle de la vie du user. Sert à
   wrapper la CMK pour l'owner lui-même. Convention : nouvelle sphere `#data`,
   ou réutilisation de `#circle` selon décision §RFC ch.2.
2. **CMK** — vivante à l'échelle de la collection. Rotation possible mais
   rare (révoque, hygiène). Sert d'index d'autorisation : qui détient un
   wrap de la CMK accède à toute la collection.
3. **DEK** — vivante à l'échelle du record. Rotation à chaque modification
   (ou conservée avec nonce renouvelé — décision §RFC ch.2). Wrappée pour
   la CMK uniquement, pas pour les apps individuelles.

Autorisation d'une nouvelle app = un seul wrap de la CMK pour le grantee du
mandate. Coût constant, indépendant du nombre de records.

## 4 — API publique cible (résumé)

```ts
const client = createAithosClient({ /* auth via mandate ou sphere key */ });

// Création de collection (owner-only)
const contacts = await client.data.createCollection({
  name: 'contacts',
  schema: 'aithos.contacts.v1',
});

// CRUD
const id = await contacts.insert({ name, email, status: 'lead' });
const page = await contacts.list({ filter: { status: 'lead' }, limit: 20 });
const prospect = await contacts.get(id);
await contacts.update(id, { status: 'won' });
await contacts.delete(id);

// Permissions
await contacts.authorize({ granteePubkey, scopes: ['read', 'write'] });
await contacts.revoke({ mandateId });
await contacts.rotateCMK();
```

Pagination cursor opaque. Mutations staged en mémoire si besoin (pattern
similaire à `sdk.ethos.me()`). Authentification via envelope signé avec
mandate, conforme au chapitre 11 du protocole Ethos.

## 5 — Jalons

| # | Jalon | Statut | Durée estimée |
|---|---|---|---|
| 1 | RFC `aithos.data.v0.1` (10 chapitres dans `spec/data/`) | en cours | 2–3 sem |
| 2 | POC crypto Node (`packages/data-crypto/`) | en attente | 1–2 sem |
| 3 | Backend MVP AWS (DDB + Lambda + API Gateway) | en attente | 4–5 sem |
| 4 | Extension SDK `sdk.data.*` | en attente | 3 sem |
| 5 | Schéma standard `aithos.contacts.v1` | en attente | 1 sem |
| 6 | Suite de tests E2E | en attente | 2 sem |
| 7 | Documentation publique + build in public | en parallèle | continu |

Total MVP : 3 à 4 mois de travail solo concentré.

### 5.1 — Jalon 1 (en cours) — RFC `aithos.data.v0.1`

Chapitres prévus dans `spec/data/` :

- `00-overview.md` — préambule, motivation, principes, terminologie
- `01-data-model.md` — Records, Collections, Schemas
- `02-key-hierarchy.md` — sphere → CMK → DEK, format normatif des wraps
- `03-schemas.md` — JSON Schema étendu avec annotations Aithos, versionnement
- `04-mandates.md` — scopes `data.<collection>.<scope>`, filtres optionnels
- `05-api-primitives.md` — toutes les RPC primitives sur read/write paths
- `06-pagination.md` — Page<T>, cursor, behavior avec mutations concurrentes
- `07-portability.md` — format d'export `.data`, processus d'import
- `08-audit.md` — extension du gamma log avec entries `data.*`
- `09-threat-model.md` — ce qui fuit, ce qui ne fuit pas, attaques considérées
- `10-open-questions.md` — décisions non tranchées en v0.1

Critère de fin : un dev tiers peut implémenter un client interopérable depuis
la seule lecture de la RFC.

### 5.2 — Jalon 2 — POC crypto Node

Package `packages/data-crypto/`, indépendant pour démarrer mais conçu pour
être absorbé dans `protocol-core` à terme.

Périmètre :

- Génération + wrap + unwrap CMK (X25519-HKDF-SHA256-AEAD)
- Génération DEK + encrypt/decrypt record avec AAD bindée `(subject_did,
  collection_id, record_id)`
- authorize_app (ajout wrap CMK pour un grantee pubkey)
- revoke_app (retrait wrap + option rotation CMK)
- Roundtrip complet (owner crée → app lit → owner update → app re-lit)
- Tests `node:test` + benchmark des opérations critiques

Hors périmètre : portabilité, gamma log, schémas validés, persistence.

### 5.3 — Jalons 3+ — voir RFC et plan ultérieur

## 6 — Décisions à trancher pendant la rédaction

Liste des questions de design qui apparaîtront dans les chapitres. Décisions
proposées en cours de rédaction, marquées `> Décision révisable` dans chaque
chapitre, agrégées finalement dans `10-open-questions.md`.

- **Sphere key utilisée pour wrapper la CMK pour l'owner.** Nouvelle `#data`
  ou réutilisation de `#circle` ?
- **Rotation DEK à chaque update record.** Obligatoire, recommandée, ou
  jamais ?
- **Rotation CMK au revoke d'une app.** Obligatoire ou optionnelle ?
- **Format des filtres dans les mandates partiels.** DSL simple ou JSON
  conditions ?
- **Pagination cursor.** Opaque DDB-style ou stable basé sur record_id ?
- **Format d'export.** ZIP avec arbre type `.ethos` ou JSONL streamable ?
- **Index serveur sur metadata.** Modèle de GSI DynamoDB ? Quels champs
  systématiquement indexés (created_at, modified_at) ?
- **Multi-CMK pour très grosses collections.** Sharding à partir de quel
  seuil ?
- **Gouvernance des schémas standards.** Process d'amendement après v0.1 ?

## 7 — Risques principaux

- **R1 — Spec trop en amont sans test.** Mitigé par jalon 2 qui prouve
  rapidement la crypto avant d'investir dans l'infra.
- **R2 — Faille de design révélée par le POC.** Probable et bienvenue —
  c'est précisément à ce stade qu'on veut la détecter. La RFC est `0.1`
  draft, amendable.
- **R3 — Coûts AWS.** Improbable à l'échelle MVP ; DDB + Lambda + API GW
  restent sous 10 $/mois pour quelques centaines d'users.
- **R4 — Perte de momentum.** Mitigé par alternance RFC ↔ code, et par build
  in public régulier pour énergie externe.
- **R5 — Pivot switchia prioritaire.** Le PDS peut être mis en pause sans
  casser ce qui aura été écrit ; la RFC reste valable.

## 8 — Critères de succès

À la fin du Jalon 6 (MVP complet), on doit pouvoir démontrer :

1. Un user crée une collection `contacts` et insère 100 prospects via le SDK.
2. Switchia (app tierce simulée) reçoit un mandate `data.contacts.read+write`
   de l'user, peut lister/lire/modifier les prospects.
3. Une seconde app (email-app simulée) reçoit un mandate du même user, peut
   lire les mêmes prospects sans qu'on ait dû re-chiffrer N records.
4. Révocation du mandate switchia : switchia ne peut plus lire les versions
   modifiées après révoque.
5. Export d'une collection dans un fichier `.data`, ré-import dans une autre
   instance, intégrité préservée.
6. Tous les tests E2E passent en CI.

Atteindre ces six critères = `aithos.data.v0.1` est prêt à devenir public et
à être consommé par le vrai switchia.
