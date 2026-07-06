# Mandated Intent Envelope

**Version:** 0.1.0 (draft) · **Status:** design spec (session 2026-07-06 — trust model révisé : main **bête**, signature = **ancre d'audit** ; la re-vérification par l'aval devient optionnelle §4.4).
**Depends on:** §1 Identity, §3 Ethos/spheres, §4 Mandates (scopes, `section_scope`), §5 Signing (`signEnvelopeWithMandate` / `verifyEnvelope`, `SignedEnvelope`), §10 Gamma, §13 Mandated Container Runtime.

> Le pattern général derrière l'intégration browser-agent — mais qui n'est **pas** spécifique à browser-agent. Il répond à : *comment un agent non-fiable peut-il causer des effets au nom de l'owner sans jamais pouvoir en falsifier l'intention ?*

## 1. L'invariant

Un agent dans la cage (§13) est **non-fiable** (buggé, prompt-injecté, adverse). Il doit pouvoir **causer** des effets au nom de l'owner, mais ne doit **jamais** pouvoir en **forger** l'intention.

L'invariant, en une phrase :

> **Tout ce que l'agent fait franchir la frontière de la cage est la composition de deux parts : (a) du contenu ancré dans l'Ethos, signé par l'owner — le « quoi » — que l'agent ne peut PAS modifier ; et (b) des paramètres fournis par l'agent, admis uniquement dans les emplacements que le contenu signé déclare. Le gateway lie les deux et signe une seule enveloppe attribuée au mandat.**

L'agent ne fabrique jamais d'autorité : il **remplit des trous déclarés**. La source de vérité est l'Ethos ; le notaire est le gateway ; l'agent n'a ni clé, ni catalogue, ni recette.

## 2. Terminologie

- **Contenu ancré** (*anchored content*, ou *capability*) — une unité signée, authored par l'owner, stockée dans l'Ethos (§3) comme une section. Immuable-par-signature. Exemple : une **action** navigateur, un gabarit de mail, une écriture de donnée.
- **Schéma de paramètres** — déclaré *dans* le contenu ancré : quels champs l'appelant peut remplir, leurs types, et leurs **contraintes** (ex. `montant ≤ 100`, `url ∈ domaine X`).
- **Intention** (*intent*) — un couple (référence de capability, paramètres) que l'agent souhaite invoquer.
- **Mandated Intent Envelope** — l'enveloppe signée qui lie (référence de capability, empreinte des paramètres, mandat), signée par la **clé déléguée** au gateway. C'est le `SignedEnvelope` de §5, appliqué aux effets aval.

## 3. Les deux parts

### 3.1 Contenu ancré (le « quoi », signé)
Une **section Ethos** (`{ id, title, body, tags?, gamma_ref }`, §3) où :
- `id` = l'identifiant de la capability (ex. `linkedin_post`) ;
- `body` = la **définition** : le corps exécutable (ex. la recette de gestes distillée) **et** le schéma de paramètres + contraintes ;
- `tags` inclut un marqueur (ex. `action`) ;
- la section est **signée** via le manifeste de zone (`ZoneSignature` : owner ou délégué, §3).

Le `section_scope` du mandat (§4.7′) sélectionne **quelles** sections un mandat couvre : c'est la granularité par capability (`mcp.browser.<id>`).

### 3.2 Paramètres agent (les « trous », libres mais bornés)
Des valeurs pour **les seuls slots déclarés** par 3.1. Leur liberté est elle-même **bornée par du signé** : le schéma et les contraintes vivent dans le contenu ancré. Un slot non déclaré n'existe pas ; une valeur hors-contrainte est refusée.

## 4. Modèle de confiance (qui fait quoi)

### 4.1 L'agent (cage, non-fiable, **sans clé** — §13.7.1)
L'agent NE PEUT PAS signer. Il émet uniquement `(capability_id, paramètres)` sous forme d'**appel de tool MCP** vers le gateway. Il ne voit, comme tools, que les capabilities que son mandat autorise (le gateway filtre — §13.6 G2).

### 4.2 Le gateway (le **notaire**, de confiance, détient la clé déléguée + le mandat)
Sur chaque appel, le gateway **DOIT** :
- **G1** — vérifier que le mandat est **vivant** (fenêtre + révocation fraîche, §13.6 G1) et que ses `scopes`/`section_scope` **couvrent** la capability ;
- **G2** — **résoudre** le contenu ancré depuis l'Ethos par son `id` (jamais depuis l'agent) ;
- **G3** — **valider** les paramètres agent contre le schéma + contraintes **signés** (3.1) ; **refuser** toute valeur hors-schéma ou hors-contrainte ;
- **G4** — **signer** une Mandated Intent Envelope : `signEnvelopeWithMandate({ method: capability_id, params: paramètres_validés, mandate, delegateKey })` → `SignedEnvelope` (§5), qui lie `method` + `params_hash` (`sha256` de `rfc8785(params)`) + `mandate` par la signature Ed25519 déléguée. C'est l'**ancre d'audit attribuée** (son `nonce` clé l'entrée gamma) — **pas** une précondition pour la main ;
- **G5** — enregistrer l'effet en **gamma** (§10) attribué au mandat, avec `capability_id`, `params_hash`, `nonce` d'enveloppe, et l'`id` de mission (§13.8), puis **dispatcher** `(capability_id, paramètres validés)` à la main sur le canal authentifié.

### 4.3 L'aval (la « main », ex. browser-agent) — un effecteur **bête**
L'aval est un **pur exécuteur**. Il fait confiance à **la frontière de la cage** (§13) et au **canal authentifié** (bearer aval détenu par le gateway, comparaison constant-time) : ce qui lui arrive vient du gateway, l'**unique** point d'enforcement. Il ne détient **aucune clé Aithos**, ne lit pas l'Ethos, et **ne re-vérifie rien**. Il exécute `(capability_id, paramètres validés)` et renvoie un **rapport typé** (`run_report` / `run_stopped`). Il garde en revanche toute son intelligence de *pilotage* (mouvement humain, ciblage sémantique) — « bête » qualifie l'absence de logique **Aithos/sécurité**, pas l'absence de savoir-faire navigateur.

> **Racine de confiance.** L'enforcement (G1–G3) vit au gateway ; la sécurité repose donc sur (i) l'intégrité de la cage/gateway et (ii) l'authenticité du canal gateway→main. Choix **assumé** : on troque la défense indépendante contre un *gateway compromis* contre une main strictement bête. Le modèle de menace de la cage vise le *runtime non-fiable* (l'esprit prompt-injecté), pas le gateway — petit, auditable, à nous. Le choix est **réversible** : une re-vérification par la main (`verifyEnvelope`) est purement **additive** (§4.4).

### 4.4 Aval vérifieur (optionnel)
Un aval qui **ne fait pas confiance** au gateway (autre machine, autre opérateur, frontière de confiance différente) **PEUT** vérifier l'enveloppe lui-même (`verifyEnvelope` : preuve déléguée + fenêtre/scope du mandat + `params_hash`). Le pattern le permet **sans changement** : l'enveloppe signée voyage déjà avec l'appel. C'est le cas d'un connecteur tiers — **pas** celui de la main browser-agent locale, qui est derrière la même frontière de confiance que le gateway.

## 5. L'enveloppe (réutilise §5, aucune crypto nouvelle)

Le `SignedEnvelope` existant (`"aithos-envelope": "0.1.0"`) porte déjà tout : `iss`, `aud`, `method` (= `capability_id`), `iat`/`exp`, `nonce`, `params_hash`, `mandate`, `proof` (Ed25519 délégué). Le pattern est **`signEnvelopeWithMandate` appliqué aux effets aval**, pas seulement aux écritures ethos. Les paramètres sont **liés par empreinte** (`params_hash`) : **n'importe quel vérifieur** — l'audit gamma (§8), ou un aval vérifieur optionnel (§4.4) — peut confirmer qu'ils correspondent exactement à ce que le gateway a validé et signé. Le `nonce` rend chaque enveloppe unique (anti-rejeu, et clé d'attribution en gamma).

## 6. Conformité (normatif)

1. L'agent **MUST NOT** fournir autre chose que des valeurs de paramètres déclarés ; le contenu ancré **MUST** provenir de l'Ethos, jamais de l'agent.
2. Le gateway **MUST** valider les paramètres contre le schéma/contraintes signés **avant** de signer, et **MUST** refuser hors-schéma/hors-contrainte.
3. Le gateway **MUST** signer l'enveloppe avec la clé déléguée nommée par le mandat ; l'effet **MUST** être attribué en gamma par le `nonce` de l'enveloppe.
4. Le canal gateway→aval **MUST** être authentifié (bearer, comparaison constant-time). Un aval **MAY** vérifier l'enveloppe lui-même (requis **seulement** s'il ne fait pas confiance au gateway — §4.4) ; s'il vérifie, il **MUST** refuser en cas d'échec.
5. Le schéma/contraintes de paramètres **sont** du contenu signé : le gateway **MUST NOT** signer ni transmettre des paramètres que le schéma signé n'autorise pas (G3). La main exécute des paramètres déjà bornés — elle n'a rien à re-valider.

## 7. Pourquoi c'est général (et pas un cas browser-agent)

`capability` ∈ { action navigateur, brouillon de mail, écriture de donnée, appel d'outil tiers, … }. **Même enveloppe, mêmes contrôles.** L'Ethos est l'**unique ancre d'authenticité** ; le gateway l'**unique notaire** ; l'aval un **exécuteur mince** (bête derrière un canal authentifié — ou vérifieur optionnel s'il ne fait pas confiance au gateway, §4.4). browser-agent n'est que la **première application** (annexe A). Ajouter un connecteur = ajouter des sections ancrées + un aval qui exécute — rien à réinventer.

## 8. Gamma / audit

Une entrée gamma par effet : `{ mandate_id, capability_id (+version), params_hash, mission_id, downstream, status }`. La traçabilité devient : *« qui a fait quoi, sous quelle autorité, avec quels paramètres (hashés), à partir de quelle capability signée »*.

---

## Annexe A — Application : browser-agent

- **Contenu ancré** = un *ActionFile* (goal + recette de gestes + schéma/contraintes de paramètres) authored + **signé** au studio → section Ethos taguée `action`, scope `mcp.browser.<id>` (famille `mcp.*`, sphères self/circle — pas public).
- **Gateway** : expose chaque action **en scope** comme tool MCP (`title` = goal, `inputSchema` = schéma de params). À l'appel → G1–G5. La **main garde son intelligence de pilotage** (ciblage sémantique role+name, mouvement humain) : le gateway lui envoie `(action_id, params validés)`, elle résout gestes + cibles via son `composite_runner` existant. L'expansion action→gestes n'est **pas** portée côté container.
- **Message WS `run_action`** (contrat, à câbler côté browser-agent — sa surface WS n'expose aujourd'hui que les primitives `navigate/click/type/scroll/html`) :
  ```json
  { "type": "run_action",
    "action_id": "inscription",
    "params":    { /* paramètres validés */ },
    "envelope":  { /* SignedEnvelope §5 — attribution ; la main bête l'ignore */ } }
  ```
  → browser-agent (**bête**, sur canal **bearer**) exécute `composite_runner.run(action_id, params)` et répond `{ "type":"run_report"|"run_stopped", "ok":…, … }`. **Aucune** vérification d'enveloppe côté main.
- **Référence exécutable du contrat** : `packages/mcp` — `httpActionDispatch` + le **mock hand** (`deploy/container/dev/mock-browser-agent.mjs`, qui lui *vérifie*, illustrant l'aval optionnel §4.4) matérialisent déjà le message ci-dessus ; la session browser-agent peut tester contre eux.
- **Perception** : niveaux `observe` (url / innerText ciblé / html / screenshot), gatés par `mcp.browser.observe`.

## Annexe B — Points ouverts (coordination browser-agent)

- **Transport `wsActionDispatch`** : câbler `run_action(action_id, params)` sur la surface WS de browser-agent (aujourd'hui primitives seules), et **fixer le mécanisme du bearer** sur le WS (sous-protocole `Sec-WebSocket-Protocol` ? query param ? premier message ?) — la `WebSocket` globale de Node ne pose pas d'en-tête `Authorization`. Tant que ce n'est pas figé, le transport de référence reste HTTP (`httpActionDispatch` + mock).
- **Langage de contraintes** de paramètres : comment une action signée déclare `montant ≤ 100`, `url ∈ domaine X` (le validateur v0 couvre déjà type/enum/required/min-max/longueur/pattern/items).
- **Nettoyage browser-agent** (session parallèle) : retirer le travail de vérification-de-signature prévu (D3.2), garder WS + bearer **durci**, garder vault/profil sur la machine. La main ne gagne **aucune** logique Aithos.
- **Note** : ce document (trust model §4) **remplace** le D3.2 « double signature » du `DESIGN-CONTAINER-TOPOLOGY.md` de browser-agent — décision session 2026-07-06 : main bête, signature = ancre d'audit.
