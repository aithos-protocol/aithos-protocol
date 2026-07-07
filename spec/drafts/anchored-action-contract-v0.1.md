# Le Contrat d'Action Ancrée (K3) + Multi-grant (K0)

**Version :** 0.2.0 (draft) · **Statut :** design, cadré en session 2026-07-06.
**Dépend de :** §3 Ethos/sections, §4 Mandats, §5 Signing, `spec/drafts/mandated-intent-envelope-v0.1.md` (l'enveloppe + la « main bête »).

> Comment une **action dynamique**, définie comme une **section signée de l'Ethos**,
> devient un **outil MCP** que l'agent en cage peut utiliser, sans que le gardien
> ni la main ne connaissent le domaine l'un de l'autre — et comment un **container
> agentique** compose **plusieurs clés et mandats** sur plusieurs Ethos. C'est le
> maillon qui transforme « une démo qui marche » en **plateforme d'agents
> composables**.

---

## 1. Les trois rôles

- **L'Ethos définit.** Une action est une **section** signée, taguée `action`,
  dont le corps est un *document Action* typé (§3). Source de vérité,
  immuable-par-signature, versionnée, zonée.
- **Le gardien projette + gouverne + route.** Il tient une **liste de grants**
  (§6), lit les sections `action` de chaque Ethos autorisé, les projette en tools
  MCP, les borne au mandat, valide les paramètres, signe l'ancre d'audit, et route
  l'exécution vers la bonne **main**. C'est *lui*, « l'outil de type MCP qui
  comprend des actions dynamiques ».
- **La main exécute.** Bête : elle reçoit `(recette, params)`, rejoue, renvoie un
  rapport. Aucune connaissance d'Aithos. browser-agent en est la référence.

Le principe qui rend le tout **ouvert et facile** : **l'opacité de la recette.**
Le gardien ne comprend pas la recette ; il la transmet. La main ne comprend que
sa recette.

---

## 2. Deux publics, deux descriptions

- **Le manifeste** — pour le **LLM** (l'agent). *À quoi ça sert, comment
  l'utiliser.* Seule chose que l'agent voit. C'est la déclaration de tool MCP :
  `{ name, description, inputSchema }`.
- **La recette** — pour la **main**. *Comment* exécuter. **Opaque** au gardien ET
  au LLM.

Le manifeste fait partie du corps signé → **la description que voit le LLM est
écrite par l'owner et infalsifiable.**

---

## 3. Contrat A — le document Action (corps de la section)

```jsonc
{
  "aithos-action": "0.1",
  "service": "browser",                 // route vers la main + namespace de tool
  "name": "read_post",                  // id stable → nom du tool

  "manifest": {                         // POUR LE LLM (= déclaration MCP, signée)
    "description": "Lit un post et renvoie son texte. À utiliser quand …",
    "params_schema": {                  // JSON Schema — le gardien valide ÇA
      "type": "object",
      "properties": {
        "url": { "type": "string", "description": "L'URL du post à lire" }
      },
      "required": ["url"],
      "additionalProperties": false
    },
    "returns": "Le texte du post."       // indice de sortie, optionnel
  },

  "recipe": { … }                        // POUR LA MAIN — opaque au gardien + LLM
}
```

- Le gardien lit `service`, `name`, `manifest`. Il **ne parse pas** `recipe`.
- `params_schema` **DOIT** porter une `description` par champ (le LLM en dépend).
- Le format de `recipe` est **propre au service** (gestes navigateur, template
  d'API, script…).

---

## 4. Contrat B — protocole d'exécution (gardien ↔ main)

```jsonc
// requête (gardien → main)
{ "type": "run_action",
  "recipe": { … },          // opaque, la copie READ-ONLY du gardien
  "params": { … } }         // params validés par le gardien
  // "envelope": { … }      // v2 : ancre d'audit, si un aval veut vérifier

// réponse (main → gardien)
{ "type": "run_report",  "ok": true,  … }
{ "type": "run_stopped", "ok": false, "step", "phase", "reason" }
```

- **Transport au choix** : WS (browser-agent), HTTP, MCP — injectable côté gardien.
- **Une main n'a besoin QUE de ça** + comprendre sa recette. C'est le critère
  « créer un outil facilement ».

---

## 5. Contrat C — routage service → main

```jsonc
// carte de config du CONTAINER (pas de l'Ethos)
{ "browser":  { "url": "ws://host.docker.internal:8765", "transport": "ws", "bearer_env": "AITHOS_ACTIONS_BEARER" },
  "monoutil": { "url": "wss://main.exemple.com",         "transport": "ws" },
  "gmail":    { "url": "https://…/mcp",                  "transport": "mcp" } }
```

- **Emplacement** (local/distant), **transport** (ws/http/mcp), **identité de
  l'outil** : trois axes indépendants. La main est un **endpoint configurable.**
- **La carte vit dans le container, pas dans l'Ethos.** L'action signée dit
  seulement « j'ai besoin du service `browser` » ; le container dit « `browser`
  est à telle URL ». → la **même action signée** tourne contre une main locale ou
  distante ; seule la carte change.
- Le `service` du document sélectionne l'entrée. Service absent de la carte →
  action **non exposée** (fail-closed). Le `service` sert aussi de namespace du
  nom de tool.

---

## 6. Multi-grant — plusieurs clés et mandats (fondation, K0)

Un container agentique compose **plusieurs Ethos**. On pose ça en **fondation**,
avant tout le reste : sinon « lire *l'*Ethos » se recâble douloureusement en
« lire *chaque* Ethos autorisé ».

**Le container tient une *liste de grants*.** Chaque grant = un accès à **un**
Ethos, et c'est l'un de deux :

- **grant owner** : une clé d'owner → accès **complet** à cet Ethos ;
- **grant délégué** : un mandat **+ sa clé d'agent** → accès **scopé** à l'Ethos
  de l'émetteur. *C'est le pack que l'app produit* (le SDK mint sa propre clé de
  délégué par mandat → chaque mandat arrive avec sa clé).

Le gardien **itère les grants** : pour chacun, il lit *son* Ethos avec *sa* clé,
fédère ce qu'il y trouve (actions → tools, connecteurs, lecture/écriture de
données), **signe avec la clé de ce grant**, et **attribue** chaque effet à *son*
mandat (gamma). L'agent voit **l'union**. Exemple : un grant sur l'Ethos
d'**actions** (les tools d'action) + un grant sur l'Ethos de **données**
(lecture/écriture) — émetteurs distincts, sans collision ni recopie.

**Décisions v1 :**

- **Une clé par grant.** L'app mint une clé de délégué par mandat → le container
  tient *N packs*, chacun avec sa clé. (Le modèle « un agent = une identité
  persistante qui collectionne N mandats » suppose d'accorder à une pubkey
  externe — c'est un v2.)
- **Namespacing sur collision.** Nom de tool = `<service>__<name>` par défaut ;
  si deux grants exposent un homonyme, on préfixe par un **alias de grant** court
  (`<alias>__<service>__<name>`) — seulement en cas de collision, pour ne pas
  alourdir la vue de l'agent.
- **Liveness/révocation par grant** : chaque mandat a sa fenêtre + sa révocation ;
  couper un grant n'affecte que ses tools.

---

## 7. Ce que fait le gardien (le pivot)

À l'ouverture de session, **pour chaque grant** :

1. **Lit l'Ethos du grant.** v1 = **mode clé-owner** (déchiffre tout — agent perso
   sur ta machine) ou **mode délégué** (le pack de l'app). v2 = délégué scellé
   par section.
2. **Énumère** les sections taguées `action` (index de zone).
3. **Parse + valide** chaque document Action (§3). Mal formé → **ignoré**.
4. **Projette** en tool MCP : `name = <service>__<name>` (namespacé sur
   collision), `description = manifest.description`, `inputSchema =
   manifest.params_schema`.
5. **Borne au mandat** (Modèle B, §8) : section `action` **lisible** = tool
   **utilisable**.

L'agent voit **l'union des tools de tous les grants** + les connecteurs.

Sur un appel de tool :

6. **Valide** les params contre le `params_schema` **signé** (refus si hors-schéma).
7. **Signe** une Mandated Intent Envelope avec **la clé du grant d'origine** →
   ancre d'audit gamma (locale), attribuée à *ce* mandat.
8. **Dispatch** `(recipe, params)` à la main du `service`.
9. **Renvoie** le rapport à l'agent.

---

## 8. Invariants de sécurité

- **L'agent ne fournit JAMAIS que `(quel tool, params)`.** Jamais la recette.
  Aucun canal d'injection au moment de l'usage. La recette est celle du gardien,
  **lue read-only** depuis la source.
- **Le manifeste est signé** → doc LLM owner-authored, infalsifiable.
- **Modèle B — lecture = usage.** Une section `action` que le mandat peut *lire*
  devient un tool *utilisable*. Le scellage à l'agent **est** l'autorisation ; le
  routage vient du `service`. (Les scopes `mcp.<service>.<verb>` restent pour les
  **connecteurs**.)
- **Altérer une action = écrire dans sa section Ethos** — acte *séparé*, gouverné
  par un **mandat d'écriture**. Responsabilité de l'utilisateur : **séparer**
  l'Ethos des actions de celui des données, ou scoper les écritures. Au *moment de
  l'usage*, aucune altération n'est possible.
- **Deny-by-default** partout : pas lisible → pas de tool. Service hors carte →
  pas de tool.
- **Enveloppe = ancre d'audit locale** (gamma), **non envoyée à la main en v1**.
  Le tuyau porte déjà le champ → l'activer = une ligne.

---

## 9. Lecture de l'Ethos : plateforme vs local

- L'Ethos vit **sur la plateforme** (api.aithos.be) ; le studio y publie via le
  SDK (zone `circle`, action = `ActionFile` JSON signé).
- **Les définitions viennent de la plateforme ; l'exécution reste locale.** La
  plateforme (Lambda) ne pilote pas ton browser-agent local. → **le gardien du
  container est le pivot** : il *lit* sur api.aithos.be et *pilote* la main
  locale. Le gateway hébergé (`mcp.aithos.be/mcp`) sert les **connecteurs cloud**,
  pas les mains locales.
- **Capacité manquante** : le gardien ne lit aujourd'hui que du **local**
  (`FilesystemStorage`). Il lui faut un **lecteur-de-plateforme** (`AithosStorage`
  parlant api.aithos.be — ce que fait `protocol-client`, côté `aithos-provider`).
  Repli acceptable pour un premier jet : un Ethos **local** (CLI-synchronisé)
  monté par le gardien.

---

## 10. Comment créer… (la propriété « facile »)

**…une nouvelle action** → publier une section `action` signée `{ service,
manifest, recipe }` (via le studio, qui génère **manifeste ET recette**). Le
gardien la voit, la projette, la borne au mandat. **Zéro code.**

**…un nouveau type de main** → un petit serveur : une URL, accepte
`{recipe, params}`, exécute, renvoie `{ok}`. Il définit son format de recette.
**Zéro connaissance d'Aithos.**

**…brancher un nouvel Ethos** → ajouter un **grant** (un pack, ou une clé owner)
à la liste du container. **Zéro code.**

---

## 11. Phasage

- **K0 — Multi-grant (fondation)** : le gardien accepte une **liste de grants**
  (owner et/ou packs délégués), les itère, fédère + signe + attribue **par grant**.
  On casse l'hypothèse « un seul pack » d'abord.
- **K1** ✅ — browser-agent : `run_action` accepte une recette inline.
- **K2** — le gardien envoie la recette ; `ActionDefinition` porte
  `manifest` + `recipe` ; le dispatch met à jour le message.
- **K3** — lecture des sections `action` **de chaque grant** (v1 clé-owner ;
  local d'abord, plateforme ensuite) ; carte `service→main`.
- **K4** — manifeste : `params_schema` avec descriptions par champ ; le studio
  génère le manifeste.
- **K6** — e2e : un mandat « actions » **+** un mandat « données » (prouve le
  multi-grant) → l'agent ne voit/fait que le permis → prompt « lance read_post … »
  → exécute ; révocation d'un grant coupe ses tools sans toucher les autres.

## 12. Points ouverts (au-delà)

- **Mode délégué scellé** (v2) : ne lire que les sections scellées à l'agent.
- **Identité d'agent persistante** (v2) : un agent = une clé, N mandats accordés à
  sa pubkey (au lieu d'une clé par pack).
- **Lecteur-de-plateforme** : adaptateur `protocol-client` → `AithosStorage`
  (cross-repo `aithos-provider`), ou adaptateur HTTP léger.
- **Fédération des connecteurs cloud** (`mcp.aithos.be/mcp`) à côté des mains
  locales, dans le même container.
- **Envoi de l'enveloppe à la main** (v2), pour un aval vérifieur.
