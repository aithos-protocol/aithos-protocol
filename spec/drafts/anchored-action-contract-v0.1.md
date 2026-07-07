# Le Contrat d'Action Ancrée (K3)

**Version :** 0.1.0 (draft) · **Statut :** design, cadré en session 2026-07-06.
**Dépend de :** §3 Ethos/sections, §4 Mandats, §5 Signing, `spec/drafts/mandated-intent-envelope-v0.1.md` (l'enveloppe + la « main bête »).

> Comment une **action dynamique**, définie comme une **section signée de l'Ethos**,
> devient un **outil MCP** que l'agent en cage peut utiliser, sans que le gardien
> ni la main ne connaissent le domaine l'un de l'autre. C'est le maillon qui
> transforme « une démo qui marche » en **plateforme d'agents composables**.

---

## 1. Les trois rôles

- **L'Ethos définit.** Une action est une **section** signée, taguée `action`,
  dont le corps est un *document Action* typé (§3 ci-dessous). Source de vérité,
  immuable-par-signature, versionnée, zonée.
- **Le gardien projette + gouverne + route.** Il lit les sections `action`, les
  projette en tools MCP, les borne au mandat, valide les paramètres, signe
  l'ancre d'audit, et route l'exécution vers la bonne **main**. C'est *lui*,
  « l'outil de type MCP qui comprend des actions dynamiques ».
- **La main exécute.** Bête : elle reçoit `(recette, params)`, rejoue, renvoie un
  rapport. Aucune connaissance d'Aithos, de mandats, de MCP-vers-l'agent, d'Ethos.
  browser-agent en est l'implémentation de référence.

Le principe qui rend le tout **ouvert et facile** : **l'opacité de la recette**.
Le gardien ne comprend pas la recette ; il la transmet. La main ne comprend que
sa recette. Ni l'un ni l'autre n'a besoin du domaine de l'autre.

---

## 2. Deux publics, deux descriptions

Une même action porte **deux** descriptions, pour deux lecteurs :

- **Le manifeste** — pour le **LLM** (l'agent). *À quoi ça sert, comment l'utiliser.*
  C'est la seule chose que l'agent voit ; sa qualité fait toute la qualité d'usage.
  C'est la déclaration de tool MCP : `{ name, description, inputSchema }`.
- **La recette** — pour la **main**. *Comment* exécuter. **Opaque** au gardien
  ET au LLM.

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
- Le format de `recipe` est **propre au service** : gestes navigateur pour
  `browser`, template d'appel API pour un connecteur maison, script, etc.

**Nom de tool** : `<service>__<name>` (namespacé pour éviter les collisions entre
Ethos/services). Mais c'est la **description** qui porte le sens, pas le nom.

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

- **Transport au choix** : WS (browser-agent), HTTP, MCP. Injectable côté gardien
  (`wsActionDispatch`, `httpActionDispatch`, …).
- **Une main n'a besoin QUE de ça** + comprendre sa recette. C'est le critère
  « créer un outil facilement » : un petit serveur qui accepte `(recipe, params)`,
  exécute, répond `{ok}`.

---

## 5. Contrat C — routage service → main

```jsonc
// carte de config du gardien
{ "browser":  { "url": "ws://host.docker.internal:8765", "transport": "ws",   "bearer_env": "AITHOS_ACTIONS_BEARER" },
  "monoutil": { "url": "wss://main.exemple.com",         "transport": "ws" },
  "gmail":    { "url": "https://…/mcp",                  "transport": "mcp" } }
```

- **Emplacement** (local/distant), **transport** (ws/http/mcp), **identité de
  l'outil** : trois axes indépendants. La main est un **endpoint configurable**,
  pas un composant en dur.
- Le `service` du document Action sélectionne l'entrée. Un service inconnu de la
  carte → l'action n'est pas exposée (fail-closed).

---

## 6. Ce que fait le gardien (le pivot)

À l'ouverture de session :

1. **Lit l'Ethos.** v1 = **mode clé-owner** (le gardien détient la clé owner,
   déchiffre tout — cas de l'agent perso sur ta machine). v2 = **mode délégué**
   (ne lit que les sections scellées à la clé d'agent).
2. **Énumère** les sections taguées `action` (index de zone).
3. **Parse + valide** chaque document Action (schéma A). Un document mal formé
   est **ignoré** (ne devient pas un tool).
4. **Projette** chaque action en **tool MCP** : `name = <service>__<name>`,
   `description = manifest.description`, `inputSchema = manifest.params_schema`.
5. **Borne au mandat** (Modèle B, §7) : une section `action` **lisible** par le
   mandat = un tool **utilisable**.

Sur un appel de tool :

6. **Valide** les params de l'agent contre le `params_schema` **signé** (refus si
   hors-schéma).
7. **Signe** une Mandated Intent Envelope → **ancre d'audit gamma** (locale).
8. **Dispatch** `(recipe, params)` à la main du `service` (Contrat B).
9. **Renvoie** le rapport à l'agent.

---

## 7. Invariants de sécurité

- **L'agent ne fournit JAMAIS que `(quel tool, params)`.** Jamais la recette. Il
  n'a **aucun canal** pour injecter ou altérer une recette au moment de l'usage.
  La recette est celle du gardien, **lue read-only** depuis la source.
- **Le manifeste est signé** → la doc que voit le LLM est owner-authored,
  infalsifiable.
- **Modèle B — lecture = usage.** Une section `action` que le mandat peut *lire*
  devient un tool *utilisable*. Le scellage à l'agent (crypto) **est** déjà
  l'autorisation ; le routage vient du `service`, pas d'un scope `mcp.*` dédié.
  (Les scopes `mcp.<service>.<verb>` restent pour les **connecteurs**.)
- **Altérer une action = écrire dans sa section Ethos** — un acte *séparé*,
  gouverné par un **mandat d'écriture** sur cet Ethos. Responsabilité de
  l'utilisateur : **séparer** l'Ethos des actions de celui des données, ou scoper
  les écritures. Le système garantit qu'au *moment de l'usage*, aucune altération
  n'est possible — pas que tu ne peux pas te tirer une balle dans le pied avec un
  mandat d'écriture trop large.
- **Deny-by-default** partout : pas lisible → pas de tool.
- **Enveloppe = ancre d'audit locale** (gamma). **Non envoyée à la main en v1**
  (tout est tracé dans le container). Le tuyau porte déjà le champ → l'activer
  plus tard = une ligne.

---

## 8. Lecture de l'Ethos : plateforme vs local

- L'Ethos vit **sur la plateforme** (api.aithos.be) ; le studio y publie via le
  SDK (zone `circle`, action = `ActionFile` JSON signé).
- **Les définitions viennent de la plateforme ; l'exécution reste locale.** La
  plateforme (un Lambda) ne peut pas piloter ton browser-agent local. Donc **le
  gardien du container est le pivot** : il *lit* sur api.aithos.be et *pilote* la
  main locale. Le gateway hébergé (`mcp.aithos.be/mcp`) sert les **connecteurs
  cloud**, pas les mains locales.
- **Capacité manquante** : le gardien ne lit aujourd'hui que du **local**
  (`FilesystemStorage`). K3 = lui donner un **lecteur-de-plateforme** (un
  `AithosStorage` qui parle à api.aithos.be en délégué/owner ; c'est ce que fait
  `protocol-client`, qui vit côté `aithos-provider`/SDK). Repli acceptable pour un
  premier jet : un Ethos **local** (synchronisé par la CLI) que le gardien monte.

---

## 9. Comment créer… (la propriété « facile »)

**…une nouvelle action** → publier une section `action` signée `{ service,
manifest, recipe }` dans l'Ethos (via le studio, qui génère **le manifeste ET la
recette**). Le gardien la voit, la projette en tool, la borne au mandat. **Zéro
code.**

**…un nouveau type de main** → un petit serveur : une URL, il accepte
`{recipe, params}`, exécute (dans son domaine), renvoie `{ok}`. Il définit son
format de recette. **Zéro connaissance d'Aithos.**

---

## 10. Phasage

- **K1** ✅ — browser-agent : `run_action` accepte une recette inline.
- **K2** — le gardien envoie la recette (au lieu d'un id) ; `ActionDefinition`
  porte `manifest` + `recipe` ; dispatch met à jour le message.
- **K3** — le gardien lit les sections `action` depuis l'Ethos (v1 clé-owner ;
  local d'abord, plateforme ensuite) ; carte `service→main`.
- **K4** — le manifeste : `params_schema` avec descriptions par champ ; le studio
  génère le manifeste.
- **K6** — e2e : mandat de lecture sur des sections `action` → l'agent ne voit/fait
  que celles-là → prompt « lance read_post … » → exécute ; révocation coupe.

## 11. Points ouverts (au-delà de K3)

- **Mode délégué** (v2) : ne lire que les sections scellées à l'agent (scellage =
  autorisation).
- **Lecteur-de-plateforme** : adaptateur `protocol-client` → `AithosStorage`
  (cross-repo avec `aithos-provider`), ou adaptateur HTTP léger.
- **Multi-mandat** : un agent, N mandats (Ethos d'actions + Ethos de données),
  émetteurs distincts, sans collision ni recopie.
- **Namespacing des scopes/actions** entre plusieurs Ethos/bibliothèques.
- **Fédération des connecteurs cloud** (`mcp.aithos.be/mcp`) à côté des mains
  locales, dans le même container.
- **Envoi de l'enveloppe à la main** (v2), pour un aval qui voudrait vérifier.
