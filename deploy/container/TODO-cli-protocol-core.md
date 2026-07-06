# TODO — réparer `aithos grant` pour les scopes `mcp.*`

**Statut :** différé (session 2026-07-06). Contournement en place : émettre le
mandat depuis app.aithos.be / l'example app (voir `REAL-MANDATE-GUIDE.md`).

## Le problème

Le package CLI (`aithos`) épingle `@aithos/protocol-core: ^0.8.0`, et une copie
imbriquée **0.8.0** vit dans `packages/cli/node_modules/@aithos/protocol-core`.
Cette version est **antérieure aux scopes `mcp.*` sphere-neutral** (introduits
plus tard, dispo dès 0.10.x). Conséquence :

```
aithos grant … --sphere self --scope mcp.browser.inscription-sandbox
# → rejeté par le protocol-core 0.8.0 du CLI (scope inconnu / non permis)
```

Le gateway (`@aithos/mcp`), lui, dépend d'un protocol-core courant
(`>=0.10.3 <0.12.0`, résout 0.11.4) et accepte `mcp.*` — d'où l'asymétrie.

## Pourquoi c'est contenu / sûr

- **Rien ne dépend du CLI** (`aithos` est une feuille) : bumper sa dépendance ne
  touche que le CLI. Gateway / runtime / container n'en dépendent pas et ne
  bougent pas.
- CLI et gateway ne se dépendent pas l'un l'autre ; ce sont deux frères sur le
  même core.

## Le fix

1. `packages/cli/package.json` : `@aithos/protocol-core` `^0.8.0` →
   `>=0.10.3 <0.12.0` (aligné sur le gateway).
2. `npm install` à la racine (met à jour le lockfile, supprime la copie 0.8.0
   imbriquée au profit du workspace 0.11.4).
3. **Vérifier la compat API** : le CLI (`grant.ts`, etc.) importe
   `loadIdentity, createMandate, writeMandate, parseTtl, issueMandateWithRewrap,
   ethosDir` de protocol-core. Compiler (`npm run build --workspace aithos`) et
   corriger toute signature qui aurait bougé entre 0.8 et 0.11.
4. `npm test --workspace aithos` (+ un test neuf : `aithos grant … --scope
   mcp.browser.<id> --sphere self` produit un mandat que le gateway accepte).

## Le test qui prouve le fix

```bash
aithos init                     # ou une identité existante
aithos grant urn:aithos:agent:demo --sphere self \
  --scope mcp.browser.inscription-sandbox --ttl 1h --pubkey <clé-agent>
# -> mandat écrit dans le keystore ; assemble-pack.mjs le récupère et boote la cage
```

Une fois fait, `REAL-MANDATE-GUIDE.md` gagne `aithos grant` comme troisième
source de mandat de plein droit (à côté d'app.aithos.be et de l'example app).
