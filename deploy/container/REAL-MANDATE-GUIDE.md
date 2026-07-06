# Booter la cage sous TON mandat (fait main)

Au lieu du mandat jetable de `prepare-actions-demo.mjs`, on lance la cage sous un
**vrai mandat que tu as émis toi-même** — depuis **app.aithos.be**, l'example
app, ou (à terme) le CLI. Comme tout est bâti sur le même `protocol-core`, la
source est indifférente : le gateway vérifie n'importe lequel de la même façon.

Le gateway a besoin de deux choses : **ton mandat** (signé par ton identité) **+
la clé de l'agent** qu'il représente. La clé d'owner ne rentre JAMAIS dans la cage.

## 1. Générer la clé de l'agent

```bash
cd <aithos-protocol>
node deploy/container/scripts/new-agent-key.mjs
```

Ça écrit `deploy/container/run/agent-key.json` et imprime une **pubkey** :

```
agent pubkey (multibase):  z6Mk…
```

## 2. Émettre le mandat vers cette pubkey (app.aithos.be)

Dans **app.aithos.be**, crée un mandat :

- **grantee / agent** : la pubkey `z6Mk…` de l'étape 1 ;
- **sphère** : `self` ;
- **scope** : `mcp.browser.inscription-sandbox` ;
- **durée** : ce que tu veux (ex. 1h).

Puis **exporte le mandat en JSON** (le fichier `mandate.json`).

> Le scope et le grantee doivent correspondre — l'assembleur refuse sinon
> (fail-closed), pour ne pas booter un mandat qui ne gate pas ce que tu crois.

## 3. Assembler le pack depuis ce mandat

```bash
node deploy/container/scripts/assemble-pack.mjs --mandate <chemin>/mandate.json
```

Ça écrit `run/pack.json` (ton mandat + la clé d'agent), `run/actions.json`, et un
`run/home` minimal (store de révocation seulement — **pas** de clé d'owner). Ça
vérifie que le mandat porte bien `mcp.browser.inscription-sandbox` et qu'il est
accordé à ta clé d'agent.

## 4. Booter la cage

Comme d'habitude (démo esprit-en-cage ou appel direct) — le gateway tourne
maintenant sous **ton** mandat :

```bash
export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-…'
export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)
export AITHOS_ACTIONS_BEARER=aithos-ba-demo        # = browser-agent --ws-bearer
docker compose -f deploy/container/docker-compose.yml \
               -f deploy/container/docker-compose.demo-cage.yml \
               up --build --abort-on-container-exit
```

(Ou l'appel déterministe : `docker compose … -f docker-compose.actions-dev.yml up gateway`
puis `call-action.mjs`.)

## Révocation

Le gateway lit le store de révocation **local** (`run/home`). Une révocation
faite dans app.aithos.be ne s'y propage pas automatiquement (pas de sync dans ce
mode dev) : pour couper localement, dépose la révocation dans `run/home`. La
propagation depuis app.aithos.be est un chantier séparé.

## Autres sources de mandat

- **example app (aithos-app-example)** : idem, même format de mandat.
- **`aithos grant` (CLI)** : ⚠️ **différé** — le CLI est épinglé à une vieille
  `protocol-core` (0.8.0) antérieure aux scopes `mcp.*` ; `aithos grant --scope
  mcp.browser.…` serait rejeté. Voir `TODO-cli-protocol-core.md`. En attendant,
  utilise app.aithos.be.
