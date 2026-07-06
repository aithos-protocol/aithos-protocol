# Booter la cage sous TON mandat (fait main)

Au lieu du mandat jetable de `prepare-actions-demo.mjs`, on lance la cage sous un
**vrai mandat que tu as émis toi-même** avec ton identité Ethos. Le gateway ne
re-vérifie pas la signature au boot (il applique fenêtre + révocation + scope) et
la main est bête → la **source** du mandat est indifférente.

Le gateway a besoin de : **ton mandat** (signé par ton identité) **+ la clé de
l'agent** qu'il représente. La clé d'owner ne rentre JAMAIS dans la cage.

---

## Flux A — via l'app (recommandé)

L'app (`aithos-app-example`, et à terme `app.aithos.be`) **mint la clé de l'agent
elle-même** et te la donne dans un **delegate bundle** (mandat + clé) — donc rien
à générer à la main.

> Prérequis app-example : le champ **« Custom scopes »** du formulaire de mandat
> (ajouté pour accorder des scopes `mcp.*` que les cases à cocher ne couvrent pas).

1. Dans l'app, connecte-toi **en owner** (ton identité), onglet **Mandates**.
2. Remplis :
   - **Grantee URN** : ce que tu veux (ex. `urn:aithos:agent:demo1`) ;
   - **Custom scopes** : `mcp.browser.inscription-sandbox` ;
   - **TTL** : au choix.
   (Un scope `mcp.*` force la sphère `self` automatiquement.)
3. **Create mandate** → **télécharge le bundle** (le `.json`).
4. Assemble le pack depuis ce bundle :

   ```bash
   cd <aithos-protocol>
   node deploy/container/scripts/assemble-pack.mjs --bundle <chemin>/mandate-bundle.json
   ```

   Ça écrit `run/pack.json` (ton mandat + la clé d'agent du bundle),
   `run/actions.json`, `run/registry.json`, et un `run/home` minimal — **pas** de
   clé d'owner dans la cage.

5. Boote la cage (démo esprit-en-cage ou appel direct) — sous **ton** mandat :

   ```bash
   export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-…'
   export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)
   export AITHOS_ACTIONS_BEARER=aithos-ba-demo        # = browser-agent --ws-bearer
   docker compose -f deploy/container/docker-compose.yml \
                  -f deploy/container/docker-compose.demo-cage.yml \
                  up --build --abort-on-container-exit
   ```

---

## Flux B — mandat brut + ta propre clé d'agent (CLI / avancé)

Quand tu émets le mandat par un moyen qui n'embarque pas la clé (ex. `aithos
grant`, une fois réparé — cf. `TODO-cli-protocol-core.md`) :

```bash
node deploy/container/scripts/new-agent-key.mjs        # -> run/agent-key.json + une pubkey
# accorde le mandat À CETTE pubkey (sphère self, scope mcp.browser.inscription-sandbox),
# exporte le mandat en JSON, puis :
node deploy/container/scripts/assemble-pack.mjs --mandate <mandate.json>
```

---

## Vérifications & révocation

- `assemble-pack` **échoue** si le mandat ne porte pas le scope attendu, ou si le
  grantee ≠ la clé d'agent (fail-closed) — pour ne pas booter un mandat qui ne
  gate pas ce que tu crois. Passe `--service`/`--action` si ton scope diffère.
- Le gateway lit le store de révocation **local** (`run/home`). Une révocation
  faite dans l'app ne s'y propage pas automatiquement (mode dev) : pour couper
  localement, dépose la révocation dans `run/home`. La propagation depuis l'app
  est un chantier séparé.
