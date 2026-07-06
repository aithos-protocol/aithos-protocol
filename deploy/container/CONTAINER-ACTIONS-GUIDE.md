# Tester le container (actions → browser-agent) à la main

Le **vrai container gateway** (la cage) pilote browser-agent : sur un appel
d'outil, le gateway valide les params contre le schéma signé, signe une
enveloppe (ancre d'audit), et envoie `run_action` sur le WebSocket avec bearer.
On lance **le gateway seul** (pas de runtime/LLM) et on appelle l'action
nous-mêmes depuis l'hôte — pour voir chaque pièce.

```
Terminal 1 : make sandbox               → le site cible (:8901)
Terminal 2 : browser-agent + vrai Chrome → la main (WS :8765, bearer)
Terminal 3 : docker compose up gateway   → la cage (MCP exposé sur :8787)
Terminal 4 : call-action.mjs             → l'appel (client MCP hôte)
```

**Deux tokens** (garde-les distincts) :
- `BA_BEARER` — gateway → browser-agent (= le `--ws-bearer` de browser-agent).
- `MCP_TOKEN` — toi → gateway (le bearer MCP du gateway).

---

## 1. Le sandbox (cible)

```bash
cd <browser-agent>
make sandbox                       # http://127.0.0.1:8901
```

## 2. browser-agent + vrai Chrome

```bash
cd <browser-agent>
export BA_BEARER="ba-$(openssl rand -hex 8)"
./.venv-darwin-arm64/bin/python -m browser_agent --ws-bearer "$BA_BEARER"
# attends : "run_action exposes 1 action(s): inscription-sandbox" + "/ws requires a bearer token"
```

## 3. Préparer le mandat/pack + lancer le container

Depuis le repo **aithos-protocol** (déjà `npm install && npm run build` une fois) :

```bash
cd <aithos-protocol>

# le pack (mandat qui n'accorde QUE mcp.browser.inscription-sandbox) + actions.json
node deploy/container/scripts/prepare-actions-demo.mjs

# les deux tokens (BA_BEARER = celui du terminal 2)
export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)
export AITHOS_ACTIONS_BEARER="<colle ici le BA_BEARER du terminal 2>"

# build + run du GATEWAY SEUL (l'overlay ajoute --actions, le downstream WS, le port)
docker compose -f deploy/container/docker-compose.yml \
               -f deploy/container/docker-compose.actions-dev.yml \
               up --build gateway
# le gateway écoute sur 127.0.0.1:8787 (MCP)
```

## 4. Appeler l'action depuis l'hôte

Nouveau terminal, dans **aithos-protocol** :

```bash
cd <aithos-protocol>
export AITHOS_MCP_TOKEN=<le même qu'au terminal 3>
node deploy/container/scripts/call-action.mjs "Sophie Martin"
```

Regarde le **Chrome du terminal 2** remplir le formulaire du sandbox. Le script
affiche le `run report` et `✅ the container drove the action under the mandate.`

## 5. Le kill-switch (révocation)

```bash
cd <aithos-protocol>
node deploy/container/scripts/revoke-demo.mjs        # révoque le mandat (côté hôte, vu par la cage en RO)
node deploy/container/scripts/call-action.mjs "Toto" # → refusé, rien ne s'exécute
```

---

## Ce que ça prouve, dans la cage réelle

- La cage n'expose **que** l'action mandatée (`browser_action__inscription-sandbox`).
- Le gateway **valide** `nom` contre le schéma **signé**, **signe** l'enveloppe
  (ancre d'audit gamma), **dispatch** `run_action` sur le WS **avec bearer**.
- La main (browser-agent, hors cage, sur ta machine) exécute — vrai Chrome.
- Révoquer le mandat coupe l'appel suivant (fail-closed).

## Dépannage

- **`downstream rejected the connection (HTTP 401)`** : `AITHOS_ACTIONS_BEARER`
  (terminal 3) ≠ `--ws-bearer` de browser-agent (terminal 2).
- **`ws error` / `ECONNREFUSED` vers host.docker.internal** : browser-agent
  n'écoute pas, ou Docker n'est pas Docker Desktop (sur Linux, lance
  browser-agent avec `--host 0.0.0.0` pour être joignable via host-gateway).
- **401 à l'appel `call-action`** : `AITHOS_MCP_TOKEN` du terminal 4 ≠ celui du
  gateway (terminal 3).
- **`run_stopped … resolve`** : l'action n'est pas côté browser-agent — lance le
  terminal 2 depuis la racine browser-agent (`--actions-dir` défaut `./actions`).
- **le gateway sort en EACCES sur l'audit** : le rootfs est read-only ; l'audit
  gamma va vers stdout — regarde les logs du container, pas un fichier.

## Note publish

Cet overlay (`docker-compose.actions-dev.yml`) est le mode « actions » de la
cage. C'est ce qui rend le container publié capable de piloter browser-agent —
à valider ici avant de tagger `container-v0.1.0`.
