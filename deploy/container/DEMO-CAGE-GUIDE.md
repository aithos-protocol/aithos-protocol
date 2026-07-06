# La démo « l'esprit en cage »

Claude Code tourne **dans** la cage, reçoit une mission, ne voit **que** les
actions que son mandat autorise (comme outils MCP), en choisit une **tout seul**,
un vrai Chrome l'exécute sur ta machine, puis le container s'arrête. Toute la
chaîne Aithos, de bout en bout, avec l'agent aux commandes.

## Prérequis

Ton abonnement Claude en token headless (une fois) :

```bash
claude setup-token        # copie le sk-ant-oat01-… qu'il imprime
```

## Les trois terminaux

**1. Le sandbox (cible)** — dans browser-agent :

```bash
make sandbox
```

**2. La main + vrai Chrome** — dans browser-agent :

```bash
./.venv-darwin-arm64/bin/python -m browser_agent --ws-bearer aithos-ba-demo
```

**3. La cage** — dans aithos-protocol :

```bash
export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-…'     # ⚠️ entre guillemets simples, JUSTE le token
export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)
export AITHOS_ACTIONS_BEARER=aithos-ba-demo          # = le --ws-bearer du terminal 2

node deploy/container/scripts/prepare-actions-demo.mjs

docker compose -f deploy/container/docker-compose.yml \
               -f deploy/container/docker-compose.demo-cage.yml \
               up --build --abort-on-container-exit
```

## Ce que tu regardes

- **Le Chrome du terminal 2** : l'agent, depuis la cage, déclenche la navigation
  vers le sandbox, tape « John Doe », clique Continuer puis Valider.
- **Les logs du terminal 3** (flux `stream-json` du runtime) : le **raisonnement**
  de l'agent puis son **appel d'outil**. Pour le rendre lisible :

  ```bash
  # dans un 4e terminal, en suivant les logs du runtime :
  docker compose -f deploy/container/docker-compose.yml \
                 -f deploy/container/docker-compose.demo-cage.yml \
                 logs -f runtime | sed -n 's/.*"text":"\([^"]*\)".*/\1/p'
  ```

  Tu verras la trace du type : *« la mission demande d'inscrire quelqu'un… je
  regarde mes outils… j'ai `inscription-sandbox`… je l'appelle avec nom=John
  Doe »*, puis le `run_report`, puis l'agent conclut et le container sort.

## Le point clé de la démo

L'agent **ne connaît pas** le nom de l'outil à l'avance. On lui donne une
mission en langage naturel ; il **découvre** dans sa liste d'outils — celle que
le gateway a matérialisée depuis son mandat — une action qui colle, et l'utilise.
Change le mandat (autorise une autre action, ou révoque) et la liste d'outils
qu'il voit change : `AITHOS_MISSION="…"` + un autre scope = un autre comportement,
sans toucher au code.

## Dépannage

- **`AITHOS_ACTIONS_BEARER … missing`** : tu ne l'as pas exporté (= le
  `--ws-bearer` du terminal 2).
- **auth d'inférence qui échoue** : `CLAUDE_CODE_OAUTH_TOKEN` doit être **le seul
  token**, sans espaces (pas toute la sortie de `setup-token`). L'entrypoint
  refuse tôt si ce n'est pas le cas.
- **claude-code #48011** (validation OAuth vers un domaine bloqué) : si le
  premier appel échoue sur l'auth, lis l'hôte refusé dans les logs de
  `egress-proxy` et ajoute-le à `EGRESS_ALLOWLIST` dans l'overlay.
- **l'agent n'appelle pas l'action** : rends la mission plus directe
  (`AITHOS_MISSION="Inscris John Doe sur le sandbox avec l'outil disponible."`),
  ou vérifie que le sandbox (terminal 1) tourne bien.
- **`ws` / `timeout` vers host.docker.internal** : browser-agent n'écoute pas,
  ou (Linux) lance-le avec `--host 0.0.0.0`.

## Différence avec l'appel direct (`call-action.mjs`)

Là, c'est **l'agent** qui décide (vraie inférence, non-déterministe) — c'est la
démo « produit ». `call-action.mjs` reste utile comme test **déterministe** de
la même chaîne, sans inférence.
