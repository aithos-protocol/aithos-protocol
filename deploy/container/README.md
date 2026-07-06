# Aithos Mandated Container Runtime

> Reference deployment for **SPEC-container-runtime 0.1.0** (§13). The mandate
> stops being a convention the agent is trusted to honour and becomes a
> **physical boundary** it cannot cross.

An autonomous agent runs inside an isolated container (**the cage**) whose only
path to the outside world is an Aithos enforcement point (**the gateway**). A
buggy, prompt-injected or adversarial agent can do **exactly** what its mandate
permits and nothing more — and every action it takes is signed and attributed.

We don't solve prompt injection. We **contain** it: the blast radius of a
compromised agent equals its mandate.

## The three pieces

| Component | Role | Trust |
|---|---|---|
| **Runtime** (the *cage*) | Runs the agent. Holds no authority, no secret. | Untrusted — assumed compromised. |
| **Gateway** | The single enforcement point: verifies the mandate on every call, filters tools by scope, signs envelopes, proxies inference, records gamma. | Trusted — holds the keys. |
| **Harness** (P1) | Deterministic loop: polls a mailbox, spawns a fresh agent run per mission, owns the state machine. | Deterministic (not an LLM). |

The rule that justifies three, not one: **the deterministic loops, the
intelligence is invoked.**

## Bring your own agent

The runtime is agent-agnostic. Any agent that can

- point its model base-URL at `$AITHOS_GATEWAY_URL/llm`, and
- speak MCP to `$AITHOS_GATEWAY_URL/mcp`

runs in the cage. `runtime-claude-code` is the first reference image (Claude
Code, headless). Swap it for the Agent SDK, a custom loop, or a local model.

## Images

Published to GHCR (primary) by `.github/workflows/container-images.yml` on a
`container-v*` tag; a manual `workflow_dispatch` can publish an `edge` tag.

```
ghcr.io/aithos-protocol/gateway
ghcr.io/aithos-protocol/runtime-claude-code
```

Bring-your-own-agent: point your agent at `$AITHOS_GATEWAY_URL` and the rest is
the gateway's affair. Swap the `runtime-*` image for your own; only the gateway
is ours to trust.

> The CI run **is** the first real Docker build of these images (it runs on
> GitHub's Docker-capable runners). A green run validates the build; pushes
> happen only on a tag or an explicit dispatch, so a broken build never
> publishes. Docker Hub mirroring (`aithosprotocol/*`) activates automatically
> when `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` repo secrets are set.

## Fastest check — no Docker

Prove the five assertions in seconds against the real gateway process:

```bash
npm ci && npm run build          # once, at the repo root
node deploy/container/scripts/check.mjs
```

It boots `aithos-mcp` under a fresh read-only mandate, federates the demo
contacts server, exercises in-scope / out-of-scope / inference / revoke, and
tears everything down. Only criterion 3's kernel network isolation needs
Docker.

## Quick start (Docker)

```bash
# 1. Prepare identity, mandate, pack, registry (writes ./run/).
node deploy/container/scripts/prepare-demo.mjs

# 2. Boot the cage + gateway and run one mission (job mode).
export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)
# Inference auth — ONE of:
#   (a) your Claude subscription, headless:  claude setup-token  → then
export CLAUDE_CODE_OAUTH_TOKEN=$(claude setup-token)   # long-lived, no browser in the cage
#   (b) a plain API key:  export ANTHROPIC_API_KEY=sk-ant-...
docker compose -f deploy/container/docker-compose.yml up --abort-on-container-exit

# 3. The punchline — revoke, and watch everything stop.
node deploy/container/scripts/revoke-demo.mjs
```

> **CLI note.** Prep uses `prepare-demo.mjs` (workspace protocol-core), not the
> `aithos` CLI: the CLI package pins an old protocol-core (`^0.8.0`) that
> rejects sphere-neutral `mcp.*` scopes, so `aithos grant --scope mcp.demo.read`
> fails against a stale nested copy. Fix the CLI's dependency range to restore
> the `aithos grant`/`revoke` path.

### Run with your Claude subscription (dev)

The sealed cage routes inference through the gateway `/llm` proxy, which needs
an API key (or gateway-held custody key). To iterate with your **subscription**
instead, use the DEV overlay — it lets Claude Code talk to `api.anthropic.com`
natively (its own subscription auth) through an egress proxy that allowlists
**exactly that one domain**:

```bash
export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)
export CLAUDE_CODE_OAUTH_TOKEN=$(claude setup-token)     # headless subscription token
node deploy/container/scripts/prepare-demo.mjs
docker compose \
  -f deploy/container/docker-compose.yml \
  -f deploy/container/docker-compose.subscription-dev.yml \
  up --build --abort-on-container-exit
```

Why this is legitimate and still bounded: it is **Claude Code itself** making
the subscription calls (not an injected credential — that would breach
Anthropic's ToS). And **actions stay fully gated**: tools/connectors are reached
only via the gateway MCP under the mandate, so the runtime can reach exactly the
gateway (to act) and `api.anthropic.com` (to think) — nothing else. Conceded in
dev only: inference is not gateway-traced, and a revoked mandate still cuts
actions but not thinking. Rationale + the sealed alternative (B-MITM): see
`ETUDE-CAGE-ABONNEMENT-CLAUDE`. **Never use this overlay for a third-party
mandate.**

## Docker-free proof

The five acceptance assertions run **without Docker** against the real gateway
process — the strongest test we can automate in CI:

```bash
npm test          # deploy/container/test/*.test.mjs
```

- `p0-acceptance.test.mjs` boots `aithos-mcp` in http mode under a real signed
  mandate + registry + LLM proxy, federates the demo contacts server, and
  asserts: in-scope tool runs & is visible; out-of-scope tool is invisible and
  refused if forced; inference flows through `/llm`; **revoke mid-session fails
  the next tool call *and* inference, closed**; no authority secret in the cage.
- `compose-lint.test.mjs` pins the cage invariants that are *configuration*:
  `internal: true` network (no egress), zero ingress, non-root + read-only +
  caps dropped, and **no secret mounted into the cage**.

## What enforces what

| Claim | Enforced by |
|---|---|
| The agent can reach only the gateway | `networks.cage.internal: true` — a kernel boundary, not an app allowlist (N1) |
| No work is pushed into the cage | no published ports; the harness *pulls* (N2) |
| Inference can't become a covert channel | it traverses the gateway `/llm` proxy; no direct model egress (§13.5 I1) |
| A revoked mandate stops everything | per-call liveness on tools **and** `/llm` — fail closed (§13.6 G1, §13.9 L1) |
| No key to steal inside the cage | the pack is mounted to the gateway; the agent authenticates by network position + a session token (§13.7.1) |
| The container never outlives its mandate | L1 fail-closed (security) + revocation/TTL watcher (hygiene) — P1 |

## The subscription exception (§13.7.2)

For a **local** run on **your own** machine you may mount your personal Claude
subscription (`~/.claude`, read-only) into the cage instead of a gateway-held
API key — see the commented block in `docker-compose.yml`. It authorizes
inference only, never Aithos authority, and **must not** be used for a mandate
delegated to a third party (that path is custody mode, P2).

## Missions & the harness (P1)

Two work-delivery modes (§13.8):

- **Job mode** (P0, shipping): one mission in `$AITHOS_MISSION`, the container
  runs it as a single agent run and exits. One container, one mission.
- **Mailbox mode** (P1): a **mailbox** — a designated ethos zone — is the queue.
  The orchestrator writes mission sections (`{id, type:"mission", status,
  payload, …}`); the **harness** (`harness/`) polls, CLAIMS one atomically
  (`pending → in_progress`, so two harnesses never double-execute — W2), spawns
  a *fresh* `claude -p` bound to the mission, and records the terminal status
  (W1). A decision beyond the mandate escalates to `waiting_input` + a
  `question`; a human answer re-queues it to `pending` with context (W3 — this
  *is* the MVP's "validate in one click", with no direct channel). Set
  `AITHOS_HARNESS=1` to opt in.

The harness is **deterministic — not an LLM**: it owns the *when* and the state
machine; the agent owns the *work*. Statuses transition only through the pure
rules in `harness/src/mission.ts` (fully unit-tested). Each mission ↔ one run ↔
`AITHOS_MISSION_ID` stamped on every gamma envelope: "who did what, and why."

A **revocation/TTL watcher** (`harness/src/watcher.ts`) runs outside the cage:
on revocation or `not_after` it pauses then stops the runtime ("revoke =
unplug"). It is best-effort hygiene — L1 fail-closed already cut every call —
so it never becomes the security boundary.

## Files

```
gateway.Dockerfile            the enforcement point (built from the monorepo)
runtime-claude-code.Dockerfile the cage (Claude Code, headless)
entrypoint-runtime.sh         generates the agent config → mission or harness
docker-compose.yml            the topology: internal cage + two-legged gateway
registry.example.json         downstream catalogue (what is connectable)
demo/contacts-server.mjs      a tiny downstream MCP (list/get/add contacts)
harness/src/                  mission state machine, mailbox, loop, watcher
harness/bin/harness.ts        the real entrypoint (ethos mailbox + Claude Code)
scripts/make-pack.mjs         assemble a mandate pack from grant + keyfile
scripts/demo.sh, revoke.sh    the 90-second story
test/                         Docker-free P0 acceptance + compose lint
harness/test/                 mission / harness / watcher unit + integration
```

## Preconditions (resolved)

The gateway container **is** the MCP HTTP transport, so the 2026-07-02 audit
findings were load-bearing here and are fixed upstream in `@aithos/mcp`:
no arbitrary file read over HTTP (no `io` injected — id-form mandates only),
constant-time bearer comparison, and per-session federation that fails closed
outside the mandate window. Remote-ethos (PDS / cas 2) stays out until client
signature verification lands (§13.12 item 3).
