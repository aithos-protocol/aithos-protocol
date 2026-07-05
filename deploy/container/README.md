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

## Quick start (Docker)

```bash
# 1. Prepare identity, mandate, pack, registry (writes ./run/).
bash scripts/demo.sh

# 2. Boot the cage + gateway and run one mission (job mode).
export AITHOS_MCP_TOKEN=$(openssl rand -hex 24)
export AITHOS_HOME=./run/home
docker compose up --abort-on-container-exit

# 3. The punchline — revoke, and watch everything stop.
bash scripts/revoke.sh
```

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

## Files

```
gateway.Dockerfile            the enforcement point (built from the monorepo)
runtime-claude-code.Dockerfile the cage (Claude Code, headless)
entrypoint-runtime.sh         generates the agent config → runs the mission
docker-compose.yml            the topology: internal cage + two-legged gateway
registry.example.json         downstream catalogue (what is connectable)
demo/contacts-server.mjs      a tiny downstream MCP (list/get/add contacts)
scripts/make-pack.mjs         assemble a mandate pack from grant + keyfile
scripts/demo.sh, revoke.sh    the 90-second story
test/                         the Docker-free acceptance + compose lint
```

## Preconditions (resolved)

The gateway container **is** the MCP HTTP transport, so the 2026-07-02 audit
findings were load-bearing here and are fixed upstream in `@aithos/mcp`:
no arbitrary file read over HTTP (no `io` injected — id-form mandates only),
constant-time bearer comparison, and per-session federation that fails closed
outside the mandate window. Remote-ethos (PDS / cas 2) stays out until client
signature verification lands (§13.12 item 3).
