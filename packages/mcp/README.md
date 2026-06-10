# `@aithos/mcp` — Aithos MCP server

Exposes an Aithos identity's **ethos** and **mandates** to any MCP-speaking
agent (Claude Code, Claude Desktop, custom hosts, …) over either:

- **stdio** — the classic local transport, used by IDEs and desktop apps
- **HTTP** (Streamable HTTP, `POST /mcp` + SSE fallback) — for daemonized /
  remote deployments

The server is a thin wrapper around `@aithos/protocol-core` — the same library
the `aithos` CLI is built on — so its behaviour is byte-for-byte identical to
the command-line tool. It reads from `$AITHOS_HOME` (default `~/.aithos/`),
exactly like the CLI.

## Install / build

From the repo root (npm workspaces):

```sh
npm install
npm run build
```

This produces `mcp/dist/bin.js`, exposed as the `aithos-mcp` binary.

## Run

### stdio

```sh
aithos-mcp                          # default
aithos-mcp --transport stdio        # explicit
```

### HTTP (Streamable HTTP)

```sh
export AITHOS_MCP_TOKEN=$(openssl rand -hex 32)
aithos-mcp --transport http --port 8787 [--host 127.0.0.1] [--stateless]
```

Clients must send `Authorization: Bearer $AITHOS_MCP_TOKEN`. Stateful mode is
the default — the server hands out an `Mcp-Session-Id` header on `initialize`
and clients echo it on subsequent calls. `--stateless` disables sessions
(every request is independent) and is appropriate for serverless deployments.

A `GET /healthz` endpoint returns `200 {"ok": true}` with no auth check.

## Tools

Tool names, schemas, and normative descriptions come from the shared
canonical catalogue **`@aithos/agent-tools`** (one source of truth across the
MCP server, the SDK agent loop, and the platform registry).

| name                    | what it does                                          |
| ----------------------- | ----------------------------------------------------- |
| `identity_list`         | List every identity this host serves                  |
| `identity_describe`     | DID + sphere DIDs for one identity                    |
| `ethos_list_sections`   | Section index across `public` / `circle` / `self`     |
| `ethos_read_section`    | Read one section's current body (per-section decrypt) |
| `ethos_read_sections`   | Read several sections by id in one call               |
| `ethos_verify`          | Full integrity check (chains, signatures, manifest)   |
| `ethos_add_section`     | Create a new section                                  |
| `ethos_update_section`  | Update title/body/tags of a section                   |
| `ethos_delete_section`  | Delete a section (audit trail in the gamma log)       |
| `mandate_verify`        | Verify a mandate against a local DID document         |

> **0.9 rename.** The pre-0.9 `aithos_*` tool names (and their camelCase
> arguments) keep working at `tools/call` through a deprecation bridge — they
> are no longer listed, and removal is scheduled for 1.0. Mapping:
> `aithos_ethos_show_section` → `ethos_read_section`,
> `aithos_ethos_modify_section` → `ethos_update_section`,
> `aithos_list_identities` → `identity_list`, etc. (see
> `LEGACY_TOOL_ALIASES` in `@aithos/agent-tools`).

### Mandate-scoped exposure

When the server is created with a `mandate`, `tools/list` only exposes the
tools its scopes allow (e.g. a read-only mandate never sees the write tools).
Per-call zone enforcement stays on in the handlers either way — a forged call
to a hidden or out-of-scope tool returns an error and never writes.

Read tools require either no auth (`public` zone) or a local identity (so the
server can decrypt `circle` / `self`). Write tools (`add_section`,
`update_section`, `delete_section`) accept either:

- nothing (signs directly with the subject's sphere key — only works on the
  subject's own machine), or
- `mandate` (id or path) + `agent_key` (path to the delegate keyfile produced
  by `aithos delegate-key`), in which case the write is signed by the
  delegate key and the mandate id is recorded in the on-disk signature.

### Library use (isomorphic core)

`createServer(opts)` is browser-safe: it imports no node builtins and no
filesystem backend (`npm run check:browser` enforces this). Hosts inject
their capabilities — `storage` (an `AithosStorage`; **required**), `io`
(path-form mandate/keyfile reading), `home`, `manifestPath`, `renderZone`,
`mandate` (scope-filtered exposure), `legacyAliases`. The `aithos-mcp` CLI
(bin.ts) is the node host and wires `FilesystemStorage` + `$AITHOS_HOME`.

## Resources

| URI template                                  | mime                  |
| --------------------------------------------- | --------------------- |
| `aithos://identities`                         | `application/json`    |
| `aithos://ethos/{handle}/manifest`            | `application/json`    |
| `aithos://ethos/{handle}/{zone}`              | `text/markdown` *     |
| `aithos://ethos/{handle}/manifest-path`       | `text/plain`          |

\* For `circle` / `self` zones the server tries to decrypt with the local
identity. If no identity is available, it returns the on-disk ciphertext as a
base64 blob — useful for sync agents that never need plaintext.

## Wiring it up

### Claude Code / Claude Desktop (stdio)

```jsonc
{
  "mcpServers": {
    "aithos": {
      "command": "aithos-mcp",
      "args": ["--transport", "stdio"],
      "env": { "AITHOS_HOME": "/Users/me/.aithos" }
    }
  }
}
```

### A remote HTTP server

Behind any reverse proxy that preserves headers:

```nginx
location /mcp {
  proxy_pass         http://127.0.0.1:8787/mcp;
  proxy_http_version 1.1;
  proxy_set_header   Connection "";
  proxy_buffering    off;       # critical for SSE
}
```

## Security notes

- The bearer token is the only auth check at the transport level. Rotate it
  with the same care as any other secret.
- The server runs with the privileges of the user who started it. Anyone who
  can reach the bearer-protected endpoint gets full read/write power over the
  identities in `$AITHOS_HOME`.
- v0.2.x stores private sphere-key seeds as plaintext JSON files under
  `$AITHOS_HOME` (mode 0600). Treat that directory as a credential store.
  The gamma log itself is sealed at rest under the self sphere key.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). See [LICENSE](./LICENSE)
in this package and the [repository overview](../../LICENSE).

The protocol specification (`spec/`, `SPEC.md`, `WHITEPAPER.md`) is under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
