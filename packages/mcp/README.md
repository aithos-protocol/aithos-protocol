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

| name                          | what it does                                        |
| ----------------------------- | --------------------------------------------------- |
| `aithos_list_identities`      | List every identity in `$AITHOS_HOME`               |
| `aithos_show_identity`        | DID + sphere DIDs for one identity                  |
| `aithos_ethos_list_sections`  | List sections across `public` / `circle` / `self`   |
| `aithos_ethos_show_section`   | Read the latest body of a section (+ history opt.)  |
| `aithos_ethos_verify`         | Full integrity check (chains, signatures, manifest) |
| `aithos_ethos_add_section`    | Create a new section + initial revision             |
| `aithos_ethos_add_revision`   | Append a revision to an existing section            |
| `aithos_mandate_verify`       | Verify a mandate against a local DID document       |

Read tools require either no auth (`public` zone) or a local identity (so the
server can decrypt `circle` / `self`). Write tools (`add_section`,
`add_revision`) accept either:

- nothing (signs directly with the subject's sphere key — only works on the
  subject's own machine), or
- `mandate` (id or path) + `agentKey` (path to the delegate keyfile produced
  by `aithos delegate-key`), in which case the revision is signed by the
  delegate key and the mandate id is recorded in the on-disk signature.

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

Business Source License 1.1 (**BUSL-1.1**), **Change Date** 2030-12-31, **Change License**
Apache-2.0. See [LICENSE](./LICENSE) in this package and the [repository overview](../../LICENSE).
