# aithos-mcp

**This is a placeholder package.** The official Model Context Protocol server for Aithos is under development and will ship as [`@aithos/mcp`](https://www.npmjs.com/package/@aithos/mcp).

This name (`aithos-mcp`, unscoped) is reserved by the maintainers of the [Aithos protocol](https://github.com/aithos-protocol/aithos-protocol) to prevent typosquatting. The package currently re-exports the core `aithos` protocol primitives so that imports do not break, and prints a notice on stderr.

```bash
# This package exists only as a reservation.
# Watch for the real MCP server:
#   npm install @aithos/mcp
```

To silence the notice when importing programmatically, set `AITHOS_MCP_QUIET=1` in your environment.

## What is Aithos?

Aithos is a protocol for the *digital embodiment of persons*: a self-sovereign identity (`did:aithos`), a structured persona document (the *ethos*), and a mandate system through which a human may authorize an AI agent to act on their behalf — under strict, scope-limited, time-bounded, and unilaterally revocable terms.

An MCP server will expose these primitives so that MCP-compatible AI hosts (Claude, etc.) can read and verify Aithos identities, ethos bundles, and mandates directly, without going through the CLI. Follow progress on the [issue tracker](https://github.com/aithos-protocol/aithos-protocol/issues).

- Whitepaper: <https://github.com/aithos-protocol/aithos-protocol/blob/main/WHITEPAPER.md>
- Specification: <https://github.com/aithos-protocol/aithos-protocol/blob/main/SPEC.md>
- Reference CLI: [`aithos`](https://www.npmjs.com/package/aithos) on npm

## License

[Apache-2.0](./LICENSE).
