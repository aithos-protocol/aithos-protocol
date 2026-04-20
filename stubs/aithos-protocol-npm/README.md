# aithos-protocol

**This is a placeholder package.** The Aithos reference CLI and SDK are published under the [`aithos`](https://www.npmjs.com/package/aithos) package name.

```bash
# install the real package
npm install aithos
```

## Why does this package exist?

This name is reserved by the maintainers of the [Aithos protocol](https://github.com/aithos-protocol/aithos-protocol) to prevent confusion and typosquatting. The package is intentionally minimal: its sole function is to depend on `aithos` and re-export it, so that `require("aithos-protocol")` still works as a drop-in alias.

When you import this package, it prints a notice on stderr and delegates to `aithos`. To silence the notice, set `AITHOS_PROTOCOL_QUIET=1` in your environment.

## What is Aithos?

Aithos is a protocol for the *digital embodiment of persons*: a self-sovereign identity (`did:aithos`), a structured persona document (the *ethos*), and a mandate system through which a human may authorize an AI agent to act on their behalf — under strict, scope-limited, time-bounded, and unilaterally revocable terms.

- Whitepaper: <https://github.com/aithos-protocol/aithos-protocol/blob/main/WHITEPAPER.md>
- Specification: <https://github.com/aithos-protocol/aithos-protocol/blob/main/SPEC.md>
- Reference CLI: [`aithos`](https://www.npmjs.com/package/aithos) on npm

## License

[Apache-2.0](./LICENSE).
