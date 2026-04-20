# aithos-cli

**This is a placeholder package.** The Aithos reference CLI is published under the [`aithos`](https://www.npmjs.com/package/aithos) package name.

```bash
# install the real CLI
npm install -g aithos
aithos --help
```

## Why does this package exist?

This name is reserved by the maintainers of the [Aithos protocol](https://github.com/aithos-protocol/aithos-protocol) to prevent confusion — someone reaching for the CLI might naturally type `aithos-cli` instead of `aithos`. Publishing a redirect here prevents typosquatting and makes the mistake obvious: installing this package prints a notice pointing at the real `aithos` binary and re-exports its API, so `require("aithos-cli")` still works as a drop-in alias.

To silence the notice when importing programmatically, set `AITHOS_CLI_QUIET=1` in your environment.

## What is Aithos?

Aithos is a protocol for the *digital embodiment of persons*: a self-sovereign identity (`did:aithos`), a structured persona document (the *ethos*), and a mandate system through which a human may authorize an AI agent to act on their behalf — under strict, scope-limited, time-bounded, and unilaterally revocable terms.

- Whitepaper: <https://github.com/aithos-protocol/aithos-protocol/blob/main/WHITEPAPER.md>
- Specification: <https://github.com/aithos-protocol/aithos-protocol/blob/main/SPEC.md>
- Reference CLI: [`aithos`](https://www.npmjs.com/package/aithos) on npm

## License

[Apache-2.0](./LICENSE).
