// This package is a redirect placeholder reserved by the Aithos protocol
// maintainers. The reference CLI and SDK are published as the `aithos` package.
//
// See: https://github.com/aithos-protocol/aithos-protocol

const NOTICE =
  "[aithos-protocol] Note: this package is a placeholder. " +
  "The Aithos reference CLI and SDK are published as `aithos`. " +
  "Run `npm install aithos` instead. " +
  "https://github.com/aithos-protocol/aithos-protocol";

// Emit once per process (module cache gives us that for free).
if (process.env.AITHOS_PROTOCOL_QUIET !== "1") {
  // eslint-disable-next-line no-console
  console.warn(NOTICE);
}

// Re-export the real package so `import ... from "aithos-protocol"` works as
// a drop-in alias. Consumers should migrate their imports to `aithos`.
export * from "aithos";
