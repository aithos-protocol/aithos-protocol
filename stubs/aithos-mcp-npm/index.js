// This package is a placeholder reserved by the Aithos protocol maintainers.
// The official MCP (Model Context Protocol) server for Aithos is under
// development and will ship as `@aithos/mcp`. In the meantime, this package
// re-exports the core `aithos` protocol primitives so that imports do not
// break if you were experimenting against this name.
//
// See: https://github.com/aithos-protocol/aithos-protocol

const NOTICE =
  "[aithos-mcp] Note: this package is a placeholder. " +
  "The official MCP server for Aithos will ship as `@aithos/mcp`. " +
  "This stub re-exports the core `aithos` protocol primitives. " +
  "https://github.com/aithos-protocol/aithos-protocol";

// Emit once per process (module cache gives us that for free).
if (process.env.AITHOS_MCP_QUIET !== "1") {
  // eslint-disable-next-line no-console
  console.warn(NOTICE);
}

// Re-export the core protocol primitives so imports from this package name
// do not break. The real MCP server will live at `@aithos/mcp`.
export * from "aithos";
