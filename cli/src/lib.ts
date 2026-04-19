/**
 * Library barrel export.
 *
 * The CLI is primarily a binary, but the MCP server (and any future host
 * process) needs programmatic access to the same primitives. Re-exporting
 * from this file keeps the `exports` map in `package.json` honest without
 * forcing consumers to reach into individual source files.
 */

export * from "./did.js";
export * from "./storage.js";
export * from "./identity.js";
export * from "./mandate.js";
export * from "./ethos.js";
