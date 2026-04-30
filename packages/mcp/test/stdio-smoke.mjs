#!/usr/bin/env node
/**
 * stdio-smoke.mjs — tiny interactive client for aithos-mcp (stdio transport).
 *
 * Usage (run from the mcp/ directory, after `npm run build`):
 *
 *   node test/stdio-smoke.mjs tools
 *   node test/stdio-smoke.mjs resources
 *   node test/stdio-smoke.mjs read aithos://ethos/john-doe/manifest
 *   node test/stdio-smoke.mjs call aithos_list_identities
 *   node test/stdio-smoke.mjs call aithos_show_identity '{"handle":"john-doe"}'
 *
 * The script spawns `node dist/bin.js --transport stdio`, performs the
 * initialize handshake via the official MCP client SDK, runs the requested
 * command, and exits. It sets no environment — the server reads the same
 * $AITHOS_HOME (default ~/.aithos) as the aithos CLI.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const argv = process.argv.slice(2);
if (argv.length === 0) {
  console.error(
    "usage: stdio-smoke.mjs <tools|resources|read <uri>|call <tool> [json-args]>",
  );
  process.exit(1);
}

// The MCP SDK's StdioClientTransport does NOT inherit the parent's environment
// by default — it only forwards a minimal "safe" set (PATH, HOME, ...). For the
// smoke test we want the child to see our $AITHOS_HOME override so we can point
// it at a throwaway directory (tracked-mode fixtures, etc.). Pass process.env
// explicitly.
const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/bin.js", "--transport", "stdio"],
  env: { ...process.env },
});
const client = new Client({ name: "aithos-smoke", version: "0.1.0" }, { capabilities: {} });

await client.connect(transport);

const cmd = argv[0];
try {
  if (cmd === "tools") {
    const r = await client.listTools();
    for (const t of r.tools) {
      console.log(`${t.name}`);
      if (t.description) console.log(`  ${t.description.split("\n")[0]}`);
    }
  } else if (cmd === "resources") {
    const r = await client.listResources();
    if (r.resources.length === 0) console.log("(no resources)");
    for (const res of r.resources) {
      console.log(`${res.uri}${res.mimeType ? "  [" + res.mimeType + "]" : ""}${res.name ? "  — " + res.name : ""}`);
    }
  } else if (cmd === "read") {
    const uri = argv[1];
    if (!uri) throw new Error("read requires a URI");
    const r = await client.readResource({ uri });
    for (const c of r.contents) {
      console.log(`-- ${c.uri}${c.mimeType ? " (" + c.mimeType + ")" : ""} --`);
      if (typeof c.text === "string") {
        console.log(c.text);
      } else if (typeof c.blob === "string") {
        console.log(`[base64 blob, ${c.blob.length} chars]`);
      } else {
        console.log(JSON.stringify(c, null, 2));
      }
    }
  } else if (cmd === "call") {
    const tool = argv[1];
    if (!tool) throw new Error("call requires a tool name");
    const args = argv[2] ? JSON.parse(argv[2]) : {};
    const r = await client.callTool({ name: tool, arguments: args });
    for (const c of r.content ?? []) {
      if (c.type === "text") console.log(c.text);
      else console.log(JSON.stringify(c, null, 2));
    }
    if (r.isError) process.exitCode = 1;
  } else {
    throw new Error(`unknown command: ${cmd}`);
  }
} catch (e) {
  console.error(`smoke: ${e.message}`);
  process.exitCode = 1;
} finally {
  await client.close();
}
