// Browser-init gate for the BROWSER-FACING core surface (what protocol-client
// and the SDK import from the root): bundles a pc-shaped entry with esbuild
// (platform=browser, node builtins shimmed empty), then EXECUTES it in a VM
// with no `process`, no `Buffer`, no node globals. Catches any node-bound
// module retained at init (the 0.11.0/0.11.1 white-screen class of bug).
// Run: node --experimental-vm-modules scripts/check-browser.mjs
import * as esbuild from "esbuild";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";

const dir = mkdtempSync(join(tmpdir(), "core-browser-check-"));
const names = ["homedir","join","dirname","basename","resolve","existsSync","readFileSync","writeFileSync","readdirSync","rmSync","mkdtempSync","statSync","copyFileSync","mkdirSync","unlinkSync","tmpdir","randomBytes","createHash","chmodSync","renameSync","lstatSync","sep","relative","appendFileSync"];
writeFileSync(join(dir, "shim.mjs"), "export default {};\n" + names.map((n) => `export const ${n} = undefined;`).join("\n"));
writeFileSync(join(dir, "entry.mjs"), `
import { buildManifestV04, dekAadV04, titleAadV2, shardCountForN, shardIndexForSection, objectShaHexV04, canonicalManifestHashHexV04 } from "${process.cwd()}/dist/index.js";
if (typeof buildManifestV04 !== "function" || shardCountForN(200) !== 2) throw new Error("surface broken");
globalThis.__OK = true;
`);

const r = await esbuild.build({
  entryPoints: [join(dir, "entry.mjs")],
  bundle: true, format: "esm", platform: "browser", write: false, logLevel: "silent",
  plugins: [{ name: "shims", setup(b) {
    b.onResolve({ filter: /^(node:)?(path|fs|os|crypto|util|zlib|constants|stream|buffer|events|assert)$/ }, () => ({ path: join(dir, "shim.mjs") }));
  } }],
});
const ctx = vm.createContext({ console, TextEncoder, TextDecoder, crypto: globalThis.crypto, URL });
const mod = new vm.SourceTextModule(r.outputFiles[0].text, { context: ctx });
await mod.link(() => { throw new Error("unexpected import"); });
await mod.evaluate();
if (!ctx.__OK) throw new Error("entry did not run");
console.log("check:browser OK — the pc-facing core surface initializes with zero node globals");
