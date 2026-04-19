#!/usr/bin/env node
/**
 * Aithos reference CLI entry point.
 *
 * The CLI is intentionally small. It covers exactly the primitives defined in
 * the v0.1.0 protocol:
 *
 *   aithos init          — create an identity, derive DID document
 *   aithos show          — print identity info
 *   aithos list <kind>   — list identities, mandates, revocations
 *   aithos grant         — issue a mandate
 *   aithos revoke        — revoke a mandate
 *   aithos verify        — verify a mandate / revocation / action artifact
 *   aithos sign-action   — emit a signed action artifact (agent side),
 *                          or counter-sign an existing artifact (subject side)
 *
 * Everything lives under `~/.aithos/` by default, overridable via
 * `AITHOS_HOME`. The on-disk format is described in the spec (ch. 1, §1.5).
 */

import { Command } from "commander";
import { runInit } from "./commands/init.js";
import { runShow } from "./commands/show.js";
import { runList, type ListKind } from "./commands/list.js";
import { runGrant } from "./commands/grant.js";
import { runRevoke } from "./commands/revoke.js";
import { runVerify } from "./commands/verify.js";
import { runSignAction } from "./commands/sign-action.js";
import { runDelegateKey } from "./commands/delegate-key.js";
import { runRotate } from "./commands/rotate.js";

const program = new Command();

program
  .name("aithos")
  .description("Aithos reference CLI — identities, mandates, signatures.")
  .version("0.1.0");

program
  .command("init")
  .description("Create a new Aithos identity (root + three sphere keys)")
  .requiredOption("--handle <handle>", "Identity handle (a-z, 0-9, _, -)")
  .option("--display-name <name>", "Human-readable display name")
  .option("--force", "Overwrite an existing identity with the same handle")
  .action((o) => wrap(() => runInit(o)));

program
  .command("show")
  .description("Print identity metadata (DID, sphere keys, …)")
  .argument("[handle]", "Identity handle; defaults to the configured default")
  .option("--json", "Output JSON")
  .action((handle, opts) => wrap(() => runShow({ handle, json: opts.json })));

program
  .command("list")
  .description("List local identities, mandates, or revocations")
  .argument("<kind>", "One of: identities, mandates, revocations")
  .option("--json", "Output JSON")
  .action((kind, opts) => wrap(() => runList(kind as ListKind, !!opts.json)));

program
  .command("grant")
  .description("Issue a mandate authorizing an agent to act under your identity")
  .argument("<agent>", "Grantee id (urn:aithos:agent:…, did:aithos:…, did:key:…, did:web:…)")
  .requiredOption("--sphere <sphere>", "public | circle | self")
  .requiredOption("--scope <list>", "Comma-separated scope list (e.g. email.reply,ethos.read.circle)")
  .requiredOption("--ttl <duration>", "Validity window (e.g. 7d, 4h, 30m)")
  .option("--handle <h>", "Issuing identity (defaults to current default)")
  .option("--label <label>", "Human-readable label for the grantee")
  .option("--pubkey <multibase>", "Agent's Ed25519 public key (multibase z…)")
  .option("--domains <list>", "Comma-separated domain restriction (* for any)")
  .option("--rate-limit <pairs>", "Rate limits, e.g. replies_per_hour=20")
  .option("--counter-sign <list>", "Scopes that require subject counter-signature")
  .option("--json", "Output JSON")
  .action((agent, opts) => wrap(() => runGrant({ agent, ...opts })));

program
  .command("revoke")
  .description("Revoke a previously-issued mandate (pass a mandate id, or --all to revoke every local mandate)")
  .argument("[mandate-id]", "Mandate id (mandate_<ULID>). Omit when using --all.")
  .option("--all", "Revoke every local mandate matching the filters")
  .option("--sphere <sphere>", "Restrict --all to this sphere (public|circle|self)")
  .option("--agent <id>", "Restrict --all to mandates issued to this grantee id")
  .option("--include-expired", "With --all, also revoke already-expired mandates (bookkeeping)")
  .option("--yes", "Skip the confirmation preview on --all and revoke immediately")
  .option("--reason <reason>", "Short reason string", "user_request")
  .option("--handle <h>", "Issuing identity")
  .option("--json", "Output JSON")
  .action((mandateId, opts) => wrap(() => runRevoke({ mandateId, ...opts })));

program
  .command("verify")
  .description("Verify a mandate, revocation, or action artifact")
  .argument("<path>", "Path to a JSON document")
  .option("--did-document <path>", "Path to issuer's DID document (auto-discovered if omitted)")
  .option("--mandate <path>", "Companion mandate (for verifying action artifacts)")
  .option("--at <timestamp>", "RFC 3339 timestamp at which to evaluate (default: now)")
  .action((path, opts) => wrap(() => runVerify({ path, ...opts })));

program
  .command("rotate")
  .description("Rotate a sphere key (kill-switch — invalidates every mandate signed by the old key)")
  .requiredOption("--sphere <sphere>", "public | circle | self")
  .option("--reason <reason>", "Rotation reason", "user_request")
  .option("--handle <h>", "Identity handle")
  .option("--yes", "Proceed without the confirmation preview")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runRotate(opts)));

program
  .command("delegate-key")
  .description("Generate a fresh Ed25519 keypair for a write-mandate delegate")
  .requiredOption("--out <path>", "Path to write the keyfile (mode 0600)")
  .option("--id <urn>", "Agent identifier to embed in the keyfile (e.g. urn:aithos:agent:phone@pixel)")
  .option("--force", "Overwrite an existing keyfile")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runDelegateKey(opts)));

program
  .command("sign-action")
  .description("Emit (or counter-sign) an action artifact")
  .option("--mandate <id>", "Mandate id to sign under")
  .option("--mandate-path <path>", "Read mandate from path instead of ~/.aithos/mandates/")
  .option("--agent-key <path>", "Agent keyfile (JSON with seed_hex and id fields)")
  .option("--verb <scope>", "Action verb (must be in mandate.scopes)")
  .option("--target <path>", "JSON file describing the action target")
  .option("--content <path>", "File whose bytes are hashed into action.content_hash")
  .option("--summary <text>", "Short summary (≤ 280 chars)")
  .option("--out <path>", "Write the artifact to this file")
  .option("--counter-sign <path>", "Counter-sign an existing artifact at this path")
  .option("--handle <h>", "Subject identity (for counter-sign)")
  .option("--json", "When printing, emit raw JSON")
  .action((opts) => wrap(() => runSignAction(opts)));

program.parseAsync(process.argv).catch((e) => {
  console.error(`aithos: ${(e as Error).message}`);
  process.exit(1);
});

function wrap(fn: () => void | Promise<void>): void {
  Promise.resolve()
    .then(fn)
    .catch((e) => {
      console.error(`aithos: ${(e as Error).message}`);
      process.exit(1);
    });
}
