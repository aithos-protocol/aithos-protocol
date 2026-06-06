#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Aithos reference CLI entry point.
 *
 * The CLI is intentionally small. It covers exactly the primitives defined in
 * the v0.2.0 protocol:
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
import { runShowMandate } from "./commands/show-mandate.js";
import { runList, type ListKind } from "./commands/list.js";
import { runGrant } from "./commands/grant.js";
import { runRevoke } from "./commands/revoke.js";
import { runMandateAdd } from "./commands/mandate-add.js";
import { runVerify } from "./commands/verify.js";
import { runSignAction } from "./commands/sign-action.js";
import { runDelegateKey } from "./commands/delegate-key.js";
import { runRotate } from "./commands/rotate.js";
import { runEthosInit } from "./commands/ethos-init.js";
import { runEthosAddSection } from "./commands/ethos-add-section.js";
import { runEthosDeleteSection } from "./commands/ethos-delete-section.js";
import { runEthosModifySection } from "./commands/ethos-modify-section.js";
import { runEthosShow } from "./commands/ethos-show.js";
import { runEthosList } from "./commands/ethos-list.js";
import { runEthosVerify } from "./commands/ethos-verify.js";
import { runEthosPack, runEthosUnpack } from "./commands/ethos-pack.js";
import { runEthosInstall } from "./commands/ethos-install.js";
import { runEthosMigrateToV03 } from "./commands/ethos-migrate.js";
import { runGammaShow } from "./commands/gamma-show.js";
import { runGammaVerify } from "./commands/gamma-verify.js";

const program = new Command();

program
  .name("aithos")
  .description("Aithos reference CLI — identities, mandates, signatures.")
  .version("0.4.0");

program
  .command("init")
  .description(
    "Create a new Aithos identity (root + three sphere keys) and initialize its ethos",
  )
  .requiredOption("--handle <handle>", "Identity handle (a-z, 0-9, _, -)")
  .option("--display-name <name>", "Human-readable display name")
  .option("--force", "Overwrite an existing identity with the same handle")
  .option(
    "--no-ethos",
    "Skip ethos initialization (headless/service identities that only sign mandates)",
  )
  .action((o) => wrap(() => runInit(o)));

program
  .command("show")
  .description("Print identity metadata (DID, sphere keys, …)")
  .argument("[handle]", "Identity handle; defaults to the configured default")
  .option("--json", "Output JSON")
  .action((handle, opts) => wrap(() => runShow({ handle, json: opts.json })));

program
  .command("show-mandate")
  .description(
    "Pretty-print a mandate with its derived status (active | expired | revoked)",
  )
  .argument("<id>", "Mandate id (mandate_<ULID>)")
  .option("--json", "Output JSON")
  .action((id, opts) => wrap(() => runShowMandate({ id, json: opts.json })));

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

const mandate = program
  .command("mandate")
  .description("Manage mandates received from other identities");

mandate
  .command("add")
  .description("Import a mandate received out-of-band into the local keystore")
  .argument("<path>", "Path to a JSON mandate document")
  .option("--did <path>", "Issuer's DID document (auto-discovered if the issuer is installed locally)")
  .option("--allow-expired", "Add the mandate even if it is outside its validity window")
  .option("--force", "Overwrite an existing mandate at the same id")
  .option("--json", "Output JSON")
  .action((path, opts) =>
    wrap(() =>
      runMandateAdd({
        path,
        did: opts.did,
        allowExpired: opts.allowExpired,
        force: opts.force,
        json: opts.json,
      }),
    ),
  );

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

const ethos = program.command("ethos").description("Manage the live ethos document (public/circle/self)");

ethos
  .command("init")
  .description(
    "Initialize (or re-initialize with --force) the ethos layout for an existing identity. " +
      "Normally unnecessary — `aithos init` already does this. Use when attaching an ethos " +
      "to an identity that was created with --no-ethos, or to reset a corrupted ethos.",
  )
  .option("--handle <h>", "Identity handle (defaults to the configured default)")
  .option("--force", "Reset an existing ethos")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runEthosInit(opts)));

ethos
  .command("add-section")
  .description("Add a new section to a zone, with an initial revision")
  .requiredOption("--zone <zone>", "public | circle | self")
  .requiredOption("--title <title>", "Section title")
  .option("--body <markdown>", "Initial revision body (inline)")
  .option("--body-file <path>", "Read initial body from file")
  .option("--tags <list>", "Comma-separated tag list")
  .option("--mandate <id>", "Write mandate authorizing a delegate key")
  .option("--agent-key <path>", "Agent keyfile (required with --mandate)")
  .option("--handle <h>", "Identity handle")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runEthosAddSection(opts)));

ethos
  .command("delete-section")
  .description(
    "Remove a section from its zone. The live doc forgets it; the gamma " +
      "deep-memory log retains both the original add and a signed delete entry.",
  )
  .requiredOption("--zone <zone>", "public | circle | self")
  .requiredOption("--section <id>", "Section id (sec_<hex>)")
  .option("--reason <text>", "Free-text audit reason, stored in the gamma entry")
  .option("--mandate <id>", "Write mandate authorizing a delegate key")
  .option("--agent-key <path>", "Agent keyfile (required with --mandate)")
  .option("--handle <h>", "Identity handle")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runEthosDeleteSection({ zone: opts.zone, section: opts.section, reason: opts.reason, mandate: opts.mandate, agentKey: opts.agentKey, handle: opts.handle, json: opts.json })));

ethos
  .command("modify-section")
  .description(
    "Apply an in-place modification to an existing section. " +
      "Emits one signed section.modify entry in the gamma log carrying the " +
      "full new value of each changed field; the previous state remains in " +
      "the log as the audit trail (spec §10.6.1).",
  )
  .requiredOption("--zone <zone>", "public | circle | self")
  .requiredOption("--section <id>", "Section id (sec_<hex>)")
  .option("--title <title>", "New title (omit to keep)")
  .option("--body <markdown>", "New body, inline (omit to keep)")
  .option("--body-file <path>", "Read new body from file")
  .option("--tags <list>", "Comma-separated tag list (replaces existing tags)")
  .option("--clear-tags", "Remove all tags")
  .option("--mandate <id>", "Write mandate authorizing a delegate key")
  .option("--agent-key <path>", "Agent keyfile (required with --mandate)")
  .option("--handle <h>", "Identity handle")
  .option("--json", "Output JSON")
  .action((opts) =>
    wrap(() =>
      runEthosModifySection({
        zone: opts.zone,
        sectionId: opts.section,
        title: opts.title,
        body: opts.body,
        bodyFile: opts.bodyFile,
        tags: opts.tags,
        clearTags: opts.clearTags,
        mandate: opts.mandate,
        agentKey: opts.agentKey,
        handle: opts.handle,
        json: opts.json,
      }),
    ),
  );

ethos
  .command("show")
  .description(
    "Show manifest summary, or a zone/section's current content. " +
      "Section mutation history lives in the gamma log — see `aithos gamma show`. " +
      "On a tracked install, encrypted zones (circle | self) are readable via " +
      "a delegate mandate by passing --mandate <id> --agent-key <path>.",
  )
  .option("--zone <zone>", "public | circle | self")
  .option("--section <id>", "Section id")
  .option("--mandate <id>", "Delegate mandate (for reads of encrypted zones on tracked installs)")
  .option("--agent-key <path>", "Agent keyfile (required with --mandate)")
  .option("--handle <h>", "Identity handle")
  .option("--json", "Output JSON")
  .action((opts) =>
    wrap(() =>
      runEthosShow({
        handle: opts.handle,
        zone: opts.zone,
        section: opts.section,
        mandate: opts.mandate,
        agentKey: opts.agentKey,
        json: opts.json,
      }),
    ),
  );

ethos
  .command("list")
  .description("List sections across zones (or one zone with --zone)")
  .argument("[kind]", "Only 'sections' is supported in v0.1.0", "sections")
  .option("--zone <zone>", "Restrict to one zone")
  .option("--handle <h>", "Identity handle")
  .option("--json", "Output JSON")
  .action((_kind, opts) => wrap(() => runEthosList(opts)));

ethos
  .command("verify")
  .description("Verify an ethos: --handle for installed identity, --path for a bundle/dir")
  .option("--handle <h>", "Verify the installed identity in the keystore")
  .option("--path <p>", "Verify a bundle path (directory or .ethos zip) statelessly")
  .option("--no-decrypt", "Skip decrypting circle/self (verifies public + manifest only)")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runEthosVerify(opts)));

ethos
  .command("pack")
  .description("Pack the live ethos/ directory into a .ethos bundle (zip)")
  .option("--out <path>", "Output .ethos path (default: cwd / <handle>-<version>.ethos)")
  .option("--handle <h>", "Identity handle")
  .option("--no-readme", "Do not include the README.txt")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runEthosPack(opts)));

ethos
  .command("unpack")
  .description("Unpack a .ethos bundle into a directory")
  .argument("<path>", "Path to the .ethos bundle")
  .requiredOption("--out <dir>", "Output directory")
  .option("--json", "Output JSON")
  .action((path, opts) => wrap(() => runEthosUnpack({ path, out: opts.out, json: opts.json })));

ethos
  .command("migrate-to-v0.3")
  .description(
    "Migrate this identity's v0.2 ethos into a v0.3 per-section bundle (written to --out). " +
      "The keystore ethos stays v0.2 — v0.3 is opt-in until the format default flips.",
  )
  .option("--handle <h>", "Identity handle (defaults to the configured default)")
  .option("--out <dir>", "Output directory for the v0.3 bundle (default: cwd/<handle>-<version>-v0.3)")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runEthosMigrateToV03(opts)));

ethos
  .command("install")
  .description("Install a .ethos bundle into the keystore as a tracked identity")
  .argument("<path>", "Path to the .ethos bundle (file or directory)")
  .option("--as <handle>", "Install under this handle instead of the manifest's subject_handle")
  .option("--force", "Overwrite an existing tracked identity at the same handle")
  .option("--set-default", "Set this identity as the keystore default")
  .option("--json", "Output JSON")
  .action((path, opts) =>
    wrap(() =>
      runEthosInstall({
        path,
        as: opts.as,
        force: opts.force,
        setDefault: opts.setDefault,
        json: opts.json,
      }),
    ),
  );

/* -------------------------------------------------------------------------- */
/*  `aithos gamma …` — inspect and verify the deep-memory log                 */
/* -------------------------------------------------------------------------- */

const gamma = program.command("gamma").description("Inspect and verify the gamma deep-memory log");

gamma
  .command("show")
  .description(
    "Print the gamma log (one line per entry). Use --section to filter to " +
      "a single section's history, --id to show one entry in full, or --head " +
      "to print just the head hash and count. On a tracked install, pass " +
      "--mandate + --agent-key to read the log via a delegate mandate.",
  )
  .option("--section <id>", "Filter to entries touching this section id")
  .option("--id <gamma_id>", "Show a single entry in full")
  .option("--head", "Print only the current head hash and count")
  .option("--mandate <id>", "Delegate mandate (for gamma reads on tracked installs)")
  .option("--agent-key <path>", "Agent keyfile (required with --mandate)")
  .option("--handle <h>", "Identity handle")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runGammaShow(opts)));

gamma
  .command("verify")
  .description(
    "Verify hash integrity, chain linkage, signatures, and the manifest " +
      "anchor (manifest.gamma.head must equal the on-disk head). On a " +
      "tracked install, pass --mandate + --agent-key to verify via a " +
      "delegate mandate.",
  )
  .option("--mandate <id>", "Delegate mandate (for gamma verify on tracked installs)")
  .option("--agent-key <path>", "Agent keyfile (required with --mandate)")
  .option("--handle <h>", "Identity handle")
  .option("--json", "Output JSON")
  .action((opts) => wrap(() => runGammaVerify(opts)));

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
