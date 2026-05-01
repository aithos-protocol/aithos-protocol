// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * `aithos sign-action` — emit a signed action artifact under a mandate.
 *
 * This command is intended for BOTH sides:
 *   - as the AGENT, to produce and sign the artifact using the agent's own key,
 *   - as the SUBJECT, to attach a counter-signature on a binding action.
 *
 * Typical flow for a non-binding reply:
 *
 *   aithos sign-action \
 *     --mandate mandate_01JG… \
 *     --agent-key /opt/gmail-agent/etc/agent.ed25519.seed \
 *     --verb email.reply \
 *     --target target.json \
 *     --content email-body.txt \
 *     --summary "Confirmed availability for Tuesday afternoon." \
 *     --out action.json
 *
 * For a binding action, the agent emits a draft (without counter-signature),
 * the subject runs:
 *
 *   aithos sign-action --counter-sign action.json --out action.signed.json
 */

import { readFileSync, writeFileSync } from "node:fs";
import {
  loadMandate,
  signActionArtifact,
  counterSignAction,
  type ActionArtifact,
  loadIdentity,
  loadConfig,
} from "@aithos/protocol-core";

export interface SignActionOpts {
  mandateId?: string;
  mandatePath?: string;
  agentKey?: string;
  verb?: string;
  target?: string;
  content?: string;
  summary?: string;
  out?: string;
  counterSign?: string; // path to an action artifact to counter-sign
  handle?: string; // subject handle for counter-signing
  json?: boolean;
}

export function runSignAction(opts: SignActionOpts): void {
  // Counter-sign path
  if (opts.counterSign) {
    const artifact = JSON.parse(readFileSync(opts.counterSign, "utf8")) as ActionArtifact;
    const mandate = opts.mandatePath
      ? JSON.parse(readFileSync(opts.mandatePath, "utf8"))
      : loadMandate(artifact.mandate_id);

    const config = loadConfig();
    const handle = opts.handle ?? config.default_handle;
    if (!handle) throw new Error("No identity selected for counter-signing.");
    const subject = loadIdentity(handle);

    const signed = counterSignAction(artifact, subject, mandate);
    const outText = JSON.stringify(signed, null, 2) + "\n";
    if (opts.out) writeFileSync(opts.out, outText);
    else process.stdout.write(outText);
    if (!opts.out) return;
    console.error(`Counter-signed ${artifact.id} → ${opts.out}`);
    return;
  }

  // Fresh-signing path
  if (!opts.agentKey) throw new Error("--agent-key <path> is required");
  if (!opts.verb) throw new Error("--verb is required");
  if (!opts.target) throw new Error("--target <path-to-json> is required");
  if (!opts.content) throw new Error("--content <path> is required (body to hash)");
  if (!opts.summary) throw new Error("--summary <text> is required");

  const mandate = opts.mandatePath
    ? JSON.parse(readFileSync(opts.mandatePath, "utf8"))
    : opts.mandateId
      ? loadMandate(opts.mandateId)
      : (() => {
          throw new Error("Pass --mandate <id> or --mandate-path <path>");
        })();

  const agentKeyFile = JSON.parse(readFileSync(opts.agentKey, "utf8"));
  const agentSeed = Uint8Array.from(Buffer.from(agentKeyFile.seed_hex, "hex"));
  if (agentSeed.byteLength !== 32) {
    throw new Error(`Agent key seed must be 32 bytes; got ${agentSeed.byteLength}`);
  }
  const agentId = agentKeyFile.id ?? mandate.grantee.id;

  const target = JSON.parse(readFileSync(opts.target, "utf8"));
  const contentBytes = readFileSync(opts.content);

  const artifact = signActionArtifact({
    mandate,
    agentSeed,
    agentId,
    verb: opts.verb,
    target,
    contentBytes: new Uint8Array(contentBytes),
    summary: opts.summary,
  });

  const outText = JSON.stringify(artifact, null, 2) + "\n";
  if (opts.out) {
    writeFileSync(opts.out, outText);
    console.error(`Wrote ${artifact.id} → ${opts.out}`);
  } else if (opts.json) {
    process.stdout.write(outText);
  } else {
    console.log(`Emitted ${artifact.id}`);
    console.log(`  Mandate:  ${artifact.mandate_id}`);
    console.log(`  Verb:     ${artifact.action.verb}`);
    console.log(`  Summary:  ${artifact.action.summary}`);
    console.log(`  Content hash: ${artifact.action.content_hash}`);
    console.log(`(pass --out <path> to write the artifact to a file; pass --json to print)`);
  }
}
