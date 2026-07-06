#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Mock "hand" downstream — the verifier half of the Mandated Intent Envelope
 * pattern (SPEC-mandated-intent-envelope 0.1.0, Annex A), standing in for the
 * real browser-agent so the whole loop is testable without Chrome or the
 * parallel dev.
 *
 * On `run_action { envelope, action, params }` it does what the real hand must:
 *   - re-verify the Mandated Intent Envelope with the REAL §5 verifier
 *     (`verifyEnvelope`): delegate signature, mandate window/revocation,
 *     audience, method = the claimed action id, and params bound by hash;
 *   - only on success "execute" the action (mock: echo the validated params +
 *     a fake observation) and return a run_report;
 *   - otherwise return run_stopped — it never trusts unverified intent.
 *
 * The agent's parameters were already validated against the SIGNED schema at
 * the gateway; the envelope's params_hash proves they reach here untampered.
 *
 * Transport: this mock speaks plain HTTP (`POST /run_action`) for simplicity and
 * zero dependencies. The real browser-agent binding sends the same `run_action`
 * message over its existing WebSocket (`/ws`); the envelope verification is
 * identical — the transport is a swap, the security is not.
 */
import http from "node:http";
import { readFileSync } from "node:fs";

let core;
try {
  core = await import("@aithos/protocol-core");
} catch {
  core = await import("../../../packages/protocol-core/dist/index.js");
}
const { verifyEnvelope } = core;

/** In-memory replay cache (a plain Set) — §11.5. */
function makeReplay() {
  const seen = new Set();
  return {
    async putIfAbsent(key) {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
}

/**
 * Build the mock. `ownerDidDoc` is the owner's DID document (to verify the
 * delegate signature chain); `aud` is this hand's audience identifier (must
 * match what the gateway signed into the envelope).
 */
export function createMockBrowserAgent({ ownerDidDoc, aud, log = () => {} }) {
  const replay = makeReplay();
  const emit = (o) => log(JSON.stringify({ kind: "aithos.mock-hand", ...o }));

  /** The core of the pattern: verify an action envelope, then (mock) execute. */
  async function runAction({ envelope, action, params }) {
    if (!envelope || !action || typeof action.id !== "string") {
      return { type: "run_stopped", ok: false, error: "malformed run_action request" };
    }
    const res = await verifyEnvelope(envelope, {
      expectedAud: aud,
      expectedMethod: action.id, // the envelope MUST be for the claimed action
      params, // params_hash must match → params are untampered
      nowSeconds: Math.floor(Date.now() / 1000),
      resolveIssuerDoc: async (iss) =>
        ownerDidDoc && iss === ownerDidDoc.id ? ownerDidDoc : null,
      replay,
    });
    if (!res.ok) {
      emit({ event: "reject", action: action.id, error: res.error?.message });
      return { type: "run_stopped", ok: false, error: res.error?.message ?? "envelope rejected" };
    }
    // Verified. A real hand would run the guarded runner here; the mock echoes
    // the validated params + a fake observation, attributed to the mandate.
    emit({ event: "run", action: action.id, mandate: res.mandateId });
    return {
      type: "run_report",
      ok: true,
      action: action.id,
      mandate_id: res.mandateId,
      observed: params,
      result: `mock-executed ${action.id}`,
    };
  }

  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, name: "mock-browser-agent" }));
      return;
    }
    if (req.method !== "POST" || req.url !== "/run_action") {
      res.writeHead(404);
      res.end();
      return;
    }
    const chunks = [];
    for await (const c of req) chunks.push(c);
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ type: "run_stopped", ok: false, error: "invalid json" }));
      return;
    }
    const report = await runAction(body);
    res.writeHead(report.ok ? 200 : 422, { "content-type": "application/json" });
    res.end(JSON.stringify(report));
  });

  return { server, runAction };
}

/* --------------------------------- main ---------------------------------- */

const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const aud = process.env.AITHOS_HAND_AUD ?? "urn:aithos:downstream:browser-agent";
  const didPath = process.env.AITHOS_OWNER_DID_DOC; // path to the DID document JSON
  const ownerDidDoc = didPath ? JSON.parse(readFileSync(didPath, "utf8")) : null;
  const port = Number(process.env.PORT ?? 8799);
  const { server } = createMockBrowserAgent({
    ownerDidDoc,
    aud,
    log: (l) => console.log(l),
  });
  server.listen(port, "0.0.0.0", () =>
    console.log(JSON.stringify({ kind: "aithos.mock-hand", event: "listening", port, aud })),
  );
  const stop = () => server.close(() => process.exit(0));
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
