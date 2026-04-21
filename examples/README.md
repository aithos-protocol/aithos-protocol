# Examples

These JSON files illustrate the shape of the normative Aithos documents. They are **not** valid signatures — the `value` fields are placeholders. To generate real, signed examples on your machine, run the CLI (`cli/README.md`) against a fresh identity.

| File | Spec reference | What it shows |
|---|---|---|
| `mandate-circle-email.json` | §4.2 | Read + email-reply mandate, circle sphere, 7-day TTL. |
| `mandate-write-circle.json` | §4.5.4 | Write mandate with a delegate key bound via `grantee.pubkey`, 90-day TTL, section and rate-limit constraints. |
| `revocation.json` | §4.6 | Revocation of the write mandate, signed by the same sphere key that issued it. |
| `action-email-reply.json` | §5.4 | Action artifact emitted after an email reply. Signed by the agent's own key. |

To regenerate with real signatures:

```bash
cd ../cli
npm install && npm run build
node dist/index.js init --handle example --display-name "Example User"
node dist/index.js grant urn:aithos:agent:demo@localhost \
  --sphere circle \
  --scope ethos.read.public,ethos.read.circle,email.reply \
  --ttl 7d \
  --json \
  > signed-mandate.json
```

## Scripts

| Script | What it does |
|---|---|
| `smoke-test.sh` | End-to-end CLI walkthrough for the v0.1.0 happy/unhappy paths (init → add-section × 3 → add-revision → verify → tamper → verify fails → restore → pack/unpack). |
| `gamma-smoke-test.sh` | End-to-end walkthrough for the gamma deep-memory log: reproduces the `spec/drafts/gamma-deep-memory.md §D.7` worked example (init → add self → gamma show → delete with reason → self is empty but gamma keeps both entries → tamper with the encrypted log → gamma verify fails → restore → pass). Run after `npm run build` from the repo root. |
