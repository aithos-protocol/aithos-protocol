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
