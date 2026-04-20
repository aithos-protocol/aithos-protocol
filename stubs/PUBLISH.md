# Publishing the Aithos name-reservation stubs

Three stubs have been prepared and tested:

| Ecosystem | Path | Name | Validation |
|---|---|---|---|
| PyPI | `stubs/aithos-py/` | `aithos` | `python3 -m build` produces a valid wheel containing `aithos/birth/*` |
| crates.io | `stubs/aithos-rs/` | `aithos` | `cargo test` passes 6/6, `cargo package` produces a valid `.crate` with `birth/*` included |
| Go (proxy.golang.org) | `stubs/aithos-go/` | `github.com/aithos-protocol/aithos` | `go test` passes 6/6, `go vet` clean, `birth/` is `//go:embed`-ded |

All three carry the same signed birth artifacts:
- `birth.json` — protocol-native birth record
- `birth-declaration.md` — human-readable text
- `aithos-birth.ethos` — signed ethos bundle (verifiable with the TypeScript CLI)
- `did.json` — DID document for `did:aithos:z6Mkeu1UTXwL4djF9JmH5idEAF5t7g3bHjvJTBGeWqX5qPpA`

---

## Prerequisites

1. **GitHub org `aithos-protocol`** — create it before anything else. <https://github.com/organizations/plan>
2. **Three GitHub repos** under that org:
   - `aithos-protocol/aithos-protocol` — the current repo (spec, whitepaper, TS CLI)
   - `aithos-protocol/aithos-py` — the Python stub (optional: can be a subdir of the main repo; a separate repo is cleaner)
   - `aithos-protocol/aithos-rs` — the Rust stub (same note)
   - `aithos-protocol/aithos` — the Go stub — **this one must be its own repo**, because the Go import path *is* the repo URL.
3. **Registry accounts + API tokens**:
   - PyPI: <https://pypi.org/manage/account/token/>
   - crates.io: <https://crates.io/me> → API Tokens
4. **Build tooling on your machine** — `python3 -m pip install build twine hatch`, Rust via `rustup`, Go 1.22+, git.

---

## Step 1 — Python (PyPI)

```bash
cd stubs/aithos-py

# Build
python3 -m build         # → dist/aithos-0.0.1.tar.gz + dist/aithos-0.0.1-py3-none-any.whl

# Sanity check
python3 -m pip install dist/aithos-0.0.1-py3-none-any.whl
python3 -c "import aithos; print(aithos.PROTOCOL_VERSION, aithos.BIRTH_DIR)"
# Should print: 0.1.0 /.../site-packages/aithos/birth

# Upload
python3 -m twine upload dist/*
# Prompts for: API token (paste the pypi- prefixed token; username is __token__)
```

After upload, verify at <https://pypi.org/project/aithos/>.

**Modern alternative (recommended for ongoing releases):** configure *Trusted Publishers* on PyPI linked to the GitHub repo, then publish via a GitHub Actions workflow with no long-lived tokens. <https://docs.pypi.org/trusted-publishers/>

---

## Step 2 — Rust (crates.io)

```bash
cd stubs/aithos-rs

# Sanity check
cargo test                # must be 5/5 passed + 1 doctest passed
cargo package             # produces target/package/aithos-0.0.1.crate and dry-runs the verify

# Log in once (stored in ~/.cargo/credentials.toml)
cargo login <paste-token-from-crates.io/me>

# Publish
cargo publish
```

After upload, verify at <https://crates.io/crates/aithos>.

**crates.io note**: once published, a version is *immutable* — you cannot re-publish `0.0.1`. If you need to change anything, publish `0.0.2`. Crates can be `cargo yank`-ed (prevents new downloads) but not deleted.

---

## Step 3 — Go (proxy.golang.org)

Go has no central registry; a module is "registered" the first time proxy.golang.org successfully caches it from your VCS. You need a real GitHub repo at the import path.

```bash
# 1. Create the repo github.com/aithos-protocol/aithos (empty, main branch)

# 2. From the stub directory
cd stubs/aithos-go
git init
git add .
git commit -m "Initial placeholder — reserve github.com/aithos-protocol/aithos on 2026-04-19"
git branch -M main
git remote add origin git@github.com:aithos-protocol/aithos.git
git push -u origin main

# 3. Tag and push the tag — this is what proxy.golang.org watches
git tag v0.0.1
git push origin v0.0.1

# 4. Trigger proxy cache (from anywhere with Go installed)
GOPROXY=proxy.golang.org go get github.com/aithos-protocol/aithos@v0.0.1
```

After that, <https://pkg.go.dev/github.com/aithos-protocol/aithos> should render the package page within a few minutes.

---

## Step 4 — Set up the two other repos and the GitHub org

```bash
# Main protocol repo (this one) gets a remote
cd /sessions/gallant-magical-wright/mnt/Aithos-protocol
git remote add origin git@github.com:aithos-protocol/aithos-protocol.git
git push -u origin main

# Python stub repo (optional — only if you want separate repos)
cd stubs/aithos-py
git init && git add . && git commit -m "Initial placeholder — reserve aithos on PyPI on 2026-04-19"
git branch -M main
git remote add origin git@github.com:aithos-protocol/aithos-py.git
git push -u origin main
git tag v0.0.1 && git push origin v0.0.1

# Rust stub repo (same)
cd ../aithos-rs
git init && git add . && git commit -m "Initial placeholder — reserve aithos on crates.io on 2026-04-19"
git branch -M main
git remote add origin git@github.com:aithos-protocol/aithos-rs.git
git push -u origin main
git tag v0.0.1 && git push origin v0.0.1
```

---

## Verification checklist (after all uploads)

- [ ] <https://pypi.org/project/aithos/> shows version 0.0.1, 2026-04-19, your author block
- [ ] <https://crates.io/crates/aithos> shows version 0.0.1, Apache-2.0, links to the repo
- [ ] <https://pkg.go.dev/github.com/aithos-protocol/aithos> renders the package page with `ProtocolVersion`, `BirthFS`, etc.
- [ ] <https://www.npmjs.com/package/aithos> (already yours)
- [ ] `pip install aithos` then `python3 -c "import aithos; print(aithos.PROTOCOL_VERSION)"` prints `0.1.0`
- [ ] `cargo add aithos` in a scratch project, then build — nothing breaks
- [ ] `go get github.com/aithos-protocol/aithos@latest` in a scratch Go module works

## Verifying the birth bundle itself (from any stub's `birth/` directory)

Once the TypeScript CLI is installed (`npm install -g aithos` — assuming that's published from `cli/` too), anyone can do:

```bash
mkdir -p /tmp/aithos-verify
AITHOS_HOME=/tmp/aithos-verify aithos ethos unpack ./birth/aithos-birth.ethos --out /tmp/aithos-verify/unpacked
# Inspect /tmp/aithos-verify/unpacked/manifest.json — Ed25519 signatures over the three zones
```

The `.ethos` bundle is self-contained: its `did.json` contains the public keys; its `signatures/` directory contains the zone and revision signatures; its `manifest.json` records per-zone plaintext hashes. Anyone with the TypeScript CLI can re-verify it decades from now.

---

## Known bug surfaced by this ceremony

While preparing the birth declaration, I hit a real bug in the TypeScript CLI:
- `src/ethos.ts:336` splits section chunks on `/(?=^# )/m`.
- If a revision body contains a line starting with `# ` (an H1 heading), the parser treats it as a second section, breaking the round-trip and causing `sha256_of_plaintext mismatch` on verify.
- Workaround used here: do not start revision bodies with `# `; use `## ` or higher, or plain paragraphs.
- Suggested fix for v0.1.1: either delimit sections with a sentinel HTML comment (`<!-- section-break -->`) instead of raw `# `, or require the `<!-- sec_... -->` marker comment on the same line as the splitter (the regex already matches that shape on line 338 — just move the split boundary to the same regex).

Worth a follow-up commit.
