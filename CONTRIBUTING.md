# Contributing to Aithos Protocol

Thank you for considering a contribution. Please read the following before opening
a pull request.

## Code of conduct

Be respectful, focused, and concise. Disagreement is welcome; hostility is not. If
you would not say it in a small in-person meeting with the people involved, do not
say it here.

## How to contribute

1. **Open an issue first** for non-trivial changes — bugs, design proposals, breaking
   changes to the wire format, or new spec chapters. Drive-by PRs that aren't tied to
   a discussed issue may be closed without review.
2. **Branch off `main`** with a descriptive name (`fix/...`, `feat/...`, `docs/...`,
   `spec/...`).
3. **Keep PRs focused.** One concern per PR; if you find unrelated cleanup along the
   way, open a separate PR for it.
4. **Run the tests** before pushing: `npm test` at the root or per-package.
5. **Sign the CLA** when prompted by the bot on your first PR (see below).

## Contributor License Agreement (CLA)

External contributions are accepted under a **Contributor License Agreement** that
grants the project the right to relicense future versions. The mechanics:

- On your first PR, [@cla-assistant] (a GitHub bot) will post a comment with a link
  to sign the CLA. Signing takes ~30 seconds — you click "I have read the CLA
  Document and I hereby sign the CLA" in the PR comment thread.
- Once signed, the bot remembers you across all future PRs to this repository.
- You retain full copyright on your contribution. The CLA grants the maintainers
  a broad license — including the right to relicense future major versions —
  without taking your copyright away.

The CLA text lives at [`CLA.md`](./CLA.md). It is adapted from the Apache Software
Foundation's Individual Contributor License Agreement (ICLA), which is the most
widely used template in the open-source world.

### Why a CLA?

The `0.x` line of this protocol is and will remain under Apache-2.0 forever — that
grant is irrevocable. However, future major versions (`1.0+`) may transition to a
different license at the maintainers' discretion (see ADR-0007 in
[`ARCHITECTURE-DECISIONS.md`](./ARCHITECTURE-DECISIONS.md)). Without a CLA, the
maintainers could not relicense your contributions even if doing so were necessary
to sustain the project. The CLA preserves that flexibility while keeping every
published release fully open-source for its lifetime.

If signing a CLA is a hard no for you, that's a legitimate position — many
seasoned contributors decline CLA-gated projects on principle. We are sorry to
miss your contribution; the spec itself (under CC BY 4.0) remains free to fork
and reimplement without any agreement.

## Style and conventions

- **Source headers**: every `.ts` / `.mjs` source file must start with the two-line
  SPDX header:

  ```
  // SPDX-License-Identifier: Apache-2.0
  // Copyright <year> <Your Name>
  ```

  Existing files use `2026 Mathieu Colla`. New files added by external contributors
  may use the contributor's name and year — both forms are valid under Apache-2.0.

- **Commit messages**: imperative present tense, English, scoped prefix:
  `feat(cli):`, `fix(mcp):`, `docs(spec):`, `chore:`, `test:`, `refactor:`.

- **Documentation language**: English for public-facing docs (`README.md`, spec
  chapters, package READMEs). Internal notes and ADRs may be French.

## Releasing (maintainers only)

See `ARCHITECTURE-DECISIONS.md` for the licensing baseline. Each package ships its
own `LICENSE` file (Apache-2.0); when bumping a major version, that license may
change — at which point this contributing guide will be updated to reflect the new
terms for the new line. Past releases remain under their published license.

[@cla-assistant]: https://cla-assistant.io
