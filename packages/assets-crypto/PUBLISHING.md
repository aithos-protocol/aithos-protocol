# Publishing `@aithos/assets-crypto`

This package is part of the Aithos protocol monorepo (npm workspaces).
Releases are independent — bump this package's version without
touching `data-crypto` or `protocol-core`.

## Pre-flight

From the **package root** (`packages/assets-crypto`):

```sh
npm run check-types
npm test
npm run build
```

All three must be green.

## Bump version

```sh
# pick one
npm version prerelease --preid=alpha     # 0.1.0-alpha.1 → 0.1.0-alpha.2
npm version patch                         # 0.1.0-alpha.N → 0.1.0
npm version minor                         # 0.1.0 → 0.2.0
```

Then add a `[x.y.z] — yyyy-mm-dd` heading to `CHANGELOG.md` mirroring
the new version. Move items from the `[Unreleased]` section under it.

## Dry-run

From the package root:

```sh
npm pack --dry-run
```

Verify the tarball contains exactly:

- `dist/` (compiled JS + .d.ts files)
- `README.md`
- `LICENSE`
- `package.json`

NOT in the tarball (filtered by `.npmignore`):
- `src/`
- `test/`
- `tsconfig.json`
- `node_modules/`

## Publish

```sh
npm publish --access public --tag alpha
```

The `--tag alpha` keeps the alpha line out of the `latest` channel so
consumers who do not opt in to alpha don't get it by default. Once the
package reaches `0.1.0` stable, drop `--tag alpha` and the install
becomes `@aithos/assets-crypto@latest`.

## Post-publish

Tag the git commit:

```sh
git tag assets-crypto-X.Y.Z
git push origin assets-crypto-X.Y.Z
```

GitHub release notes lifted verbatim from the matching `CHANGELOG.md`
section. The repo uses git tags as the GitHub Release source of truth.
