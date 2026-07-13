# Releasing Mini-Ops

Mini-Ops is distributed as a GitHub source/binary release. The Rust crate and
embedded frontend are not published independently to crates.io or npm because
the supported deployable unit also includes scripts, the systemd unit,
configuration examples, and operational documentation.

## Release contract

- Rust `1.93.0`, Node.js `24.17.0`, and npm `12.0.1` are pinned in the
  repository and CI.
- `Cargo.toml`, `frontend/package.json`, and a `vX.Y.Z` tag must have the
  same version.
- CI must pass Rust tests/fmt/clippy/audit, frontend lint/build/audit, and shell
  contract fixtures.
- The tag workflow builds on Ubuntu 22.04 and publishes a Linux x86-64 archive,
  `SHA256SUMS`, an SPDX JSON SBOM, build provenance, and an SBOM attestation.
- Release archives are assembled only from tracked files plus the verified
  binary. Local planning files, environment files, tokens, databases, and
  other untracked state are never included.

## Prepare a release

1. Complete the release audit and resolve every blocker.
2. Update Rust and frontend versions together in an explicit version task.
3. Review the exact diff and run the local CI-equivalent checks.
4. Commit and push the release-ready tree.
5. Create and push the matching signed or annotated `vX.Y.Z` tag.

Pushing the tag starts `.github/workflows/release.yml`. Do not manually replace
assets under an existing tag. Prefer immutable GitHub Releases when the
repository setting is available.

## Verify a downloaded release

Download the archive, SPDX SBOM, and `SHA256SUMS` from the same GitHub Release:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify mini-ops-vX.Y.Z-linux-x86_64.tar.gz \
  --repo rg-onion/mini-ops
```

Extract the archive and start with the non-mutating deploy plan:

```bash
tar -xzf mini-ops-vX.Y.Z-linux-x86_64.tar.gz
cd mini-ops-vX.Y.Z-linux-x86_64
DEPLOY_HOST=server.example \
  DEPLOY_DRY_RUN=1 \
  DEPLOY_RUN_LOCAL_BUILD=0 \
  ./scripts/bootstrap_server.sh
```

Read `docs/DEPLOY.md` before authorizing any remote mutation.
