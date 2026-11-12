# Releasing

A release is one tag. `dev/release.sh` prepares it locally; `.github/workflows/release.yml`
builds and publishes everything after a maintainer approves.

## Cutting a release

1. Make sure `CHANGELOG.md` has entries under `## [Unreleased]`. Contributors add them in their
   pull requests.
2. On an up-to-date, clean `main`:

   ```sh
   dev/release.sh 0.0.2
   ```

   This bumps the workspace version and the internal `=X.Y.Z` pins, turns `[Unreleased]` into
   `[0.0.2] - <today>`, runs fmt, clippy, the tests and `cargo publish --dry-run`, then commits
   `Release 0.0.2` and creates the annotated tag `v0.0.2`. It pushes nothing.
3. Review the commit (`git show`), then push both:

   ```sh
   git push origin main v0.0.2
   ```

4. The **release** workflow starts. `verify` and `build` run on their own. `publish` waits for
   approval: open the run under Actions and click **Review deployments → release → Approve**.
   Check that `verify` and `build` are green first.

## What the workflow does

| Job | What | Notes |
|---|---|---|
| `verify` | tag = crate version, tag is on `main`, changelog section exists, fmt, clippy, tests, `cargo publish --dry-run` | |
| `build` | static musl binaries for x86_64 (`ubuntu-latest`) and aarch64 (`ubuntu-24.04-arm`), checks they are static and print the right version, runs the sandbox tests against them, packs `cant-vX-TARGET.tar.gz` | `packaging/tarball.sh` |
| `publish` | environment `release`, after approval | steps below, in order |

`publish` steps:

1. Build `.deb` and `.rpm` packages (`packaging/packages.sh`), sign the `.rpm` files, write
   `SHA256SUMS` and its signature `SHA256SUMS.asc`.
2. **crates.io**: publish the five crates in dependency order via Trusted Publishing (no stored
   token). Versions already on crates.io are skipped.
3. **GitHub release** with the tarballs, packages and checksums; notes from the changelog.
   A version with a `-` (e.g. `0.1.0-rc.1`) is marked as a pre-release.
4. **APT and RPM repositories**: `packaging/update-repos.sh` adds the packages to
   [cantainer/packages](https://github.com/cantainer/packages), regenerates and signs the
   metadata, and pushes; GitHub Pages serves it at <https://cantainer.github.io/packages/>.
5. **Homebrew**: `packaging/homebrew.sh` writes `Formula/cantainer.rb` in
   [cantainer/homebrew-tap](https://github.com/cantainer/homebrew-tap).
6. **AUR**: `packaging/aur.sh` updates `cantainer-bin`. Skipped with a notice while
   `AUR_SSH_KEY` is unset.

Steps 4–6 are skipped for pre-releases. Every step skips or replaces what already exists, so
after a failure fix the cause and click **Re-run failed jobs**.

## One-time setup (done 2026-11-12)

| Where | What |
|---|---|
| GitHub → Settings → Environments → `release` | required reviewer: the maintainer; deployment tags: `v*` |
| crates.io → each of the five crates → Settings → Trusted Publishing | GitHub: `cantainer/cantainer`, workflow `release.yml`, environment `release` |
| `release` environment secret `PACKAGE_SIGNING_KEY` | private half of `packaging/signing-key.asc` (armored) |
| `release` environment secret `HOMEBREW_TAP_DEPLOY_KEY` | SSH deploy key with write access to `cantainer/homebrew-tap` |
| `release` environment secret `PACKAGES_DEPLOY_KEY` | SSH deploy key with write access to `cantainer/packages` |
| `cantainer/packages` → Settings → Pages | deploy from branch `main`, `/` |
| `release` environment secret `AUR_SSH_KEY` | **not set yet**: AUR registration was closed on 2026-11-12 |

Secrets live on the environment, not the repository, so only approved release runs can read them.

### AUR, once registration reopens

1. Register at <https://aur.archlinux.org/register>.
2. `ssh-keygen -t ed25519 -N '' -C 'cantainer release -> aur' -f aur_key`
3. Paste `aur_key.pub` into the account's **SSH Public Key** field.
4. Add the contents of `aur_key` as the `release` environment secret `AUR_SSH_KEY`, then delete
   both files.
5. Re-run the latest release's `publish` job, or wait for the next release. The first push
   creates the `cantainer-bin` package.

## The package signing key

- Fingerprint `93B1 11A2 5A48 73A3 2AFA  EF6D DEC0 3DB8 3F0D 540B`, RSA 4096 (RHEL 8's `rpm`
  can't verify Ed25519), created 2026-11-12, **expires 2029-11-11**.
- Public half: `packaging/signing-key.asc`, also published at
  <https://cantainer.github.io/packages/signing-key.asc>. The workflow refuses a secret key with
  a different fingerprint (`SIGNING_KEY_FPR` in `release.yml`).
- Private half: the `PACKAGE_SIGNING_KEY` secret and the maintainer's password manager.

**Before it expires** (or if it leaks): extend the expiry with `gpg --quick-set-expire` and
publish the updated public key; users who re-import it keep working. On a leak, generate a new
key, replace `packaging/signing-key.asc`, `SIGNING_KEY_FPR` and the secret, re-sign the
repositories with a release, and announce it in the changelog under **Security**.

## Tools

Packages are built with `dpkg-deb`, `rpmbuild`/`rpmsign`, `apt-ftparchive` and `createrepo_c`
from Ubuntu's archive; no packaging tool is downloaded. To try the packaging locally:

```sh
cargo build --release --target x86_64-unknown-linux-musl
packaging/tarball.sh 0.0.0 x86_64-unknown-linux-musl target/x86_64-unknown-linux-musl/release/cant /tmp/dist
packaging/tarball.sh 0.0.0 aarch64-unknown-linux-musl target/x86_64-unknown-linux-musl/release/cant /tmp/dist  # stand-in
packaging/packages.sh 0.0.0 /tmp/dist
```
