# Cans: design

**Status:** design only, nothing here is implemented. Written 2026-11-16 for review. The file
format lives in its own versioned document, [spec/can-format.md](../spec/can-format.md).

A **can** is a redistributable cant: one executable, its dependency closure and its manifest,
packed as a signed OCI artifact. `cant pack git` makes one, `cant run ghcr.io/acme/git:2.47
status` runs one.

## 0. Positioning, and three decisions

Cans are **signed tools with permission labels, built for agents**. They are not "Docker for
binaries" and not another package manager. Getting a binary onto a machine is a solved problem.
What is new is that **what the tool may do travels with it**, as a label the kernel enforces and
that a person, an agent or a company policy can read *before* the tool runs.

The first target is MCP servers: today an agent installs them with `npx`/`uvx`, unsigned, and they
run with the user's full rights.

Research for this document turned up three findings that changed the plan. The maintainer
decided them on 2026-11-16:

| | Decision |
|---|---|
| **A** Host allowlist | **Backlog.** 0.1.0 has no host enforcement. The `network = { allow = [...] }` field stays in the spec, and `cant` shows, records and approves it as **unrestricted network** until enforcement exists ([spec §8](../spec/can-format.md#8-honest-labels)). The netns + proxy design in §7.3 waits in the backlog. |
| **B** MCP servers | **Go servers first** (static binaries), then one Node server, then Python as time allows. Node and Python trees use **per-package bundles** ([spec §4.3](../spec/can-format.md#43-bundles)), so a package version shared by several servers is one blob. Shared base cans (a signed `node-22` can that servers build on) are backlogged. |
| **C** `/proc/self/exe` | **Document in v1, fix in v2** with mount namespaces. |

The analysis behind each decision follows.

### Decision A: the host allowlist cannot be enforced with Landlock and seccomp

The launch demo says a server "reaches only `api.github.com`". **That is not enforceable with the
mechanisms Cantainer uses today.**

| Mechanism | Can it limit a can to one host? |
|---|---|
| Landlock network rules (TCP since ABI 4, UDP since ABI 10) | **No.** They filter local/remote **port numbers**, never addresses ([kernel docs](https://docs.kernel.org/userspace-api/landlock.html)). "Port 443" means every host's port 443. |
| seccomp | **No.** The destination is in a `sockaddr` the kernel reads from user memory; a BPF filter can't dereference pointers. |
| `HTTPS_PROXY` in the environment | **No.** Advisory. A hostile program ignores it. |
| A proxy on a loopback port, with Landlock allowing only that port | **No.** The rule allows the port on *any* address, so the program can connect to any remote host that listens on it. |
| seccomp user notification (a helper decides each `connect`) | Possible, but the helper must perform the connect and inject the descriptor (`SECCOMP_IOCTL_NOTIF_ADDFD`) to avoid a time-of-check race on the address. Complex, and a new supervisor. |
| **A network namespace with only loopback, and a filtering proxy outside** | **Yes.** This is what other sandboxes do. It needs user namespaces. |

Options:

1. **Netns + proxy (recommended for 0.2.0).** For cans with `network.allow`, `cant` creates a
   user+network namespace (no route out, `lo` only), and a sidecar `cant proxy` process, started
   before `exec`, listens inside that namespace and forwards `CONNECT host:port` requests that
   match the allowlist. The proxy resolves names itself (the can has no DNS), refuses loopback,
   private and link-local addresses, and the can gets `HTTPS_PROXY`. §7.3 has the design.
   Cost: user namespaces (restricted by default on Ubuntu 24.04, where the `.deb` would ship an
   AppArmor profile, as other tools that use user namespaces do; to be verified), a sidecar process, and a reversal of the
   "no namespaces" decision for this one capability.
2. **Ship 0.1.0 without enforcement, and say so.** The label format already has
   `network = { allow = [...] }` ([spec §8](../spec/can-format.md#8-honest-labels)). A runtime
   that can't enforce it shows and records **unrestricted network**, so `--approve-if-within`
   policies treat it as such. The MCP demo then shows what is enforced: `~/.ssh` denied, no other
   file access, network `any host` stated plainly. No dishonest label, no namespaces yet.

**Decided: option 2; option 1 goes to the backlog.** The demo claim becomes "can't read
`~/.ssh`, can't touch your files, and its network access is on the label", which is true.

### Decision B: Node and Python servers are heavier than the example suggests

GitHub's own MCP server is a **static Go binary** (MIT): one file, no closure, an ideal first can.
The reference servers (`@modelcontextprotocol/server-*`, `mcp-server-git`, `mcp-server-fetch`)
are Node or Python. Packing those means bundling the interpreter's closure *and* a tree with
thousands of small files (`node_modules`, `site-packages`) plus native extensions found only by
`dlopen`. The format handles it (bundles, `[pack] elf_roots`), but the packer is more work and the
cans are tens of megabytes.

**Decided:** Go servers first, then one Node server, then Python as time allows.

**Do layers help?** Partly, for a different problem than they seem to. The *runtime* (`node`,
`python3`, libc, libstdc++, OpenSSL) needs no layers: with one blob per file, every can that
bundles the same `node` binary shares that blob, which dedupes better than a Docker base layer
(that only dedupes when images share the exact layer). The *thousands of small files* in
`node_modules`/`site-packages` are where grouping matters: one blob per file would mean
thousands of requests and a manifest near the 4 MB limit. So files are grouped, but **per
package**: one bundle per npm/PyPI package version (`lodash@4.17.21`), files in a fixed order,
so its bytes and digest are identical in every can that uses that version. A typical Node
server becomes a few hundred blobs, deduped across servers at package granularity. Package
boundaries come from the same metadata the SBOM uses.

*Backlog:* **shared base cans** (`[pack] base = "ghcr.io/…/node:22@sha256:…"`, like
`FROM node:22`). The runtime would be packed, signed and audited once, but cans would depend on
cans, and approval would involve two signers. Per-file dedup already gives most of the storage
benefit.

### Decision C: `/proc/self/exe` points at the loader

A can runs as `ld-linux … program`, so `readlink /proc/self/exe` is the loader, not the program.
Programs that re-run themselves (`process.execPath` in Node, some Go programs that re-exec) can
break. §3 describes the fix (v2, user namespaces); v1 documents it and flags such cans at pack
time when it can detect the pattern. **Decided:** document in v1, fix in v2. *Not chosen:* a
patched-interpreter variant (a per-user copy of the program with `PT_INTERP` rewritten), which
costs one extra file per can and a `patchelf`-style rewriter.

## 1. Artifact layout

Specified in [spec/can-format.md](../spec/can-format.md). In short:

```
index  (artifactType application/vnd.cantainer.can.v1)
 ├─ manifest linux/amd64 ─┬─ config: the can's manifest (TOML)
 │                        ├─ layer 0: tree.json    path → digest, mode, size; entrypoint
 │                        ├─ layer 1: SBOM         CycloneDX 1.6 JSON
 │                        └─ layers: one blob per file (+ bundles for trees of tiny files)
 └─ manifest linux/arm64 ─ …
referrer: Sigstore bundle (signs the index digest)
referrer: sources (copyleft, §8)
```

- **One blob per file, not tar layers.** Files that two cans share (libc, the loader, libz) have
  one digest, so a registry stores them once and `cant pull` downloads only blobs missing from the
  local store, and may `mount_blob` them across repositories on push.
- **The closure includes libc and the ELF loader.** `cant pack` walks `DT_NEEDED` from the
  entrypoint using the same reader as `cant run` (`cant-launch/src/linux/elf.rs`), and bundles
  `ld-linux-*.so`, `libc.so.6` and friends. The can then runs on any distro of the same
  architecture, with the bundled glibc rather than the host's. Static and musl programs have no
  loader to bundle.
- **Architectures:** `linux/amd64` and `linux/arm64` now; the index leaves room for `darwin` and
  for `riscv64`, which CI already builds. A can per architecture is a separate manifest, so
  libraries deduplicate only within an architecture.
- **SBOM: CycloneDX 1.6.** Chosen over SPDX because the data we need maps directly: per-file
  SHA-256 `hashes`, `purl`s that OSV queries by, `externalReferences` of type
  `source-distribution`, `pedigree` for patched packages, and VEX statements later. SPDX is the
  better fit for legal exchange and an ISO standard, but the Rust crate for it (`spdx-rs` 0.5.5)
  has not been released since 2023, while `cyclonedx-bom` 0.9.0 (CycloneDX organisation, updated
  2026-11-06) is maintained. SPDX can be generated from the same data later. Gap: `cyclonedx-bom`
  documents 1.3, 1.4 and 1.6 models; confirm 1.6 completeness in Phase 2.
- **Registry limits:** distribution-spec asks clients and registries to support manifests of at
  least 4 MB, about 20,000 layer descriptors. Bundles keep a Node tree under that. Whether
  ghcr.io accepts the largest manifests and how it handles many small blobs is untested; it is a
  Phase 2 check.
- **No compression** in v1: the blob is the file, so digests deduplicate. Transfer compression is
  the registry's or CDN's business. A `…file.v1+zstd` variant with a deterministic encoder is
  possible later.

## 2. The local store

```
~/.local/share/cantainer/
  store/
    blobs/sha256/ab/abcdef…      one immutable file per digest, mode 0444
    tmp/                         incoming files, same filesystem (atomic rename into place)
  cans/<manifest-digest>/        one directory per installed platform manifest
    manifest.json  config.toml  tree.json  sbom.json
    root/                        the can's files, hard-linked from store/blobs, laid out per tree.json
  refs/<registry>/<repo>/<tag>   name → manifest digest, with the time it was fetched
  state/                         approvals cache index, last-used times, gc lock
```

- **Content-addressed, verified on write and read.** `Store::put` hashes while writing and
  renames into place only when the digest matches. `Store::open(digest)` returns a handle that has
  been verified. Verifying every file of a 30 MB closure on every launch costs tens of
  milliseconds, so `cant run` verifies the small, security-relevant files every time (manifest,
  tree, the loader, the entrypoint) and checks the rest by size and inode against a record made at
  install time. `cant run --paranoid` re-hashes everything. This detects accidents, not an attacker
  with your uid, who could rewrite the record too (SECURITY.md already says such an attacker has
  your rights). The path to stronger guarantees is fs-verity.
- **Why hard links.** Landlock grants attach to a directory or file and are checked along the
  path used to open a file. A can's `root/` directory is granted (read + execute), and the store
  is not, so a running can can't see other cans' files or other blobs. Hard links give each can
  a private view without copying. If the store and `cans/` are on different filesystems,
  `cant pull` falls back to reflinks and then to copies. Symlinks would not work, because Landlock
  resolves them and would need the store granted.
- **Protected:** `~/.local/share/cantainer` is added to the read-only protected paths, so no
  manifest can grant write access to it. The runtime grants the running can's own `root/`
  internally, as it does for the executable and libraries today.
- **Composefs/fs-verity later.** Blob names stay plain SHA-256, the OCI digest. composefs names
  objects by fs-verity digest, so the migration adds an index from SHA-256 to verity digest
  (computed at install, enabled with `FS_IOC_ENABLE_VERITY`, an ioctl `rustix` may expose;
  verify in Phase 2; the `fs-verity` crate 0.2.0 is stale since 2023) and replaces the hard-link
  farm with an EROFS + overlayfs mount via `composefs` 0.10.0 (`containers/composefs-rs`, updated
  2026-11-05). Mounting needs privileges or a user namespace, so that is a v2 item.
- **`cant gc`.** Mark and sweep under an exclusive lock: roots are the installed `cans/*`
  that have a ref or were used in the last 14 days (`state/` records last use), plus the newest two
  versions of each repository. The sweep deletes unreferenced `cans/*` directories, then blobs
  that no surviving `tree.json` references. `--dry-run` lists what would go; `--now` ignores the
  grace period. Linux keeps deleted files alive for processes that opened them, but a can that
  `dlopen`s later could find a library gone, hence the grace period.

## 3. Launching without namespaces (v1)

```
<root>/lib64/ld-linux-x86-64.so.2 --library-path <root>/usr/lib/x86_64-linux-gnu \
    --argv0 git <root>/usr/bin/git status
```

`cant` builds the policy as it does today, and adds: the can's `root/` (read + execute), nothing
else from the store, and the usual runtime base. It then restricts itself and `exec`s the
**bundled** loader with the entrypoint as an argument. No namespace, no mount, no supervisor.

- **Dynamic programs:** `--library-path` carries `library_path` from the tree. glibc ≥ 2.33 is
  required for `--argv0` (from memory, confirm in Phase 2); the can bundles its own loader, so this is the packer's concern, and
  `cant pack` refuses a loader that lacks it. musl's loader accepts `--library-path`; confirm
  `--argv0` equivalents in Phase 2.
- **Static programs:** `exec` the entrypoint directly. This is the simplest case (most Go
  servers).
- **`$ORIGIN`:** the loader resolves it against the program's real path under `root/`, and the
  root mirrors the packing machine's layout, so `$ORIGIN/../lib` works as it did.
- **Hardcoded data paths.** A program that opens `/usr/share/git-core/templates` finds the *host's*
  copy (or none). The v1 fix is environment overrides in the manifest, which most programs have:
  `[env] set = { GIT_EXEC_PATH = "$CAN/usr/lib/git-core", GIT_TEMPLATE_DIR = "$CAN/usr/share/git-core/templates" }`,
  plus `[pack] include` for the data. Programs without an override either work with the host's
  files (declared in `fs.ro`) or need v2. `cant pack` can scan strings for absolute paths under
  `/usr`, `/etc`, `/lib` in the binary and warn; this is a heuristic.
- **`/proc/self/exe`** is the loader (Decision C). The program still has `AT_EXECFN`/`argv[0]`.
- **Landlock and the loader.** `execve` of the loader needs the execute right; mapping the
  program with `mmap` doesn't (ARCHITECTURE.md, "Libraries"). The existing SECURITY.md caveat that
  the loader runs any readable ELF file applies to cans, but the can has only its own `root/`.

**v2 (design only): opt-in mounts.** For programs that need files at their usual paths, or a true
`/proc/self/exe`, `cant` creates a user and mount namespace, bind-mounts the can's `root/`
(read-only) over `/usr`, `/lib`, `/lib64` and the data paths in the *can's own view* and runs the
program directly. It requires user namespaces (Ubuntu 24.04 needs an AppArmor profile), costs
startup time, and is selected per can with `[pack] launch = "mount"`. Netns for the host allowlist
(Decision A) shares this machinery, so the two should be designed together.

## 4. Signing and verification

- **Format:** Sigstore bundle (v0.3), stored as an OCI 1.1 referrer of the **index** digest
  ([spec §7](../spec/can-format.md#7-signatures)). One signature covers all platforms.
- **Keyless:** the publisher signs in CI with an OIDC identity (GitHub Actions workflow
  identity). The bundle contains a Fulcio certificate and a Rekor inclusion proof. The
  consumer's policy names the **identity** it trusts, not just "signed".
- **Key-based:** a public key in policy, for registries that don't want OIDC.
- **Policy** (`~/.config/cantainer/policy.toml`, or `/etc/cantainer/policy.toml`, both read-only to
  cants):

  ```toml
  [signature]
  default = "require"            # require | warn   (there is no "off")

  [[signature.trust]]
  match    = "ghcr.io/acme/*"
  identity = "https://github.com/acme/*/.github/workflows/release.yml@refs/tags/*"
  issuer   = "https://token.actions.githubusercontent.com"

  [[signature.trust]]
  match = "registry.internal/*"
  key   = "~/.config/cantainer/keys/internal.pub"
  ```

  `require` (the default) refuses unsigned cans and cans signed by an identity no `trust` entry
  allows for that registry/namespace. `warn` runs them after a warning, and the approval
  prompt (§5) says so. Policy lives in a file, not a flag, so a caller such as an agent can't
  weaken it with `--allow-unsigned`. Local `./x.can` files are trusted only through an explicit
  `cant approve ./x.can`, shown as "unsigned, local".
- **Trust root:** Sigstore's public-good instance through TUF, refreshed on `cant pull`. Verifying
  works offline from the stored bundle and the cached trust root afterwards.
- **Crates (verified 2026-11-16):**

  | Crate | Version | Notes |
  |---|---|---|
  | `sigstore-verify`, `sigstore-sign`, `sigstore-oidc`, `sigstore-trust-root`, `sigstore-bundle` | 0.16.0 (2026-11-09) | Repo `sigstore/sigstore-rust`. Bundle-based, TUF trust root, keyless signing via OIDC, identity + issuer policy on verify, MSRV 1.86, Apache-2.0. Pre-1.0. **Preferred.** |
  | `sigstore` | 0.15.0 (2026-11-05) | Repo `sigstore/sigstore-rs`. cosign key and keyless verify, Fulcio and Rekor clients. "Not considered stable until 1.0"; no attestation verification. Older, tag-based cosign format. |

  Gaps: both are pre-1.0 and their APIs move between minors (0.12 → 0.16 within a few months),
  so pin exact versions. Whether `sigstore-verify` verifies a bundle fetched from an OCI referrer
  with cosign 3's artifact layout needs an interop test against `cosign sign --new-bundle-format`
  in Phase 2. Keyless **signing** for publishers can also be done with `cosign` in CI, so `cant`
  need only verify in 0.1.0. That is the plan: `cant push` signs only if it can do so cleanly.

## 5. Approval on first run

The label is the interface. The first `cant run <ref>` for a publisher shows it:

```
git 2.47.1 (signed by github.com/acme/git-can, release.yml@refs/tags/v2.47.1) wants:
  read and write the current directory
  read /etc/ssl/certs
  no network
  run: git-core helpers bundled in the can
Allow? [y/N]
```

- **Plain language, generated from the manifest** and from nothing else: one line per capability,
  in a fixed vocabulary. Anything unusual is highlighted: any network, write access outside
  `$CWD`, `exec` of shells, `unix_sockets`, `chmod_by_path`, environment variables passed
  through (names shown, because `GITHUB_PERSONAL_ACCESS_TOKEN` is a capability).
- **The approval is stored** in `~/.config/cantainer/approvals/` (protected: cants can't write
  it) keyed by **repository + signer identity**, with the approved capabilities in canonical form
  and the digests accepted so far.
- **An update that asks for more shows only the difference** and asks again:

  ```
  git 2.48.0 (signed by github.com/acme/git-can) now also wants:
    + network to api.github.com
  Allow? [y/N]
  ```

  Rules: same signer, same-or-fewer capabilities → runs, with one line ("updated 2.47.1 → 2.48.0,
  no new rights"). More capabilities → diff prompt. **Different signer for the same name → full
  prompt and a warning** ("previously signed by github.com/acme"). A version or signed time
  older than the approved one is refused ([spec §9](../spec/can-format.md#9-versions-and-downgrades))
  unless `cant approve --allow-downgrade`.
- **No terminal, no prompt.** The prompt reads `/dev/tty`, never stdin: an MCP server's stdin is
  the protocol stream. With no controlling terminal and no applicable policy, `cant run` exits 125
  and says how to approve (`cant approve REF`, or `--approve-if-within`). For MCP, the user runs
  `cant pull` and `cant approve` once; the client config then just runs the can.
- **Non-interactive: `--approve-if-within POLICY.toml`.** Approves automatically **only if** the
  can's effective capabilities are a subset of the policy. Never prompts. This is the feature for
  agents and CI: an agent may install and run any can that stays inside the envelope its operator
  set.

  ```toml
  # agent-policy.toml
  [allow]
  fs_rw        = ["$CWD"]
  fs_ro        = ["$CWD", "/etc/ssl/certs"]
  exec         = []
  network      = ["api.github.com:443"]          # or "none"; "any" must be written out
  env          = ["GITHUB_PERSONAL_ACCESS_TOKEN"]
  unix_sockets = false
  chmod_by_path = false
  max_closure_age_days = 180
  signers = [{ identity = "https://github.com/acme/*", issuer = "https://token.actions.githubusercontent.com" }]
  ```

  The check is the same machinery as attenuation: paths are resolved as `cant run` resolves
  them and compared with `cant-policy::intersect`/`Policy::permits`, environment patterns with
  `EnvPattern::intersect`, hosts by set inclusion. On failure the message names the first
  capability outside the policy (`cant: git-mcp wants network to any host (not within
  agent-policy.toml)`) and exits 125. A host allowlist the runtime can't enforce counts as `any`
  (Decision A). The approval is recorded as "by policy, digest of the policy" so it can be
  audited, and it is *not* reused by a later run without the policy.
- **Protected paths always win.** A can whose manifest grants a protected path (`~/.ssh`, `~/.aws`,
  …) can't be approved by anyone: `cant pull`/`inspect` flag it, `cant run` refuses it exactly as
  it does for any manifest (`cant-policy::build`), and only the user's own `--grant` at the command
  line, for one run, opens it. No policy can allow it either.
- **Approval fatigue** (see §10) is why the prompt is short, defaults to N, shows the difference
  and never offers "always allow everything", and why policies exist for repeated use.

## 6. CLI

| Command | What it does |
|---|---|
| `cant pack PROGRAM [-o FILE] [--manifest M]` | Build a can from an installed program and a manifest: resolve the closure, `[pack]` data, SBOM, tree; write an OCI layout to `FILE` (`git.can`, an OCI image-layout tar for transport), or just install into the store. |
| `cant push FILE-or-REF REF` | Push blobs (skipping those the registry has, `mount_blob` across repositories), then the manifests, the index and, if given, the signature. Checks the licensing rules in §8. |
| `cant pull REF` | Resolve the platform manifest, verify the signature against policy, fetch missing blobs, install into the store, **don't run, don't approve**. |
| `cant run REF [args…]` | `pull` if needed, check approval, then launch (§3). `REF` is a name, a `./x.can` path, a registry reference or a `@sha256:` digest. Existing manifest names and paths work as before. |
| `cant inspect REF` | Label in plain language, signer and signed time, digest, platform, SBOM summary (components, licenses, closure age, known vulnerabilities from a cached audit), approval state (`not approved`, `approved for this digest`, `approved at 2.47.1, update wants more`). |
| `cant approve REF` / `cant revoke REF` | Show the label, ask, and record. `revoke` removes the approval; the can stays in the store. |
| `cant gc` | §2. |
| `cant audit [REF|--all]` | §9. |
| `cant search TEXT` | **Design only.** Needs a catalog: a signed OCI artifact (`ghcr.io/cantainer/catalog`) that lists name, reference, signer and a label summary for each can, which `search` fetches and filters locally. No server, no accounts. The catalog is a convenience; it never decides what is trusted. |

Exit status is as today: 125 for a refusal by `cant` (with the brand-voice message), 126/127 for
launch errors, the program's own status otherwise. Messages follow the existing voice:
`cant: git-mcp can't write ~/.ssh/config (not granted)`.

## 7. MCP servers

### 7.1 What a stdio server needs

A stdio MCP server reads JSON-RPC on stdin and writes it on stdout; it logs to stderr. `cant run`
already passes stdin/stdout/stderr through untouched (it `exec`s). A server needs: no filesystem
by default, files only through arguments (powerbox), a network allowlist, and the environment
variables it uses.

```toml
# github-mcp-server, illustrative: check flags and variables against the release you pack.
manifest_version = 2
name = "github-mcp-server"
version = "0.0.0-example"
description = "GitHub's MCP server over stdio"

[entrypoint]
path = "$CAN/usr/local/bin/github-mcp-server"
args = ["stdio"]

[args]
operands = "none"

[capabilities]
network = { allow = ["api.github.com:443"] }
fs.ro   = ["/etc/ssl/certs"]            # Go reads the system roots; no other file access

[env]
pass = ["GITHUB_PERSONAL_ACCESS_TOKEN"]
```

A filesystem server takes its directories as arguments, so the command line is the permission:
`operands = "rw"` and `cant run ghcr.io/acme/fs-mcp:1.0 ~/src/proj` grants exactly `~/src/proj`.

### 7.2 Pointing an agent at it

```json
{ "mcpServers": { "github": {
    "command": "cant",
    "args": ["run", "ghcr.io/acme/github-mcp-server:1.4", "stdio"],
    "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PAT}" }
} } }
```

`cant` filters the environment, so only variables named in the manifest's `pass` reach the
server. The client's `env` goes to `cant`, and `pass` forwards it. `docs/MCP.md` (Phase 2) will have
the exact snippets for Claude Code and other clients, and the one-time `cant pull` + `cant approve`
step that has to happen before a client starts the server, because the client has no terminal for
the prompt.

### 7.3 Host allowlist: the smallest version

See Decision A. If we do build it (option 1), the minimum is:

- `cant proxy` (a hidden subcommand, ≈ 300 lines on `std::net`): an HTTP `CONNECT`-only
  proxy. Accepts `CONNECT host:port`, matches `host:port` against the allowlist (exact names and
  `*.suffix`), resolves the name itself, **refuses loopback, private (RFC 1918, ULA), link-local
  and metadata addresses** (the SSRF case), connects, and relays bytes. No MITM, no TLS
  inspection, no HTTP forwarding; HTTPS is all MCP servers use.
- `cant run` for a can with `network.allow`: `unshare(CLONE_NEWUSER|CLONE_NEWNET)`, bring up
  `lo`, fork the proxy as a sidecar that creates its listening socket inside the can's network
  namespace (it holds the original namespace for its upstream connections) and exits when
  the can does (`PR_SET_PDEATHSIG`), apply Landlock/seccomp to the sidecar (network only, no
  files), set `HTTPS_PROXY`/`https_proxy`, then `exec` as usual. The can's seccomp keeps
  `AF_INET` stream sockets available (for the loopback proxy) and blocks datagram and raw sockets.
- Programs that ignore `HTTPS_PROXY` fail closed: the namespace has no route.
- Honest limits: only HTTPS-through-CONNECT works; a program that needs UDP or raw TCP can't
  have a host allowlist; the proxy sees destinations, not contents.

This is a bounded spike on Ubuntu 24.04 (userns policy) and Fedora before committing to it.

### 7.4 What the demo honestly shows (Decision A)

`npx` server: reads `~/.ssh/id_rsa`. The same server as a can: the read fails, writes anywhere but
its arguments fail, and `cant inspect` states "network: any host (host limits not enforced on this
system)". That is still the claim that matters for the next hostile package.

## 8. Licensing

Redistributing GPL (and LGPL) binaries means providing the matching source. A can that bundles
glibc (LGPL), coreutils or git (GPL) makes the publisher a distributor. This section is a design,
not legal advice; publishers should check their own obligations.

- **`cant pack` records provenance.** For each file it asks the package manager that owns it
  (`dpkg -S` / `dpkg-query`, `rpm -qf`), and writes into the SBOM: package, version, `purl`, SPDX
  license expression (from the package's copyright metadata) and a `source-distribution`
  reference (`Source:` for Debian, the SRPM for Fedora). Files not owned by a package (built from
  source) need `[pack] source = "https://…/tarball"`; otherwise they're listed as "unknown
  provenance".
- **`cant pack` classifies the licenses.** Permissive licenses need nothing but the notice
  (the SBOM carries them). GPL, LGPL and AGPL components are **copyleft components**.
- **`cant push` refuses a can with copyleft components and no source plan.** The plan is one of:
  - `--include-sources` (the default when copyleft is present): `cant` downloads the source
    packages (`apt-get source --download-only`, SRPMs) and pushes them as a **referrer** artifact
    of the can, `artifactType application/vnd.cantainer.can.sources.v1`, one blob per source
    archive. Registries stay the single distribution point and `cant pull --sources` fetches them.
  - `[pack.sources] offer = "https://…"`: a written offer or URL the publisher maintains. `cant
    push` checks it answers (HTTP HEAD) and records it. The publisher takes the responsibility.
- **`cant inspect` shows the licenses and where the source is**, so a consumer can see them.
- **Not in scope:** license compatibility analysis, patent questions, or EULAs. Proprietary
  binaries can be packed but `cant pack` warns that redistribution terms are unchecked.

## 9. Security patches: `cant audit`

Bundled libc and OpenSSL go stale; the user can't `apt upgrade` a can.

- **SBOM → OSV.** `cant audit` posts the SBOM's `purl`s to OSV's `POST /v1/querybatch` (documented
  API, free, supports Debian, Ubuntu, Alpine, PyPI, npm, Go, crates.io…), then fetches advisories
  with `GET /v1/vulns/{id}`, and prints affected components, severity, and the fixed version.
  OSV has a Rust crate (`osv` 0.3.0, schema and client), but a plain HTTPS call with the HTTP stack
  we already have is smaller than a new dependency; decide in Phase 2.
- **It is explicit.** `cant run` never makes network calls on its own, and the audit sends only
  package names and versions, not paths or machine data. `cant audit --all` covers every can in
  the store; results are cached for `cant inspect`.
- **Closure age.** `cant inspect` shows when the closure was built (the manifest's `created`) and
  the age of its oldest component, for example "built 212 days ago; libc6 2.39-0ubuntu8; 3 known
  vulnerabilities". The policy file's `max_closure_age_days` makes `cant run` warn, or refuse for
  `--approve-if-within`.
- **Fixing it is the publisher's job:** repack and sign a new version. An update that adds no new
  capability runs without a prompt (§5), so security releases flow quickly.
- **Not provided:** vulnerability *exploitability* analysis (VEX) in 0.1.0; a CycloneDX VEX
  document published with a can is the later path.

## 10. Threat model additions

These also go into SECURITY.md under "Cans (planned)".

| Threat | What we do | What remains |
|---|---|---|
| **Malicious publisher** | The label is enforced by the kernel and shown before first run; protected paths can't be granted by any manifest; attenuation bounds nested cans. | A publisher can ask for a lot and a user can say yes. A can asking for the network plus the token in its environment can send the token anywhere the network label allows. The user is trusting the label *and* that it's honest. |
| **Registry compromise** | Blobs are checked against digests in a manifest that is signed; the signer's identity is checked against policy. | A compromised registry can withhold, serve old signed versions (downgrade check below), or serve an unsigned can, which `require` refuses. It can't forge a signature without the signer's identity. |
| **Signer compromise** (CI identity, key) | Approval is keyed by signer *and* capabilities: a new version needing more is re-prompted. | A compromised signer can ship a malicious update that asks for nothing new and is still run. Short-lived keyless certificates and the transparency log limit this and make it visible, but don't prevent it. |
| **Downgrade** | Signed time and version are compared with the last accepted from the same signer; refusal unless `--allow-downgrade`. | The state is local. A fresh machine has no history. |
| **Approval fatigue** | Short plain-language label, diff-only on update, default N, no "allow all", highlights for risky capabilities, policies for repeated use. | People click yes. Policies and the `--approve-if-within` envelope exist so that agents and teams don't have to. |
| **Prompt injection of the approval** (an agent being told to approve) | The prompt reads `/dev/tty`, never stdin. An agent's tool calls have no tty. `--approve-if-within` can only approve within an operator-written policy, in a file the cant can't write. | An agent that also controls the user's terminal is outside the model. |
| **Local store tampering** | The store is read-only protected for cants; blobs verified on write; the small critical files verified on every run; the rest by recorded size and inode, or `--paranoid`. | Your uid can edit the store, and the approvals; so can any program you run outside a cant. fs-verity or composefs will fix this class later. |
| **Malicious archive content** (path traversal, symlink escape, huge files, hard-link tricks) | The tree format forbids them ([spec §4.1](../spec/can-format.md#41-path-and-entry-rules), §5) and the reader rejects the whole can on a violation; files are created without following symlinks and only under the can's own root. | Parser bugs; the reader is small and fuzzable (Phase 2 adds fuzz tests). |
| **Stale dependencies** | `cant audit`, closure age in `inspect`, policy ceiling. | A publisher who never updates. |
| **Confused label** (a manifest saying less than the program can do) | The kernel enforces the manifest; the label is not a description but the actual policy. | A bug in policy generation or in kernel enforcement. |
| **Host allowlist not enforced** | Reported as unrestricted network (Decision A). | Until netns/proxy lands, no host limits. |
| **Loader tricks** | The can runs the *bundled* loader, so a poisoned host loader or `ld.so.cache` isn't used; the can's `LD_*` is dropped by the existing environment filter. | The loader runs any readable ELF (existing limitation). |

## 11. Rejected alternatives

- **Tar layers (Docker-style).** A layer is a unit of duplication: two cans sharing libc but
  differing in one other file share no layer, so registries store and clients download the
  same bytes repeatedly, and a layer must be fully downloaded and unpacked before anything runs.
  Per-file blobs dedupe in the registry and the store, and the client fetches only what's
  missing. Costs we accept: more blobs and a bigger manifest (bundles bound it), and no
  existing tooling that understands the layout (`docker pull` can't run a can).
- **Nix-style relocation** (rewrite RPATHs and interpreters into a private prefix, `/nix/store`
  style, or `patchelf` every binary). It makes programs path-independent but changes the
  binary's bytes, so digests no longer match upstream, it needs a build or rewrite step per
  program, and it breaks anything that checks itself (signatures, `/proc/self/exe` tests). The
  can keeps the original bytes and fixes up *how* it's started (the loader's `--library-path`).
- **AppImage-style squashfs** (one filesystem image mounted via FUSE or loop). One image per app
  means no cross-can deduplication, the whole image is the unit of download, and mounting needs
  FUSE or privileges. Reading a file requires the mount, which conflicts with "no mounts" in v1.
- **Mount namespaces by default** (so programs see `/usr/lib` etc. as they expect). It needs user
  namespaces, which Ubuntu 24.04 restricts for unprivileged users by default, costs startup time,
  and complicates TTY and job control (ARCHITECTURE.md rejects it for the same reasons).
  It stays an opt-in v2 for programs that need it, and for the host allowlist.
- **cosign signatures as `.sig` tags.** The legacy format is a tag per signature, which pollutes
  tag lists and conflicts with registries' tag rules. Referrers (OCI 1.1, with the tag fallback
  for ghcr.io) are the standard path now.
- **A catalog server for `search`.** An extra service to trust and run. A signed catalog artifact
  needs only a registry.
- **Verifying every file on every run** (as the default). Hashing a few tens of megabytes per
  launch is a real cost for what is, against an attacker with your uid, no protection. fs-verity is
  the proper answer.

## 12. Crates (verified on crates.io and docs.rs, 2026-11-16)

| Need | Crate | Version | Notes and gaps |
|---|---|---|---|
| OCI distribution client | `oci-client` | 0.18.0 (2026-09-18) | Apache-2.0. Has `push_blob`, `blob_exists`, `mount_blob`, streaming and partial pulls, `push_manifest`/`push_manifest_list`, and `pull_referrers` with the tag-schema fallback (it names ghcr.io as needing it). rustls by default (aws-lc-rs), `native-tls` and `rustls-tls-no-provider` optional; custom transports supported. No MSRV published. Gap: async/tokio only; `cant` is synchronous today, so use one runtime in the registry code. |
| OCI types | `oci-spec` | 0.10.0 (2026-05-27) | `ImageManifest` has `artifact_type` and `subject`; `ImageIndex`, `Platform`, `Descriptor` builders. Enough for everything in the spec. |
| Sigstore | `sigstore-verify` / `-sign` / `-oidc` / `-trust-root` / `-bundle` | 0.16.0 (2026-11-09) | See §4. Preferred. Pre-1.0. |
| Sigstore (alternative) | `sigstore` | 0.15.0 (2026-11-05) | See §4. |
| SBOM | `cyclonedx-bom` | 0.9.0 (2026-11-06) | CycloneDX organisation. Confirm 1.6 coverage. |
| SBOM (rejected) | `spdx-rs` | 0.5.5 (2023-09-19) | Not released in three years. |
| Vulnerabilities | `osv` | 0.3.0 (2026-04-02) | Schema + client; a plain HTTPS call may be enough. |
| composefs | `composefs` | 0.10.0 (2026-11-05) | `containers/composefs-rs`, the reference implementation. Later. |
| fs-verity | `fs-verity` | 0.2.0 (2023-06-09) | Stale. Use `rustix` ioctls if they cover `FS_IOC_ENABLE_VERITY`; verify. |
| Syscalls | `rustix` | 1.1.6 | Already used. `openat2` with `RESOLVE_BENEATH` for unpacking. |
| Hashing | `sha2` | 0.11.1 | Already used by `cant-store`. |
| ELF | own reader | | `cant-launch/src/linux/elf.rs`; the packer reuses it (and adds `PT_INTERP`/`DT_NEEDED` closure walking for `.so` files found in `[pack]` trees). `object` 0.41.0 is the fallback. |

New dependencies mean new supply-chain surface. `oci-client` pulls `reqwest`, `tokio` and `rustls`;
the registry code should live in its own crate (`cant-registry`) behind a cargo feature so that
`cant run` of a local manifest stays small and fast. A binary-size and startup measurement goes with
Phase 2.

## 13. Phase 2 plan, in order

1. `cant-pack` crate: tree, spec parser, unpacker; `cant-store` implemented (put/open/verify,
   hard-link farm); `cant pack` for a local can; `cant run ./git.can`.
2. Launch through the bundled loader. CI matrix: build a can on Ubuntu, run it on Fedora, and the
   reverse.
3. `cant-registry`: `push`/`pull` against a `registry:2` container in CI, then GHCR (asking first).
4. Signing verification (and `push --sign` if clean), approval store, prompt, `--approve-if-within`.
5. `cant inspect`, `cant gc`, `cant audit`.
6. Pack 3-5 MCP servers as cans: Go first, then one Node server (per-package bundles), then
   Python if time allows. `docs/MCP.md`.
7. The demo tape, README, CHANGELOG, version 0.1.0.

Fuzzing the tree/archive reader and a size/startup benchmark join step 1 and step 3.

## 14. Backlog

- **Host allowlist enforcement** (Decision A): user + network namespace with a `CONNECT` proxy
  sidecar, §7.3. Shares machinery with the v2 mount namespaces.
- **Mount-namespace launch** (v2, §3): files at their usual paths, a true `/proc/self/exe`
  (Decision C).
- **Shared base cans** (Decision B).
- **composefs / fs-verity store** (§2).
- **`cant search`** catalog (§6).
