# Vision

## Where this is going

Today's Linux userland is one shared, ambient-authority namespace. Every program you run can read
everything you can read, reach everything you can reach, and run everything you can run. Cantainer
makes the **executable** the unit of isolation and identity:

- Each program is a *cant*: a content-addressed executable with its own dependency closure and a
  declared set of capabilities.
- The kernel enforces those capabilities. The default answer is no.
- Running a cant feels like running a command. There is no daemon, no root and no image to build.

The long-term destination is a minimal Linux OS with **no shared userland**. There is no
`/usr/bin`; every command, including `ls` and `sh`, is a cant, fetched by digest and run with only
the rights its caller hands it. The runtime comes first, as a standalone tool on ordinary Linux.
It has to be useful on its own before an OS makes sense.

## Principles

1. **The unit is the executable**, not an application bundle (Flatpak) or an environment
   (Docker).
2. **Unmodified native binaries.** No recompiling for a new ABI (WASI).
3. **Attenuation across exec.** A cant can only pass on rights it holds. Rights shrink down the
   chain.
4. **The command line is the permission.** `vim notes.txt` grants `notes.txt`. No prompts and no
   `allow *`.
5. **Content-addressed, deduplicated per file.** OCI registries as transport; files as the unit of
   storage.
6. **Safe tools for agents.** An AI agent can run `git` and `cargo` without being able to read
   `~/.ssh` or reach the network.

## Roadmap

Done:

- **Milestone 0:** manifests, policy, the Landlock + seccomp launcher, `cant run`,
  `cant inspect`, `--explain`, attenuation, and benchmarks.
- **Built-in cants and agent-sh** (0.0.2–0.0.3), **watched cants** that report changes to
  files that run code later (0.0.4).
- **Cans, experimental** (0.0.4): redistributable cants as OCI artifacts. `cant pack`, `cant push`
  and `cant pull` work with any OCI registry, and a **content-addressed store** keeps each file
  once, checked when it's stored ([USING-CANS.md](USING-CANS.md), [CANS.md](CANS.md),
  [spec/can-format.md](../spec/can-format.md)).

Planned, roughly in order:

- **Signing and approval** (next, toward 0.1.0). Sigstore signatures on cans, checked at pull and
  at run time; a first-run approval prompt; `--approve-if-within POLICY` for agents.
- **MCP servers as cans**, `cant audit`, and published sources for the GPL programs in public
  cans (0.1.0).
- **composefs and fs-verity** behind the store, so the kernel verifies files on read.
- **Cached sandboxes.** Precomputed library closures and rulesets keyed by digest, to cut startup
  overhead further.
- **Shell integration.** A shell (or shell plugin) that runs commands as cants and applies the
  powerbox to its own command lines.
- **Bootable OS image.** A minimal Linux whose entire userland is cants.
- **Docker and Kubernetes integration.** Running cants inside containers and pods, and using
  cants as fine-grained tool sandboxes there.

Also on the list: script entrypoints (`#!`), `dlopen` discovery, Landlock audit logs (ABI 7+) for
explaining runtime denials, fetching manifests from a registry, and `git config` in the `git`
cant (git `chmod`s `.git/config.lock` by path, which the seccomp baseline refuses; the fix is
`chmod_by_path` for git, or a narrower rule). Can-specific items are in
[CANS.md](CANS.md#14-backlog).
