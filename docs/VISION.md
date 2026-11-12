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

Milestone 0 (this repository today): manifests, policy, the Landlock + seccomp launcher, `cant run`,
`cant inspect`, `--explain`, attenuation, and benchmarks.

Planned, roughly in order. None of this exists yet:

- **OCI registry pull and push.** Distribute cants (manifest + files) through any OCI registry,
  addressed by digest.
- **Content-addressed store.** Per-file storage under `cant-store`, later backed by **composefs**
  with **fs-verity**, so files are deduplicated across cants and verified by the kernel on read.
- **Signing.** Sigstore signatures on cant manifests, checked at pull and at run time.
- **Cached sandboxes.** Precomputed library closures and rulesets keyed by digest, to cut startup
  overhead further.
- **Shell integration.** A shell (or shell plugin) that runs commands as cants and applies the
  powerbox to its own command lines.
- **Bootable OS image.** A minimal Linux whose entire userland is cants.
- **Docker and Kubernetes integration.** Running cants inside containers and pods, and using
  cants as fine-grained tool sandboxes there.

Also on the list: script entrypoints (`#!`), `dlopen` discovery, Landlock audit logs (ABI 7+) for
explaining runtime denials, and replacing the `./examples` lookup with the registry.
