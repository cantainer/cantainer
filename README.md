# Cantainer

**By default, you can't.**

Cantainer runs every executable as a lightweight capsule called a *cant*. A cant can touch only
what its manifest declares and the files you name on its command line. The kernel enforces this
with Landlock and seccomp. Cants run like ordinary commands, with about a millisecond of extra
startup, and need no root.

There is no cantainerd. No daemon. You cant.

```console
$ cant run cat ~/.ssh/id_rsa
cant: cat can't read ~/.ssh/id_rsa (~/.ssh is protected); to allow it anyway: cant run --grant ~/.ssh/id_rsa:r cat ...

$ cant run cat notes.txt
meeting notes

$ cant run curl https://example.com
curl: (6) Could not resolve host: example.com

$ cant run vim notes.txt       # vim works normally, but can write only notes.txt
```

> **Status: experimental.** Cantainer is a young, unaudited security tool. Read
> [SECURITY.md](SECURITY.md) for the threat model and known limitations before relying on it.

## Why

On a normal Linux system every program you run can read your SSH keys, talk to the network and
start any other program. That matters more now that AI agents run tools on our behalf. Cantainer
makes the **executable** the unit of isolation:

- **The command line is the permission.** `cant run vim notes.txt` grants vim `notes.txt`. There
  are no prompts and no `allow *`.
- **Unmodified native binaries.** No images to build and nothing to recompile.
- **Rights only shrink.** A cant that runs another cant can only pass on rights it holds, and the
  kernel enforces the intersection.
- **Secrets stay out of reach.** Credentials such as `~/.ssh`, `~/.aws` and `~/.gnupg` can't be
  granted by a manifest or a command-line argument, only by an explicit `--grant`.

The long-term goal is a Linux system with no shared userland, where every command is a cant. See
[docs/VISION.md](docs/VISION.md).

## Quickstart

### Linux (kernel ≥ 6.2; ≥ 6.7 for Landlock network rules)

```sh
git clone https://github.com/cantainer/cantainer && cd cantainer
cargo build --release
./target/release/cant check          # can this kernel sandbox cants?
echo "meeting notes" > notes.txt
./target/release/cant run cat notes.txt
```

`cant run NAME` looks for `~/.config/cantainer/cants/NAME.toml`, then `./examples/NAME.toml`.
To install the examples:

```sh
mkdir -p ~/.config/cantainer/cants && cp examples/*.toml ~/.config/cantainer/cants/
```

### macOS (via Lima)

Cants need a Linux kernel. The workspace compiles on macOS, so you can edit and run
`cargo check` natively; build and test inside a Lima VM:

```sh
brew install lima                                  # Lima >= 2.0
limactl start --name=cantainer dev/lima.yaml       # Ubuntu 24.04, Linux 6.8, Rust, vim, curl
limactl shell cantainer
cd /Users/$USER/path/to/cantainer                  # your Mac home is mounted at the same path
cargo run -p cantainer -- check
cargo test --workspace
```

Inside the VM, build output goes to `~/cantainer-target` (set by the VM's `~/.profile`), so it
doesn't mix with macOS builds in `target/`.

### Dev container

Open the repository in VS Code with Dev Containers, or in GitHub Codespaces. The container needs
a host kernel with Landlock. OrbStack, Docker Desktop and Lima all qualify on macOS. See
[`dev/README.md`](dev/README.md).

## Usage

```
cant run [--explain] [--grant PATH[:ACCESS]]... <CANT> [ARGS]...
cant inspect <CANT>     manifest, resolved binary, sha256 digest, capabilities
cant list               cants found in the search path
cant check              does this kernel support sandboxing?
```

- `--explain` prints the effective policy (every granted path and why) and exits without running.
- `--grant PATH[:r|rw|rx|rwx]` adds a grant. It is the only way to reach a protected path.
- `CANT` is a name or a path to a manifest.
- `cant` exits with 125 when it refuses or fails. Otherwise the exit status is the program's own.

A manifest declares what a cant may do. Here is `examples/cat.toml`:

```toml
manifest_version = 1
name = "cat"
version = "0.1.0"
description = "Concatenate files to standard output"

[entrypoint]
path = "cat"

[args]
operands = "r"        # non-option arguments are files to read

[env]
pass = ["LANG", "LC_*"]
```

The format is documented in [docs/MANIFEST.md](docs/MANIFEST.md). The examples cover `cat`,
`curl` (without network), `git` (confined to the current directory, offline) and `vim`.

## How it works

`cant` reads the manifest and builds a policy. The policy contains the executable, its ELF
interpreter and shared libraries (found without running anything), a small runtime base, the
manifest's paths and the files named on the command line. Then `cant`:

1. applies a Landlock ruleset that denies all filesystem access (and TCP, when the network is off)
   except those grants;
2. installs seccomp filters. They refuse sockets the policy doesn't allow, path-based metadata
   changes, namespace creation, `ptrace`, `io_uring`, `bpf`, terminal injection, and other rarely
   needed kernel interfaces;
3. `exec`s the program.

No process stays behind, so exit codes, signals, job control and the terminal behave exactly as
without `cant`. The details and the rejected alternatives are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Startup overhead

`benches/startup.sh` runs `cat notes.txt` and `cant run cat notes.txt` 1000 times each with
hyperfine (release build, 50 warm-up runs):

| Command | Mean | Min | Max |
|:---|---:|---:|---:|
| `cat notes.txt` | 0.71 ms ± 0.26 | 0.52 ms | 3.86 ms |
| `cant run cat notes.txt` | 2.13 ms ± 0.53 | 1.79 ms | 5.97 ms |

So the overhead is about **1.4 ms** per launch. Measured on 2026-11-12 in a dev container on an
Azure VM (Intel Xeon Platinum 8370C, Linux 6.8). It covers manifest parsing, library resolution,
building the Landlock and seccomp rules, and the extra `execve`. Run the script on your own
machine; the numbers vary with hardware and kernel.

## Demo recording

`demo/demo.tape` renders the demo above as a GIF with [vhs](https://github.com/charmbracelet/vhs):

```sh
cargo build --release && PATH="$PWD/target/release:$PATH" vhs demo/demo.tape
```

The GIF isn't committed yet.

## How it compares

These tools solve different problems, and several are excellent at theirs.

| | Unit | Isolation | Needs | Programs |
|---|---|---|---|---|
| **Cantainer** | one executable | Landlock + seccomp, per-file grants from the command line | Linux ≥ 6.2, no root, no daemon | unmodified native binaries |
| **Docker / OCI containers** | a whole environment (image) | namespaces, cgroups, seccomp | a daemon (or rootless setup), images | anything in the image |
| **Flatpak** | a desktop application | bubblewrap namespaces, portals | runtimes, app packaging | apps built for Flatpak |
| **bubblewrap** | whatever you configure | namespaces, bind mounts, seccomp | unprivileged user namespaces (or setuid) | unmodified native binaries |
| **Nix** | a package and its closure | none at runtime (build sandbox only) | the Nix store | packages built with Nix |
| **pkgx** | a tool and its dependencies | none at runtime | the pkgx runtime | packaged tools |
| **WASI** | a WebAssembly module | capability-based by construction | a Wasm runtime | programs recompiled to Wasm |

Honest differences:

- **Docker** isolates far more (process tree, network stack, resource limits) and is the right
  tool for services and reproducible environments. Cantainer doesn't build or ship images; it
  confines one command on the host you already have.
- **Flatpak** targets desktop apps, with portals for user-mediated access. Cantainer has no
  portals; the command line plays that role, which suits command-line tools.
- **bubblewrap** is a flexible, mature low-level sandbox. Cantainer is narrower: a declarative
  manifest, the powerbox, protected paths and attenuation, without user namespaces. bubblewrap can
  hide paths entirely, which Landlock can't (a cant can still `stat` paths it can't open).
- **Nix** and **pkgx** solve distribution and dependency closure, which Cantainer plans to address
  with OCI and a content-addressed store. Neither sandboxes programs at runtime.
- **WASI** offers stronger, cleaner capability semantics, but programs must be compiled for it.
  Cantainer runs the binaries you already have, so it inherits Linux's larger attack surface.

## Repository layout

```
crates/cantainer       the `cant` CLI (published as `cantainer`)
crates/cant-manifest   manifest types and validation
crates/cant-policy     capability model, powerbox, protected paths, attenuation
crates/cant-launch     ELF resolution, Landlock, seccomp, exec
crates/cant-store      content digests; future content-addressed store
examples/              manifests for cat, curl, git, vim
docs/                  VISION, ARCHITECTURE, MANIFEST
benches/startup.sh     startup benchmark
dev/                   Lima VM config and kernel check
demo/demo.tape         README demo recording
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state otherwise, any
contribution you submit for inclusion is dual-licensed as above, without additional terms.
