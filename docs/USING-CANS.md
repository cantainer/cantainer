# Using cans

A **can** is a cant you can hand to someone else. It holds one program, the libraries it needs
(libc and the ELF loader included), its manifest, which says what the program may do, and an
SBOM, packed as one OCI artifact. You can push it to any OCI registry. It runs on any Linux
distribution of the same architecture, and the kernel enforces the same manifest there as on
the machine where it was packed.

What's new is that the permissions travel with the program. A person, an agent or a company
policy can read what a can may do before it runs, and the kernel holds it to that.

> **Status: experimental (0.0.4).** Cans are **not signed yet**, and there is no approval
> prompt. Until signing lands, a can from a registry runs only after you `cant pull` it
> yourself. Run only cans you made or trust. [SECURITY.md](../SECURITY.md) has the details.

The design is in [CANS.md](CANS.md). The file format is an open specification, versioned on its
own so that other runtimes can adopt it: [spec/can-format.md](../spec/can-format.md).

## Quickstart

```console
$ cant pack grep                                   # grep, its libraries, its manifest, an SBOM
packed grep 0.1.0 into grep.can: 5 files, 3.4 MB, manifest sha256:e67f76…
run it with: cant run grep.can ARGS...

$ cant run ./grep.can TODO notes.txt               # runs on the can's own libc and loader
TODO: buy milk

$ cant push grep.can ghcr.io/you/grep:3.11         # any OCI registry
pushed grep.can to ghcr.io/you/grep:3.11 (sha256:71e5b8…): 7 blobs uploaded, 0 already there

# on another machine, even another distribution:
$ cant pull ghcr.io/you/grep:3.11
pulled grep 0.1.0 from ghcr.io/you/grep:3.11 (sha256:71e5b8…): 7 blobs downloaded, 0 already here
warning: this can is NOT signed; it runs with what its manifest declares. Check it first: cant inspect ghcr.io/you/grep:3.11
$ cant run ghcr.io/you/grep:3.11 TODO notes.txt
```

Everything that applies to a cant applies to a can. The files named on the command line are its
grants, protected paths such as `~/.ssh` are refused, and nested cants only lose rights.

## Commands

| Command | What it does |
|---|---|
| `cant pack CANT [-o DIR]` | Makes a can from a cant (a built-in name, or a manifest path). The output is an OCI image layout directory (`NAME.can/`). |
| `cant run ./NAME.can ARGS...` | Installs the can into the store, if it isn't there yet, and runs it. |
| `cant push DIR HOST/NAME:TAG` | Uploads a can to a registry. Only blobs the registry doesn't have are sent. |
| `cant pull HOST/NAME:TAG` | Downloads a can and installs it. Only the files missing from your store are downloaded. `HOST/NAME@sha256:…` pins a digest. |
| `cant run HOST/NAME:TAG ARGS...` | Runs a can you pulled. |
| `cant inspect ./NAME.can` or `cant inspect HOST/NAME:TAG` | Shows the manifest, the program and its digest, the bundled loader, and the capabilities. |

A registry reference must start with a registry host (`ghcr.io/…`, `localhost:5000/…`), so it
can't be mistaken for a cant name or a file. Registries on `localhost` use plain HTTP; all others
need HTTPS.

**Credentials** come from `CANT_REGISTRY_USER` and `CANT_REGISTRY_TOKEN`. Without them, `cant`
connects anonymously. For GitHub's registry, use your user name and a token with `read:packages`
to pull, or `write:packages` to push. In GitHub Actions, use `github.actor` and `GITHUB_TOKEN`.

## Packing your own

`cant pack` starts from a manifest (see [MANIFEST.md](MANIFEST.md)). It finds the program and
follows its shared libraries the way the loader would, bundling libc and the loader too. It adds
whatever `[pack]` lists:

```toml
manifest_version = 2
name = "mytool"
version = "1.2.0"

[entrypoint]
path = "/opt/mytool/bin/mytool"          # where it is on the packing machine

[capabilities]
fs.ro = ["$CAN/opt/mytool/share"]       # $CAN: the can's own files, when it runs

[pack]
include = ["/opt/mytool/share"]          # copied into the can at the same path
exclude = ["**/*.md"]
elf_roots = ["/opt/mytool/lib/plugins"]  # these ELF files' libraries are bundled too
```

The packed manifest's entrypoint becomes `$CAN/...`, and the result passes the same strict
validation as any manifest. `cant pack` also writes a CycloneDX SBOM, with the package each file
came from (via `dpkg` or `rpm`) and its SHA-256.

## Where things live

| Path | What |
|---|---|
| `~/.local/share/cantainer/store/` | Every file of every can, once, named by its SHA-256 and checked when stored |
| `~/.local/share/cantainer/cans/<digest>/` | An installed can: its manifest, tree, SBOM, and `root/` (hard links into the store) |
| `~/.local/share/cantainer/refs/` | Which installed can each pulled reference points at |

`$XDG_DATA_HOME` moves all of it. No cant can write there (it's a protected path). An installed
can whose program or loader changed is refused when it's opened.

Cans share files. libc and the loader are stored once, however many cans bundle them, and a pull
downloads only what's missing.

## How a can runs

`cant` runs the can's program through the can's **own** loader:

```
<root>/lib64/ld-linux-x86-64.so.2 --inhibit-cache --library-path <root>/usr/lib/x86_64-linux-gnu \
    --argv0 grep <root>/usr/bin/grep TODO notes.txt
```

Nothing from the host's libraries is used or granted. The can's own files are readable and
executable by it, never writable. Static programs (most Go programs, for example) start directly.
`cant run --explain` shows every grant.

## Limitations today

- **Not signed, no approval prompt.** Planned next: Sigstore signatures with the publisher's
  identity, a plain-language approval prompt on first run, a prompt showing only what's new when
  an update asks for more, and `--approve-if-within POLICY` for agents. See
  [CANS.md](CANS.md) §4–§5.
- **`/proc/self/exe` is the loader.** Programs that check it refuse to run, for example Ubuntu
  26.04's coreutils (uutils `cat`, `head`, …). GNU coreutils (Ubuntu 24.04, Fedora) and static
  programs are fine.
- **Bundled helper programs.** When a can's program starts *another* program from the can (git's
  `git-remote-https`, for example), that helper uses the host's loader, which isn't granted, so
  it fails with "Permission denied". Most git commands are built in and work.
- **No network host limits.** A `network = { allow = [...] }` label is shown and enforced as
  unrestricted network until host filtering exists ([CANS.md](CANS.md), Decision A).
- **Linux only**, x86_64 and aarch64. A can's libraries come from the machine it was packed on.
  `cant audit` (known vulnerabilities, closure age) isn't there yet.
- **Licenses:** packing GPL or LGPL programs (which includes glibc) and publishing the cans makes
  you a distributor. Publish the sources too. `cant` will help with this ([CANS.md](CANS.md) §8);
  today it doesn't.

## Official cans

[cantainer/cans](https://github.com/cantainer/cans) packs and publishes cans built from the
built-in cants to `ghcr.io/cantainer/<name>`. They're **private** until they are signed and their
sources are published alongside them.
