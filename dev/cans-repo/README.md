# cans

Cans built from [Cantainer](https://github.com/cantainer/cantainer)'s built-in cants, published at
`ghcr.io/cantainer/<name>:<version>`.

A **can** is a redistributable cant: one executable, its libraries (libc and the ELF loader
included), its manifest (what the program may do) and an SBOM, as an OCI artifact. See
[docs/CANS.md](https://github.com/cantainer/cantainer/blob/main/docs/CANS.md) and the
[format spec](https://github.com/cantainer/cantainer/blob/main/spec/can-format.md).

```sh
cant pull ghcr.io/cantainer/grep:3.11
cant run ghcr.io/cantainer/grep:3.11 TODO notes.txt
```

**Status: experimental. The packages are private** until the cans are signed and the sources of
the GPL/LGPL programs inside them are published alongside (CANS.md §8). `cant run` runs a can
from a registry only after you `cant pull` it yourself. Signing (Sigstore, keyless) will be added to
[the pack workflow](.github/workflows/pack.yml); the signer identity of every can will then be
that workflow in this repository.

| Can | Built from |
|---|---|
| `grep` | GNU grep on the workflow's Ubuntu runner |
| `git` | git on the workflow's Ubuntu runner |

Licensed under either of Apache-2.0 or MIT at your option. The programs inside each can keep
their own licenses (listed in each can's SBOM); providing their source is still to do (see
CANS.md §8).
