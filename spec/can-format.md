# The can format

**Version:** 1.0-draft (2026-11-16). This document is versioned on its own, apart from the
Cantainer runtime. Another runtime can implement it without implementing Cantainer. Reference
implementation: [Cantainer](https://github.com/cantainer/cantainer) (`cant pack`, `cant run`).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. What a can is

A **can** is one executable, the files it needs (its dynamic-library closure and data), a
**manifest** that says what the program may do, and an SBOM, distributed as an
[OCI artifact](https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidance-for-an-empty-descriptor)
(OCI image-spec 1.1, distribution-spec 1.1). Its purpose is to carry a machine-readable permission
label with the tool: a person, an agent or a policy can read the label before the tool runs,
and the runtime enforces it.

This specification defines the artifact, the manifest fields that matter to other parties, the
rules for reading a can safely, and how a can is signed. It does **not** define how a runtime
enforces the label. Enforcement is the runtime's business, but §8 says what a runtime MUST tell
the user when it cannot enforce a part of the label.

## 2. Artifact layout

A can is published as an **image index** (`application/vnd.oci.image.index.v1+json`) with one
image manifest per platform.

### 2.1 Image index

- `artifactType` MUST be `application/vnd.cantainer.can.v1`.
- Each entry in `manifests` MUST have `platform.os` and `platform.architecture`
  (`linux/amd64` and `linux/arm64` at the time of writing; GOARCH names as in the OCI spec).
  A runtime MUST select the entry matching its own platform and MUST refuse a can that has none.
- A can for a single platform MAY be published as a bare image manifest.

### 2.2 Image manifest (per platform)

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.cantainer.can.v1",
  "config": { "mediaType": "application/vnd.cantainer.can.manifest.v1+toml", "digest": "sha256:…", "size": 812 },
  "layers": [
    { "mediaType": "application/vnd.cantainer.can.tree.v1+json", "digest": "sha256:…", "size": 14211 },
    { "mediaType": "application/vnd.cyclonedx+json",             "digest": "sha256:…", "size": 90314 },
    { "mediaType": "application/vnd.cantainer.can.file.v1",       "digest": "sha256:…", "size": 3456789 },
    { "mediaType": "application/vnd.cantainer.can.bundle.v1",     "digest": "sha256:…", "size": 1048576 }
  ],
  "annotations": {
    "org.cantainer.can.format": "1",
    "org.opencontainers.image.title": "git",
    "org.opencontainers.image.version": "2.47.1",
    "org.opencontainers.image.created": "2026-11-01T00:00:00Z",
    "org.opencontainers.image.source": "https://example.com/acme/git-can"
  }
}
```

| Part | Media type | Rules |
|---|---|---|
| `config` | `application/vnd.cantainer.can.manifest.v1+toml` | The can's **manifest** (§3). Exactly one. |
| layer 0 | `application/vnd.cantainer.can.tree.v1+json` | The **tree** (§4). Exactly one, first. |
| SBOM | `application/vnd.cyclonedx+json` | CycloneDX 1.6 JSON. Exactly one (§6). |
| file | `application/vnd.cantainer.can.file.v1` | The raw bytes of one file. The digest is the SHA-256 of the file. No compression or archive format. |
| bundle | `application/vnd.cantainer.can.bundle.v1` | Concatenated contents of many small files, with no header (§4.3). |

- **One blob per file.** Identical files in different cans have the same digest, so a registry
  stores them once and a client downloads only blobs it does not have. A can MUST NOT use tar
  or any other archive layer.
- Every digest referenced by the tree MUST appear in `layers`. A registry that garbage-collects
  unreferenced blobs would otherwise delete them. A layer not referenced by the tree (other than
  the tree and the SBOM) MUST be ignored.
- The manifest SHOULD stay under 4 MiB, which distribution-spec 1.1 says clients and registries
  should support. At about 170 bytes per layer descriptor, that is roughly 20,000 files. §4.3
  describes bundles for larger trees.
- The `org.cantainer.can.format` annotation MUST be `"1"` for this version. A runtime MUST
  refuse a can with a greater value.

## 3. The manifest

The config blob is a TOML document in the Cantainer manifest format
([docs/MANIFEST.md](../docs/MANIFEST.md)). A can's manifest uses `manifest_version = 2`, which
adds to version 1:

| Addition | Meaning |
|---|---|
| `$CAN` | In any path, the root directory of the can's files (§5). |
| `[pack]` | Packing instructions. A runtime MAY ignore this table; it records how the can was made (see §3.1). |
| `capabilities.network = { allow = ["api.github.com:443"] }` | Network access limited to the listed `host:port` pairs, as an alternative to `true`/`false`. See §8. |

The label that is shown to people and policies is the manifest's `[capabilities]`, `[env]`,
`[args]` and `[entrypoint]` tables. A reader MUST treat unknown tables and fields as an error
(manifests are strictly validated), so a field a newer format adds cannot be silently ignored
by a runtime that would then enforce less than the publisher declared.

### 3.1 `[pack]`

```toml
[pack]
include  = ["/usr/lib/git-core", "/usr/share/git-core/templates"]  # trees copied into the can
exclude  = ["**/*.pyc", "**/__pycache__"]
elf_roots = ["/usr/lib/git-core"]      # ELF files here also get their DT_NEEDED closure bundled

[pack.sources]                         # copyleft obligations, see docs/CANS.md §8
offer = "https://example.com/acme/git-can/sources"
```

`include` paths are absolute paths on the packing machine; each appears at the same path inside
the can's root.

## 4. The tree

The tree is a JSON document listing everything in the can's root:

```json
{
  "version": 1,
  "entries": [
    { "path": "usr/bin/git", "type": "file", "mode": "0755", "size": 3456789, "digest": "sha256:…" },
    { "path": "usr/lib/x86_64-linux-gnu/libc.so.6", "type": "file", "mode": "0755", "size": 2125328, "digest": "sha256:…" },
    { "path": "usr/share/git-core/templates/description", "type": "file", "mode": "0644", "size": 73,
      "digest": "sha256:…", "bundle": { "digest": "sha256:…", "offset": 4096, "length": 73 } },
    { "path": "usr/bin/git-upload-pack", "type": "symlink", "target": "git" },
    { "path": "usr/share/git-core", "type": "dir", "mode": "0755" }
  ],
  "entrypoint": {
    "path": "usr/bin/git",
    "loader": "lib64/ld-linux-x86-64.so.2",
    "library_path": ["usr/lib/x86_64-linux-gnu"]
  }
}
```

### 4.1 Path and entry rules

A runtime MUST reject the whole can if any of these is violated:

- `path` is relative, uses `/` separators, is normalized (no `.` or `..` components, no empty
  components, no trailing `/`), contains no NUL, and is unique in the tree.
- Every parent directory of an entry is itself an entry of type `dir`.
- `type` is `file`, `dir` or `symlink`. There are no hard links, device nodes, FIFOs or sockets.
- `mode` is `"0755"` or `"0644"` for files and `"0755"` for directories. No other permission
  bits exist, in particular no setuid, setgid, sticky or group/other write. Ownership,
  extended attributes and timestamps are not part of the format. A runtime sets owner to the
  current user and timestamps to a constant.
- A symlink's `target` is relative and, resolved against the symlink's directory, stays inside
  the root. It MUST NOT be absolute, and MUST NOT leave the root through `..`, even if it
  would come back.
- `digest` is the SHA-256 of the file contents, and `size` its length. A runtime MUST verify
  both when it stores the file.
- Paths that differ only in case or Unicode normalization are allowed, and a runtime on a
  filesystem that cannot hold both MUST refuse the can.

### 4.2 `entrypoint`

- `path` names a `file` entry: the program to run.
- For a dynamically linked program, `loader` names the ELF interpreter's `file` entry (the
  bundled `ld-linux`), and `library_path` lists directories (`dir` entries) searched for
  shared libraries, in order. The runtime runs the program through the bundled loader and
  never through the host's. For a static program both are omitted.
- All paths in `entrypoint` are relative to the root, like tree paths.

### 4.3 Bundles

Many small files make a large manifest. A packer MAY store files smaller than 64 KiB in
**bundles**: blobs with media type `application/vnd.cantainer.can.bundle.v1` that are the plain
concatenation of file contents, with no header or padding. A file entry then carries
`"bundle": {"digest", "offset", "length"}` in addition to its own `digest` and `size`
(`length` MUST equal `size`). A runtime reads the byte range from the bundle and MUST verify the
file's `digest` after extraction. Bundles are meant for trees such as `node_modules`; ELF
files and anything over 64 KiB SHOULD stay individual blobs so that they deduplicate across
cans. A packer SHOULD use bundles only when a can would otherwise exceed about 5,000 files.

### 4.4 The root

The tree describes a root directory. A runtime materializes it on disk (the reference runtime
uses hard links into a content-addressed store) at a location it chooses, and `$CAN` in the
manifest stands for that location. Programs find their own files with `$ORIGIN`-relative
library paths and relative layouts, because the root mirrors the packing machine's directory
structure for every packed path.

## 5. Reading a can safely

Everything in a can is untrusted until the signature (§7) and the runtime's policy accept it.
A runtime:

1. MUST verify each blob's SHA-256 against its descriptor before using it, and MUST NOT trust
   sizes from a registry beyond the descriptor.
2. MUST apply §4.1 before writing any file, and MUST write only inside the can's own root. It
   MUST create files without following symlinks (for example `O_NOFOLLOW|O_EXCL`, or
   `openat2` with `RESOLVE_BENEATH`).
3. MUST enforce a limit on the total unpacked size, number of entries and path length, and
   SHOULD default them to values that a normal can fits in comfortably (suggested: 4 GiB,
   100,000 entries, 4,096 bytes).
4. MUST NOT execute anything from the can during unpacking.
5. MUST parse the manifest with the strict rules of §3 and MUST refuse a can whose manifest
   grants access the runtime's own protected-path list forbids, rather than ignoring the
   grant.

## 6. SBOM

The SBOM is a CycloneDX 1.6 JSON document. It MUST list a component for each package that
contributed files (name, version, `purl`, SPDX license identifier or expression, and the
SHA-256 of each shipped file as `hashes`). A component under a copyleft license SHOULD carry an
`externalReferences` entry of type `source-distribution`. The runtime-relevant parts are the
component list (for vulnerability audits) and the licenses and source references (for the
obligations in the publisher's jurisdiction). The SBOM is informative to a runtime; the
manifest is normative.

## 7. Signatures

A can SHOULD be signed, and a runtime SHOULD refuse an unsigned can unless its user says
otherwise in local policy (never in a per-run flag that a caller such as an agent could set).

- The signature covers the **digest of the image index** (or the bare manifest). That covers
  every platform manifest, config, tree and blob through their digests.
- It is a [Sigstore bundle](https://docs.sigstore.dev/about/bundle/) (version 0.3 or later),
  stored as an OCI 1.1 **referrer** of the signed manifest: an image manifest with `subject`
  set to the signed descriptor, `artifactType`
  `application/vnd.dev.sigstore.bundle.v0.3+json` and the bundle as its single layer
  (provisional: to be confirmed against what cosign 3 writes). A client
  finds it through the referrers API, falling back to the referrers tag schema of
  distribution-spec 1.1 where the registry has no such API (ghcr.io is one).
- **Keyless:** the bundle's certificate binds the signer to an OIDC identity (for example a
  GitHub Actions workflow, `https://github.com/acme/git-can/.github/workflows/pack.yml@refs/tags/v2.47.1`,
  issuer `https://token.actions.githubusercontent.com`), and the transparency-log inclusion
  proves it was made while the certificate was valid. **Key-based:** a public key, identified
  by its fingerprint.
- A verifier MUST check the signature against a trust root it obtained through TUF (or the
  user's own), MUST check the signer's identity against policy (a valid signature from *someone*
  is not enough), and SHOULD record the signed time so that it can detect a downgrade (§9).

## 8. Honest labels

A runtime that cannot enforce some part of a manifest MUST NOT show the label as if it could.
In particular, for `capabilities.network = { allow = [...] }`:

- If the runtime can enforce host limits, it does, and the label reads "network to
  api.github.com".
- If it cannot, it MUST either refuse to run the can, or show and record the capability as
  **unrestricted network** ("this system cannot limit the can to api.github.com") and apply
  every policy and approval to that stronger capability.

The same applies to any future field. Reading `network = false`, `fs.*`, `exec` and `env.pass`
requires only the kernel features the reference runtime already requires.

## 9. Versions and downgrades

`org.opencontainers.image.version` is the can's version. A signed can has a signed time (from
the transparency log). A runtime that keeps state SHOULD refuse a can whose signed time is
earlier than that of a can it has accepted from the same signer under the same name, unless the
user asks for it. Otherwise an attacker who controls a registry could serve an old, signed, but
vulnerable or over-privileged version.

## 10. Media types

| Media type | Used for |
|---|---|
| `application/vnd.cantainer.can.v1` | `artifactType` of can indexes and manifests |
| `application/vnd.cantainer.can.manifest.v1+toml` | config blob |
| `application/vnd.cantainer.can.tree.v1+json` | tree |
| `application/vnd.cantainer.can.file.v1` | one file |
| `application/vnd.cantainer.can.bundle.v1` | concatenated small files |
| `application/vnd.cantainer.can.sources.v1` | `artifactType` of a source-code referrer (docs/CANS.md §8) |
| `application/vnd.cyclonedx+json` | SBOM |
| `application/vnd.dev.sigstore.bundle.v0.3+json` | signature |

These names are provisional until the format reaches 1.0.
