//! Shared-library resolution, in the style of `ldd`, without running anything.
//!
//! We read only what the dynamic loader reads to find dependencies: the ELF header, the
//! program headers, `PT_INTERP`, and from `PT_DYNAMIC` the `DT_NEEDED`, `DT_RPATH` and
//! `DT_RUNPATH` strings. Each is a small positioned read, so large binaries cost no more than
//! small ones. Search order follows glibc: `DT_RPATH` (only without `DT_RUNPATH`),
//! `DT_RUNPATH`, the directories in `/etc/ld.so.conf`, then the system defaults.
//! `LD_LIBRARY_PATH` is ignored because `cant` never passes `LD_*` variables into a cant.
//!
//! This is an approximation of the loader (no `ld.so.cache`, no `$LIB`/`$PLATFORM`).
//! Libraries it misses are reported, and the loader's own error appears if one is needed.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Errors reading an executable.
#[derive(Debug, thiserror::Error)]
pub enum ElfError {
    /// I/O error.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// The file starts with `#!`.
    #[error("{0} is a script; cants must currently be native ELF executables")]
    Script(PathBuf),
    /// Not an ELF file, or a malformed one.
    #[error("{path} is not a usable ELF executable: {reason}")]
    Malformed {
        /// File.
        path: PathBuf,
        /// What is wrong.
        reason: &'static str,
    },
}

/// What an executable needs from the filesystem to start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    /// `PT_INTERP`, canonicalized (absent for static binaries).
    pub interpreter: Option<PathBuf>,
    /// Shared libraries (canonical paths), in discovery order.
    pub libs: Vec<PathBuf>,
    /// `DT_NEEDED` names that could not be found.
    pub missing: Vec<String>,
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;

/// Sanity limits so a hostile file cannot make us allocate without bound.
const MAX_PHNUM: u64 = 4096;
const MAX_DYNAMIC: u64 = 1 << 20;
const MAX_STRTAB: u64 = 16 << 20;
const MAX_INTERP: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Kind {
    is_64: bool,
    little: bool,
    machine: u16,
}

#[derive(Debug, Default)]
struct DynInfo {
    kind: Option<Kind>,
    interp: Option<String>,
    needed: Vec<String>,
    rpath: Vec<String>,
    runpath: Vec<String>,
}

struct Reader<'a> {
    file: &'a File,
    path: &'a Path,
}

impl Reader<'_> {
    fn bad(&self, reason: &'static str) -> ElfError {
        ElfError::Malformed {
            path: self.path.to_path_buf(),
            reason,
        }
    }

    fn read(&self, offset: u64, len: u64) -> Result<Vec<u8>, ElfError> {
        let len = usize::try_from(len).map_err(|_| self.bad("size overflow"))?;
        let mut buf = vec![0u8; len];
        self.file
            .read_exact_at(&mut buf, offset)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => self.bad("truncated file"),
                _ => ElfError::Io {
                    path: self.path.to_path_buf(),
                    source: e,
                },
            })?;
        Ok(buf)
    }
}

fn uint(bytes: &[u8], little: bool) -> u64 {
    let mut v: u64 = 0;
    if little {
        for &b in bytes.iter().rev() {
            v = (v << 8) | u64::from(b);
        }
    } else {
        for &b in bytes {
            v = (v << 8) | u64::from(b);
        }
    }
    v
}

fn field(buf: &[u8], off: usize, len: usize, little: bool) -> u64 {
    // Callers only pass offsets inside fixed-size structures they already read.
    buf.get(off..off + len).map_or(0, |b| uint(b, little))
}

struct Segment {
    kind: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

fn read_dyn_info(path: &Path) -> Result<DynInfo, ElfError> {
    let file = File::open(path).map_err(|source| ElfError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let r = Reader { file: &file, path };
    let mut ident = [0u8; 64];
    let n = read_prefix(&file, &mut ident).map_err(|source| ElfError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if ident.starts_with(b"#!") {
        return Err(ElfError::Script(path.to_path_buf()));
    }
    if n < 52 || &ident[..4] != b"\x7fELF" {
        return Err(r.bad("not an ELF file"));
    }
    let is_64 = match ident[4] {
        1 => false,
        2 => true,
        _ => return Err(r.bad("unknown ELF class")),
    };
    let little = match ident[5] {
        1 => true,
        2 => false,
        _ => return Err(r.bad("unknown byte order")),
    };
    if is_64 && n < 64 {
        return Err(r.bad("truncated header"));
    }
    let machine = field(&ident, 18, 2, little) as u16;
    let (phoff, phentsize, phnum) = if is_64 {
        (
            field(&ident, 32, 8, little),
            field(&ident, 54, 2, little),
            field(&ident, 56, 2, little),
        )
    } else {
        (
            field(&ident, 28, 4, little),
            field(&ident, 42, 2, little),
            field(&ident, 44, 2, little),
        )
    };
    let min_phent = if is_64 { 56 } else { 32 };
    if phnum > MAX_PHNUM || (phnum > 0 && phentsize < min_phent) {
        return Err(r.bad("bad program header table"));
    }
    let table = r.read(phoff, phentsize * phnum)?;
    let mut segments = Vec::with_capacity(phnum as usize);
    for i in 0..phnum as usize {
        let ph = &table[i * phentsize as usize..];
        let seg = if is_64 {
            Segment {
                kind: field(ph, 0, 4, little) as u32,
                offset: field(ph, 8, 8, little),
                vaddr: field(ph, 16, 8, little),
                filesz: field(ph, 32, 8, little),
            }
        } else {
            Segment {
                kind: field(ph, 0, 4, little) as u32,
                offset: field(ph, 4, 4, little),
                vaddr: field(ph, 8, 4, little),
                filesz: field(ph, 16, 4, little),
            }
        };
        segments.push(seg);
    }

    let mut info = DynInfo {
        kind: Some(Kind {
            is_64,
            little,
            machine,
        }),
        ..DynInfo::default()
    };

    if let Some(seg) = segments.iter().find(|s| s.kind == PT_INTERP) {
        if seg.filesz == 0 || seg.filesz > MAX_INTERP {
            return Err(r.bad("bad PT_INTERP"));
        }
        let raw = r.read(seg.offset, seg.filesz)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        info.interp = Some(String::from_utf8_lossy(&raw[..end]).into_owned());
    }

    let Some(dynamic) = segments.iter().find(|s| s.kind == PT_DYNAMIC) else {
        return Ok(info); // statically linked
    };
    if dynamic.filesz > MAX_DYNAMIC {
        return Err(r.bad("PT_DYNAMIC too large"));
    }
    let entries = r.read(dynamic.offset, dynamic.filesz)?;
    let entsize = if is_64 { 16 } else { 8 };
    let word = entsize / 2;
    let mut strtab_vaddr = None;
    let mut strsz = None;
    let mut wanted: Vec<(u64, u64)> = Vec::new();
    for entry in entries.chunks_exact(entsize) {
        let tag = field(entry, 0, word, little);
        let val = field(entry, word, word, little);
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab_vaddr = Some(val),
            DT_STRSZ => strsz = Some(val),
            DT_NEEDED | DT_RPATH | DT_RUNPATH => wanted.push((tag, val)),
            _ => {}
        }
    }
    if wanted.is_empty() {
        return Ok(info);
    }
    let (Some(strtab_vaddr), Some(strsz)) = (strtab_vaddr, strsz) else {
        return Err(r.bad("dynamic section without string table"));
    };
    if strsz > MAX_STRTAB {
        return Err(r.bad("string table too large"));
    }
    let load = segments
        .iter()
        .find(|s| s.kind == PT_LOAD && strtab_vaddr >= s.vaddr && strtab_vaddr - s.vaddr < s.filesz)
        .ok_or_else(|| r.bad("string table outside loaded segments"))?;
    let strtab_offset = load
        .offset
        .checked_add(strtab_vaddr - load.vaddr)
        .ok_or_else(|| r.bad("string table offset overflow"))?;
    let strtab = r.read(strtab_offset, strsz)?;
    let string_at = |off: u64| -> Result<String, ElfError> {
        let start = usize::try_from(off).map_err(|_| r.bad("bad string offset"))?;
        let rest = strtab
            .get(start..)
            .ok_or_else(|| r.bad("bad string offset"))?;
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| r.bad("unterminated string"))?;
        Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
    };
    for (tag, val) in wanted {
        let s = string_at(val)?;
        match tag {
            DT_NEEDED => info.needed.push(s),
            DT_RPATH => info.rpath.extend(s.split(':').map(str::to_owned)),
            DT_RUNPATH => info.runpath.extend(s.split(':').map(str::to_owned)),
            _ => {}
        }
    }
    Ok(info)
}

fn read_prefix(file: &File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read_at(&mut buf[filled..], filled as u64) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn kind_of(path: &Path) -> Option<Kind> {
    let file = File::open(path).ok()?;
    let mut ident = [0u8; 20];
    let n = read_prefix(&file, &mut ident).ok()?;
    if n < 20 || &ident[..4] != b"\x7fELF" {
        return None;
    }
    let little = ident[5] == 1;
    Some(Kind {
        is_64: ident[4] == 2,
        little,
        machine: uint(&ident[18..20], little) as u16,
    })
}

/// Directories from `/etc/ld.so.conf` (with `include`s) followed by the system defaults.
fn system_dirs() -> &'static [PathBuf] {
    static DIRS: OnceLock<Vec<PathBuf>> = OnceLock::new();
    DIRS.get_or_init(|| {
        let mut dirs = Vec::new();
        parse_ld_so_conf(Path::new("/etc/ld.so.conf"), &mut dirs, 0);
        let triplet = if cfg!(target_arch = "x86_64") {
            "x86_64-linux-gnu"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-linux-gnu"
        } else {
            "unknown"
        };
        for d in [
            format!("/lib/{triplet}"),
            format!("/usr/lib/{triplet}"),
            "/lib64".into(),
            "/usr/lib64".into(),
            "/lib".into(),
            "/usr/lib".into(),
        ] {
            let d = PathBuf::from(d);
            if !dirs.contains(&d) {
                dirs.push(d);
            }
        }
        dirs
    })
}

fn parse_ld_so_conf(path: &Path, out: &mut Vec<PathBuf>, depth: u32) {
    if depth > 8 {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with("hwcap ") {
            continue;
        }
        if let Some(pattern) = line.strip_prefix("include") {
            let pattern = pattern.trim();
            let pattern = if pattern.starts_with('/') {
                PathBuf::from(pattern)
            } else {
                path.parent().unwrap_or(Path::new("/")).join(pattern)
            };
            for file in glob_last_component(&pattern) {
                parse_ld_so_conf(&file, out, depth + 1);
            }
        } else {
            let dir = PathBuf::from(line);
            if dir.is_absolute() && !out.contains(&dir) {
                out.push(dir);
            }
        }
    }
}

/// Expands a single `*` in the last path component (all `ld.so.conf` needs).
fn glob_last_component(pattern: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (
        pattern.parent(),
        pattern.file_name().and_then(|n| n.to_str()),
    ) else {
        return Vec::new();
    };
    let Some((prefix, suffix)) = name.split_once('*') else {
        return vec![pattern.to_path_buf()];
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e.file_name();
            let n = n.to_str()?;
            (n.len() >= prefix.len() + suffix.len() && n.starts_with(prefix) && n.ends_with(suffix))
                .then(|| e.path())
        })
        .collect();
    out.sort();
    out
}

fn expand_origin(entry: &str, origin: &Path) -> Option<PathBuf> {
    let origin = origin.to_str()?;
    let expanded = entry
        .replace("${ORIGIN}", origin)
        .replace("$ORIGIN", origin);
    if expanded.contains('$') || !expanded.starts_with('/') {
        // $LIB, $PLATFORM and relative entries are not supported.
        return None;
    }
    Some(PathBuf::from(expanded))
}

/// Resolves the interpreter and all shared libraries of `binary`.
pub fn resolve(binary: &Path) -> Result<Resolved, ElfError> {
    let main = read_dyn_info(binary)?;
    let kind = main.kind;
    let mut out = Resolved::default();
    if let Some(interp) = &main.interp {
        out.interpreter = Some(std::fs::canonicalize(interp).unwrap_or_else(|_| interp.into()));
    }
    // glibc: DT_RPATH of the executable applies to all its dependencies unless DT_RUNPATH exists.
    let exe_rpath: Vec<String> = if main.runpath.is_empty() {
        main.rpath.clone()
    } else {
        Vec::new()
    };

    let mut seen_names: HashSet<String> = HashSet::new();
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();
    let mut queue: VecDeque<(PathBuf, DynInfo)> = VecDeque::new();
    queue.push_back((binary.to_path_buf(), main));

    while let Some((obj_path, info)) = queue.pop_front() {
        let origin = obj_path.parent().unwrap_or(Path::new("/")).to_path_buf();
        let mut dirs: Vec<PathBuf> = Vec::new();
        if info.runpath.is_empty() {
            for e in info.rpath.iter().chain(exe_rpath.iter()) {
                dirs.extend(expand_origin(e, &origin));
            }
        }
        for e in &info.runpath {
            dirs.extend(expand_origin(e, &origin));
        }
        dirs.extend(system_dirs().iter().cloned());

        for name in &info.needed {
            if !seen_names.insert(name.clone()) {
                continue;
            }
            let found = if name.contains('/') {
                Some(PathBuf::from(name)).filter(|p| p.is_file())
            } else {
                dirs.iter()
                    .map(|d| d.join(name))
                    .find(|p| p.is_file() && kind_of(p) == kind)
            };
            let Some(found) = found else {
                out.missing.push(name.clone());
                continue;
            };
            // Optimized variants the loader may prefer (glibc-hwcaps).
            if let Some(dir) = found.parent() {
                for variant in glob_last_component(&dir.join("glibc-hwcaps").join("*")) {
                    let candidate = variant.join(name);
                    if candidate.is_file() {
                        if let Ok(c) = std::fs::canonicalize(&candidate) {
                            if seen_paths.insert(c.clone()) {
                                out.libs.push(c);
                            }
                        }
                    }
                }
            }
            let canonical = std::fs::canonicalize(&found).unwrap_or(found);
            if seen_paths.insert(canonical.clone()) {
                out.libs.push(canonical.clone());
                if let Ok(child) = read_dyn_info(&canonical) {
                    queue.push_back((canonical, child));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_cat_like_ldd() {
        let cat = std::fs::canonicalize("/bin/cat").expect("cat exists");
        let r = resolve(&cat).expect("resolve");
        let libc = r.libs.iter().any(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("libc.so"))
        });
        assert!(libc, "libc not found in {r:?}");
        assert!(r.interpreter.is_some(), "cat should be dynamically linked");
        assert!(r.missing.is_empty(), "{r:?}");
        // Compare with ldd when available.
        if let Ok(out) = std::process::Command::new("ldd").arg(&cat).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if let Some((_, rest)) = line.split_once("=> ") {
                    if let Some(path) = rest.split_whitespace().next() {
                        let p = std::fs::canonicalize(path).expect("ldd path exists");
                        assert!(r.libs.contains(&p), "ldd found {p:?}, we did not: {r:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_non_elf_and_scripts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("s");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").expect("write");
        assert!(matches!(resolve(&script), Err(ElfError::Script(_))));
        let junk = dir.path().join("j");
        std::fs::write(&junk, vec![0u8; 100]).expect("write");
        assert!(matches!(resolve(&junk), Err(ElfError::Malformed { .. })));
        let truncated = dir.path().join("t");
        let mut bytes = std::fs::read("/bin/cat").expect("read cat");
        bytes.truncate(200);
        std::fs::write(&truncated, bytes).expect("write");
        assert!(resolve(&truncated).is_err());
    }

    #[test]
    fn origin_expansion() {
        let o = Path::new("/opt/app/bin");
        assert_eq!(
            expand_origin("$ORIGIN/../lib", o),
            Some(PathBuf::from("/opt/app/bin/../lib"))
        );
        assert_eq!(
            expand_origin("${ORIGIN}/lib", o),
            Some(PathBuf::from("/opt/app/bin/lib"))
        );
        assert_eq!(expand_origin("$LIB/x", o), None);
        assert_eq!(expand_origin("lib", o), None);
    }
}
