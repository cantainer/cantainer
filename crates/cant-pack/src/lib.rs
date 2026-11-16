//! Cans: redistributable cants (`docs/CANS.md`, `spec/can-format.md`).
//!
//! - [`tree`]: the list of a can's files and how its program starts, with the spec's
//!   validation rules;
//! - [`layout`]: a can as an OCI image layout directory (`git.can/`);
//! - [`pack`]: `cant pack`, which builds a can from an installed program (Linux);
//! - [`install`]: verifies a can into the content-addressed store and builds its root (Linux).

#![forbid(unsafe_code)]

use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod glob;
pub mod layout;
#[cfg(target_os = "linux")]
mod sbom;
pub mod tree;

#[cfg(target_os = "linux")]
pub mod install;
#[cfg(target_os = "linux")]
pub mod pack;

/// Errors packing, reading or installing a can.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The can (or the request) breaks a rule; every problem is listed.
    #[error("{}", .0.join("; "))]
    Invalid(Vec<String>),
    /// File system error.
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Store error (a blob that doesn't match its digest, ...).
    #[error(transparent)]
    Store(#[from] cant_store::StoreError),
}

/// Now as RFC 3339 UTC (`2026-11-16T12:00:00Z`), or `SOURCE_DATE_EPOCH` if set.
#[cfg(target_os = "linux")]
pub(crate) fn timestamp() -> String {
    let secs = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        });
    rfc3339(secs)
}

#[cfg(target_os = "linux")]
fn rfc3339(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn rfc3339_known_values() {
        assert_eq!(super::rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::rfc3339(1_763_294_400), "2025-11-16T12:00:00Z");
        assert_eq!(super::rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod roundtrip {
    use std::path::Path;

    use cant_manifest::Manifest;

    use crate::Error;

    const CAT: &str = "manifest_version = 1\nname = \"cat\"\nversion = \"1.0\"\n\
                       [entrypoint]\npath = \"cat\"\n[args]\noperands = \"r\"\n";

    fn pack_cat(tmp: &Path) -> crate::pack::Packed {
        let m = Manifest::from_toml_str(CAT).expect("manifest");
        crate::pack::pack(&m, tmp, &tmp.join("cat.can")).expect("pack")
    }

    #[test]
    fn pack_then_install_cat() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = std::fs::canonicalize(dir.path()).expect("canonical");
        let packed = pack_cat(&tmp);
        assert!(packed.files >= 3, "cat, libc and the loader: {packed:?}");

        let data = tmp.join("data");
        let can = crate::install::install(&packed.dir, &data).expect("install");
        assert_eq!(
            can.manifest.entrypoint.path,
            format!("$CAN/{}", can.tree.entrypoint.path)
        );
        assert_eq!(can.manifest.manifest_version, 2);
        let program = can.root.join(&can.tree.entrypoint.path);
        assert!(program.is_file());
        let loader = can.tree.entrypoint.loader.as_ref().expect("cat is dynamic");
        assert!(can.root.join(loader).is_file());
        // Installing again finds it.
        let again = crate::install::install(&packed.dir, &data).expect("again");
        assert_eq!(again.dir, can.dir);
        // The bundled loader runs the bundled cat with the bundled libc.
        let lib_path: Vec<String> = can
            .tree
            .entrypoint
            .library_path
            .iter()
            .map(|d| can.root.join(d).display().to_string())
            .collect();
        std::fs::write(tmp.join("hello"), "hi\n").expect("write");
        let out = std::process::Command::new(can.root.join(loader))
            .arg("--inhibit-cache")
            .arg("--library-path")
            .arg(lib_path.join(":"))
            .arg(&program)
            .arg(tmp.join("hello"))
            .output()
            .expect("run");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hi\n", "{out:?}");
        let sbom = std::fs::read_to_string(can.dir.join("sbom.json")).expect("sbom");
        assert!(sbom.contains("\"specVersion\":\"1.6\""), "{sbom}");
    }

    #[test]
    fn tampered_layout_and_install_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = std::fs::canonicalize(dir.path()).expect("canonical");
        let packed = pack_cat(&tmp);
        let data = tmp.join("data");

        // A blob in the layout changed: refused before anything is installed.
        let reader = crate::layout::Reader::open(&packed.dir).expect("open");
        let can = reader.can().expect("can");
        let file = can.manifest.layers[2].digest.parse().expect("digest");
        let blob = reader.blob_path(&file);
        let mut bytes = std::fs::read(&blob).expect("read");
        bytes[100] ^= 0xff;
        std::fs::write(&blob, &bytes).expect("write");
        match crate::install::install(&packed.dir, &data) {
            Err(Error::Store(_)) => {}
            other => panic!("expected a store error, got {other:?}"),
        }
        bytes[100] ^= 0xff;
        std::fs::write(&blob, &bytes).expect("restore");

        // An installed program changed: refused when opened.
        let can = crate::install::install(&packed.dir, &data).expect("install");
        let program = can.root.join(&can.tree.entrypoint.path);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let mut p = std::fs::read(&program).expect("read");
        p[200] ^= 0xff;
        std::fs::write(&program, &p).expect("tamper");
        assert!(crate::install::open_installed(&can.dir).is_err());
    }

    #[test]
    fn a_can_manifest_cannot_be_packed_again() {
        let m = Manifest::from_toml_str(
            "manifest_version = 2\nname = \"x\"\nversion = \"1\"\n[entrypoint]\npath = \"$CAN/usr/bin/x\"\n",
        )
        .expect("manifest");
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(crate::pack::pack(&m, dir.path(), &dir.path().join("x.can")).is_err());
    }
}
