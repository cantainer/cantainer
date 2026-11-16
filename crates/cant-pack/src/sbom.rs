//! A CycloneDX 1.6 SBOM for a can (spec §6): one component per package that contributed
//! files, and one `file` component per shipped file with its SHA-256.
//!
//! Package ownership comes from the packing machine's package manager (`dpkg-query`, or
//! `rpm`). Files no package owns are listed without one. Licenses are not filled in yet.

use std::collections::BTreeMap;
use std::process::Command;

use serde_json::{Value, json};

/// A shipped file: its path in the can, the host file it came from, and its digest.
pub struct Shipped<'a> {
    pub path: &'a str,
    pub host: &'a std::path::Path,
    pub digest: &'a str,
}

#[derive(Debug, Clone)]
struct Package {
    name: String,
    version: String,
    arch: String,
    kind: &'static str, // "deb" or "rpm"
}

fn os_release() -> (String, String) {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_default()
    };
    (get("ID"), get("VERSION_ID"))
}

/// Owner package of each host path, by asking dpkg (in one call) or rpm.
fn owners(paths: &[&std::path::Path]) -> BTreeMap<std::path::PathBuf, Package> {
    let mut out = BTreeMap::new();
    if paths.is_empty() {
        return out;
    }
    if let Ok(o) = Command::new("dpkg-query").arg("-S").args(paths).output() {
        let text = String::from_utf8_lossy(&o.stdout);
        let mut names: Vec<String> = Vec::new();
        for line in text.lines() {
            // "libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6"
            let Some((pkgs, path)) = line.split_once(": ") else {
                continue;
            };
            let pkg = pkgs.split(", ").next().unwrap_or(pkgs);
            let (name, arch) = pkg.split_once(':').unwrap_or((pkg, ""));
            names.push(name.to_string());
            out.insert(
                std::path::PathBuf::from(path),
                Package {
                    name: name.into(),
                    version: String::new(),
                    arch: arch.into(),
                    kind: "deb",
                },
            );
        }
        names.sort();
        names.dedup();
        if !names.is_empty() {
            if let Ok(v) = Command::new("dpkg-query")
                .args(["-W", "-f", "${Package} ${Version} ${Architecture}\n"])
                .args(&names)
                .output()
            {
                let text = String::from_utf8_lossy(&v.stdout);
                let versions: BTreeMap<&str, (&str, &str)> = text
                    .lines()
                    .filter_map(|l| {
                        let mut p = l.split(' ');
                        Some((p.next()?, (p.next()?, p.next()?)))
                    })
                    .collect();
                for pkg in out.values_mut() {
                    if let Some((ver, arch)) = versions.get(pkg.name.as_str()) {
                        pkg.version = (*ver).to_string();
                        pkg.arch = (*arch).to_string();
                    }
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    for path in paths {
        if let Ok(o) = Command::new("rpm")
            .args([
                "-qf",
                "--queryformat",
                "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n",
            ])
            .arg(path)
            .output()
        {
            if !o.status.success() {
                continue;
            }
            let text = String::from_utf8_lossy(&o.stdout);
            let mut p = text.split_whitespace();
            if let (Some(n), Some(v), Some(a)) = (p.next(), p.next(), p.next()) {
                out.insert(
                    path.to_path_buf(),
                    Package {
                        name: n.into(),
                        version: v.into(),
                        arch: a.into(),
                        kind: "rpm",
                    },
                );
            }
        }
    }
    out
}

fn purl(p: &Package, distro: &(String, String)) -> String {
    format!(
        "pkg:{}/{}/{}@{}?arch={}&distro={}-{}",
        p.kind, distro.0, p.name, p.version, p.arch, distro.0, distro.1
    )
}

/// The SBOM document.
pub fn build(name: &str, version: &str, files: &[Shipped<'_>], timestamp: &str) -> Value {
    let distro = os_release();
    let hosts: Vec<&std::path::Path> = files.iter().map(|f| f.host).collect();
    let owners = owners(&hosts);
    let mut packages: BTreeMap<String, Value> = BTreeMap::new();
    let mut components: Vec<Value> = Vec::new();
    for f in files {
        let owner = owners.get(f.host).filter(|p| !p.version.is_empty());
        let mut file = json!({
            "type": "file",
            "bom-ref": format!("file:{}", f.path),
            "name": f.path,
            "hashes": [{ "alg": "SHA-256", "content": f.digest.trim_start_matches("sha256:") }],
        });
        if let Some(p) = owner {
            let purl = purl(p, &distro);
            packages.entry(purl.clone()).or_insert_with(|| {
                json!({ "type": "library", "bom-ref": purl, "name": p.name, "version": p.version, "purl": purl })
            });
            file["properties"] = json!([{ "name": "cantainer:package", "value": purl }]);
        } else {
            file["properties"] = json!([{ "name": "cantainer:package", "value": "unknown" }]);
        }
        components.push(file);
    }
    let mut all: Vec<Value> = packages.into_values().collect();
    all.extend(components);
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": { "components": [{ "type": "application", "name": "cant", "version": env!("CARGO_PKG_VERSION") }] },
            "component": { "type": "application", "bom-ref": "can", "name": name, "version": version },
        },
        "components": all,
    })
}
