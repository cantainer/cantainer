//! `capabilities.cants`: a cant that may run other cants.
//!
//! Rights only shrink down a chain of cants: a nested `cant run git` gets the intersection of
//! git's manifest and the enclosing cant's rights. So a cant that should run git must already
//! hold everything git needs. Instead of repeating git's grants, a manifest lists
//! `cants = ["git"]`, and this module adds git's grants (built exactly as `cant run git` would,
//! without command-line files), git's executable, `cant` itself, and the manifest directories.
//!
//! Files later named on a nested cant's command line still have to be within the enclosing
//! cant's own grants (typically `fs.rw = ["$CWD"]`).

use std::collections::BTreeSet;
use std::path::Path;

use cant_manifest::Manifest;
use cant_policy::{Access, Built, Context, Grant, Origin, PolicyError, Skipped};

use crate::catalog::Catalog;

/// Paths the nested `cant` reads to plan a launch (library search configuration).
const CANT_READS: &[&str] = &["/etc/ld.so.conf", "/etc/ld.so.conf.d"];

/// Adds the rights of every cant in `manifest.capabilities.cants` (and of the cants those may
/// run) to `built`. A listed cant whose program isn't installed is skipped and reported in
/// `built.skipped`; any other problem with one is an error naming it.
pub fn include_cants(
    manifest: &Manifest,
    built: &mut Built,
    ctx: &Context,
    catalog: &Catalog,
) -> Result<(), String> {
    if manifest.capabilities.cants.is_empty() {
        return Ok(());
    }
    let mut seen = BTreeSet::from([manifest.name.clone()]);
    let mut queue: Vec<String> = manifest.capabilities.cants.clone();
    while let Some(name) = queue.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let found = catalog
            .find(&name)
            .map_err(|e| format!("{} may run `{name}`, but {e}", manifest.name))?;
        let child = match cant_policy::build(&found.manifest, ctx, &[], &[]) {
            Ok(child) => child,
            Err(PolicyError::ProgramNotFound { .. }) => {
                built.skipped.push(Skipped {
                    path: found.manifest.entrypoint.path.clone().into(),
                    origin: Origin::Cant { name },
                });
                continue;
            }
            Err(e) => return Err(format!("{} may run `{name}`, but {e}", manifest.name)),
        };
        let origin = Origin::Cant { name: name.clone() };
        for g in child.policy.grants {
            built.policy.add(Grant {
                origin: origin.clone(),
                ..g
            });
        }
        built.policy.network |= child.policy.network;
        built.policy.unix_sockets |= child.policy.unix_sockets;
        for pattern in child.policy.env {
            if !built.policy.env.contains(&pattern) {
                built.policy.env.push(pattern);
            }
        }
        built.exec_targets.push(child.program_canonical);
        built.exec_targets.extend(child.exec_targets);
        built
            .skipped
            .extend(child.skipped.into_iter().map(|s| Skipped {
                origin: origin.clone(),
                ..s
            }));
        queue.extend(found.manifest.capabilities.cants.iter().cloned());
    }

    // `cant` itself: its executable, the manifests it looks up, its library configuration.
    let launcher = Origin::Cant {
        name: "cant".into(),
    };
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("cannot find the cant executable: {e}"))?;
    built.policy.add(Grant {
        path: exe.clone(),
        access: Access::RX,
        origin: launcher.clone(),
        create: false,
    });
    built.exec_targets.push(exe);
    let reads = catalog
        .dirs
        .iter()
        .map(|d| d.as_path())
        .chain(CANT_READS.iter().map(Path::new));
    for path in reads {
        if let Ok(canonical) = std::fs::canonicalize(path) {
            built.policy.add(Grant {
                path: canonical,
                access: Access::R,
                origin: launcher.clone(),
                create: false,
            });
        }
    }
    Ok(())
}
