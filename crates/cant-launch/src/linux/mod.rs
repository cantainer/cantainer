//! Linux implementation of planning and launching.

pub mod elf;
pub mod landlock;
pub mod seccomp;

use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use cant_manifest::Manifest;
use cant_policy::{
    Access, Built, Grant, Origin, Policy, display_path, intersect, not_permitted_by,
};

use crate::{DYNAMIC_LOADERS, LaunchError, POLICY_ENV, Plan, RUNTIME_READ, RUNTIME_READ_WRITE};

fn add_existing(policy: &mut Policy, path: &Path, access: Access, origin: Origin) {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        policy.add(Grant {
            path: canonical,
            access,
            origin,
            create: false,
        });
    }
}

pub fn plan(
    manifest: &Manifest,
    built: Built,
    user_args: &[OsString],
    parent: Option<&Policy>,
    home: &Path,
) -> Result<Plan, LaunchError> {
    let mut policy = built.policy;
    let mut missing_libs = Vec::new();

    for path in RUNTIME_READ {
        add_existing(&mut policy, Path::new(path), Access::R, Origin::Runtime);
    }
    for path in RUNTIME_READ_WRITE {
        add_existing(&mut policy, Path::new(path), Access::RW, Origin::Runtime);
    }
    let executes_a_directory = policy
        .grants
        .iter()
        .any(|g| g.access.contains(Access::RX) && g.path.is_dir());
    if executes_a_directory {
        for path in DYNAMIC_LOADERS {
            add_existing(&mut policy, Path::new(path), Access::RX, Origin::Runtime);
        }
    }

    // Inside another cant, its rights bound ours: say so plainly if it can't run the program.
    if let Some(parent) = parent {
        if !parent
            .access_at(&built.program_canonical)
            .contains(Access::RX)
        {
            return Err(LaunchError::ParentCannotRun {
                cant: manifest.name.clone(),
                shown: display_path(&built.program_canonical, home),
            });
        }
    }

    // The entrypoint must be a usable ELF executable; exec targets are best effort.
    let main = elf::resolve(&built.program_canonical)?;
    let mut resolved = vec![main];
    for target in &built.exec_targets {
        if let Ok(r) = elf::resolve(target) {
            resolved.push(r);
        }
    }
    for r in resolved {
        if let Some(interp) = &r.interpreter {
            add_existing(&mut policy, interp, Access::RX, Origin::Library);
        }
        for lib in &r.libs {
            add_existing(&mut policy, lib, Access::R, Origin::Library);
        }
        for name in r.missing {
            if !missing_libs.contains(&name) {
                missing_libs.push(name);
            }
        }
    }

    let effective = match parent {
        Some(parent) => {
            // Refuse early, with a clear message, when the enclosing cant does not allow a
            // file the user named. Everything else is left to the kernel (and --explain).
            if let Some(g) = not_permitted_by(parent, &policy)
                .into_iter()
                .find(|g| matches!(g.origin, Origin::Argument { .. }))
            {
                return Err(LaunchError::ParentDenies {
                    cant: manifest.name.clone(),
                    verb: g.access.verb(),
                    shown: display_path(&g.path, home),
                });
            }
            intersect(parent, &policy)
        }
        None => policy.clone(),
    };

    let mut env: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| k != POLICY_ENV && k.to_str().is_some_and(|k| policy.passes_env(k)))
        .collect();
    for (name, value) in &built.env_set {
        env.retain(|(k, _)| k != name.as_str());
        env.push((name.into(), value.clone()));
    }
    if let Ok(text) = effective.to_toml() {
        env.push((POLICY_ENV.into(), text.into()));
    }

    let argv0 = built
        .program
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| built.program.clone().into_os_string());
    let mut args: Vec<OsString> = manifest
        .entrypoint
        .args
        .iter()
        .map(OsString::from)
        .collect();
    args.extend(user_args.iter().cloned());

    Ok(Plan {
        cant: manifest.name.clone(),
        program: built.program_canonical,
        argv0,
        args,
        env,
        policy,
        effective,
        nested: parent.is_some(),
        missing_libs,
    })
}

/// Creates a writable command-line file that does not exist yet. `create_new` uses
/// `O_EXCL`, which also refuses to follow a symlink planted at that name.
fn create_pending(path: &PathBuf) -> Result<(), LaunchError> {
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // Created in the meantime. Accept a regular file, nothing else.
            match std::fs::symlink_metadata(path) {
                Ok(m) if m.file_type().is_file() => Ok(()),
                _ => Err(LaunchError::Create {
                    path: path.clone(),
                    source: e,
                }),
            }
        }
        Err(source) => Err(LaunchError::Create {
            path: path.clone(),
            source,
        }),
    }
}

pub fn exec(plan: Plan, warn: &mut dyn FnMut(&str)) -> LaunchError {
    match enforce(&plan, warn) {
        Ok(()) => {}
        Err(e) => return e,
    }
    let source = Command::new(&plan.program)
        .arg0(&plan.argv0)
        .args(&plan.args)
        .env_clear()
        .envs(plan.env.iter().map(|(k, v)| (k, v)))
        .exec();
    LaunchError::Exec {
        program: plan.program,
        source,
    }
}

fn enforce(plan: &Plan, warn: &mut dyn FnMut(&str)) -> Result<(), LaunchError> {
    for g in plan.policy.grants.iter().filter(|g| g.create) {
        create_pending(&g.path)?;
    }
    let enforced = landlock::restrict(&plan.policy)?;
    if !plan.policy.network && enforced.abi < 4 {
        warn(&format!(
            "note: kernel Landlock ABI is {} (< 4), so there are no Landlock network rules; \
             network access is blocked by seccomp only",
            enforced.abi
        ));
    }
    seccomp::install(&plan.policy)?;
    Ok(())
}
