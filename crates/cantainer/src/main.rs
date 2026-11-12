//! `cant`: run executables as least-privilege capsules. By default, you can't.
//!
//! There is no cantainerd. No daemon. You cant.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cant_launch::{LaunchError, POLICY_ENV, Plan};
use cant_manifest::{Manifest, validate_name};
use cant_policy::{Context, Origin, Policy, PolicyError, UserGrant, display_path};
use clap::{Parser, Subcommand};

/// Exit status for refusals and errors of `cant` itself (as `env`, `nohup` and container
/// runtimes do), so they are distinguishable from the program's own exit status.
const EXIT_CANT: u8 = 125;
const EXIT_NOT_EXECUTABLE: u8 = 126;
const EXIT_NOT_FOUND: u8 = 127;

#[derive(Debug, Parser)]
#[command(
    name = "cant",
    version,
    about = "Run executables as least-privilege capsules. By default, you can't.",
    after_help = "There is no cantainerd. No daemon. You cant."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a cant: `cant run cat notes.txt`
    Run(RunArgs),
    /// Show a cant's manifest, binary, digest and capabilities
    Inspect {
        /// Cant name or path to a manifest
        cant: String,
    },
    /// List the cants that `cant run NAME` can find
    List,
    /// Check whether this kernel can sandbox cants
    Check,
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Print the effective policy and exit without running anything
    #[arg(long)]
    explain: bool,

    /// Also grant PATH (default access `r`; `rw`, `rx`, `rwx` also accepted). Needed to reach
    /// protected paths such as ~/.ssh. Repeatable.
    #[arg(long = "grant", value_name = "PATH[:ACCESS]")]
    grants: Vec<UserGrant>,

    /// Cant name (looked up in ~/.config/cantainer/cants, then ./examples) or manifest path
    cant: String,

    /// Arguments for the program. Files named here are granted as the manifest declares.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<OsString>,
}

/// A failure, already phrased for the user, with the exit status to use.
#[derive(Debug)]
struct Failure {
    message: String,
    code: u8,
}

impl Failure {
    fn new(message: impl Into<String>) -> Self {
        Failure {
            message: message.into(),
            code: EXIT_CANT,
        }
    }
}

impl From<PolicyError> for Failure {
    fn from(e: PolicyError) -> Self {
        Failure::new(e.to_string())
    }
}

impl From<LaunchError> for Failure {
    fn from(e: LaunchError) -> Self {
        let code = match &e {
            LaunchError::Exec { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                EXIT_NOT_FOUND
            }
            LaunchError::Exec { .. } => EXIT_NOT_EXECUTABLE,
            _ => EXIT_CANT,
        };
        Failure {
            message: e.to_string(),
            code,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run(args),
        Command::Inspect { cant } => inspect(&cant),
        Command::List => list(),
        Command::Check => Ok(check()),
    };
    match result {
        Ok(code) => code,
        Err(f) => {
            eprintln!("cant: {}", f.message);
            ExitCode::from(f.code)
        }
    }
}

fn home_dir() -> Result<PathBuf, Failure> {
    match std::env::var_os("HOME") {
        Some(h) if Path::new(&h).is_absolute() => Ok(PathBuf::from(h)),
        _ => Err(Failure::new("HOME is not set to an absolute path")),
    }
}

fn context() -> Result<Context, Failure> {
    let home = home_dir()?;
    let home = std::fs::canonicalize(&home).unwrap_or(home);
    let cwd = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|e| Failure::new(format!("cannot determine the current directory: {e}")))?;
    Ok(Context::new(home, cwd))
}

/// Directories searched for `NAME.toml`, in order.
fn search_dirs() -> Result<Vec<PathBuf>, Failure> {
    let config = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(c) if Path::new(&c).is_absolute() => PathBuf::from(c),
        _ => home_dir()?.join(".config"),
    };
    Ok(vec![
        config.join("cantainer").join("cants"),
        PathBuf::from("examples"),
    ])
}

fn locate(name: &str) -> Result<(PathBuf, Manifest), Failure> {
    let path = if name.contains('/') || name.ends_with(".toml") {
        PathBuf::from(name)
    } else {
        validate_name(name).map_err(Failure::new)?;
        let dirs = search_dirs()?;
        let found = dirs
            .iter()
            .map(|d| d.join(format!("{name}.toml")))
            .find(|p| p.is_file());
        match found {
            Some(p) => p,
            None => {
                let looked: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
                return Err(Failure::new(format!(
                    "no cant named `{name}` (looked in {})",
                    looked.join(" and ")
                )));
            }
        }
    };
    let manifest =
        Manifest::from_file(&path).map_err(|e| Failure::new(format!("{}: {e}", path.display())))?;
    Ok((path, manifest))
}

fn parent_policy() -> Result<Option<Policy>, Failure> {
    match std::env::var(POLICY_ENV) {
        Ok(text) => Policy::from_toml(&text)
            .map(Some)
            .map_err(|e| LaunchError::ParentPolicy(e.to_string()).into()),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(LaunchError::ParentPolicy("not UTF-8".into()).into())
        }
    }
}

fn prepare(
    name: &str,
    args: &[OsString],
    grants: &[UserGrant],
) -> Result<(PathBuf, Manifest, Context, Plan, Vec<cant_policy::Skipped>), Failure> {
    let (path, manifest) = locate(name)?;
    let ctx = context()?;
    let built = cant_policy::build(&manifest, &ctx, args, grants)?;
    let skipped = built.skipped.clone();
    let parent = parent_policy()?;
    let plan = cant_launch::plan(&manifest, built, args, parent.as_ref(), &ctx.home)?;
    Ok((path, manifest, ctx, plan, skipped))
}

fn run(args: RunArgs) -> Result<ExitCode, Failure> {
    let (path, _manifest, ctx, plan, skipped) = prepare(&args.cant, &args.args, &args.grants)?;
    if args.explain {
        print_explain(&path, &ctx, &plan, &skipped);
        return Ok(ExitCode::SUCCESS);
    }
    let mut warn = |msg: &str| eprintln!("cant: {msg}");
    Err(cant_launch::exec(plan, &mut warn).into())
}

fn origin_rank(o: &Origin) -> u8 {
    match o {
        Origin::Argument { .. } => 0,
        Origin::User => 1,
        Origin::Manifest => 2,
        Origin::ManifestExec => 3,
        Origin::Executable => 4,
        Origin::Library => 5,
        Origin::Runtime => 6,
    }
}

fn yes_no(allowed: bool) -> &'static str {
    if allowed { "allowed" } else { "denied" }
}

fn print_policy(ctx: &Context, policy: &Policy) {
    println!("network:      {}", yes_no(policy.network));
    println!("unix sockets: {}", yes_no(policy.unix_sockets));
    let env: Vec<String> = policy.env.iter().map(ToString::to_string).collect();
    println!(
        "env:          {}",
        if env.is_empty() {
            "(none)".to_string()
        } else {
            env.join(", ")
        }
    );
    println!("files:");
    let mut grants: Vec<_> = policy.grants.iter().collect();
    grants.sort_by(|a, b| {
        origin_rank(&a.origin)
            .cmp(&origin_rank(&b.origin))
            .then(a.path.cmp(&b.path))
    });
    for g in grants {
        let note = if g.create { " (will be created)" } else { "" };
        println!(
            "  {:<4} {:<48} {}{note}",
            g.access.to_string(),
            ctx.show(&g.path),
            g.origin
        );
    }
    println!("  everything else: denied");
}

fn print_explain(path: &Path, ctx: &Context, plan: &Plan, skipped: &[cant_policy::Skipped]) {
    println!("cant:         {} ({})", plan.cant, path.display());
    println!("program:      {}", plan.program.display());
    let argv: Vec<String> = std::iter::once(&plan.argv0)
        .chain(plan.args.iter())
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    println!("argv:         {}", argv.join(" "));
    if plan.nested {
        println!("attenuation:  running inside another cant; showing the intersection");
    }
    print_policy(ctx, &plan.effective);
    for s in skipped {
        println!(
            "not found, not granted: {} ({})",
            display_path(&s.path, &ctx.home),
            s.origin
        );
    }
    if !plan.missing_libs.is_empty() {
        println!("libraries not found: {}", plan.missing_libs.join(", "));
    }
}

fn inspect(name: &str) -> Result<ExitCode, Failure> {
    let (path, _manifest, ctx, plan, skipped) = prepare(name, &[], &[])?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Failure::new(format!("{}: {e}", path.display())))?;
    let digest = cant_store::Digest::of_file(&plan.program)
        .map_err(|e| Failure::new(format!("{}: {e}", plan.program.display())))?;
    println!("manifest: {}", path.display());
    println!("---");
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    println!("---");
    println!("binary:       {}", plan.program.display());
    println!("digest:       {digest}");
    println!("capabilities (without command-line files):");
    print_policy(&ctx, &plan.effective);
    for s in skipped {
        println!(
            "not found, not granted: {} ({})",
            display_path(&s.path, &ctx.home),
            s.origin
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn list() -> Result<ExitCode, Failure> {
    let mut seen = std::collections::BTreeSet::new();
    for dir in search_dirs()? {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<(String, PathBuf)> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .filter_map(|p| Some((p.file_stem()?.to_str()?.to_owned(), p)))
            .collect();
        names.sort();
        for (name, path) in names {
            if !seen.insert(name.clone()) {
                continue; // shadowed by an earlier directory
            }
            let description = Manifest::from_file(&path)
                .map(|m| m.description.unwrap_or_default())
                .unwrap_or_else(|e| {
                    format!("(invalid: {})", e.to_string().lines().next().unwrap_or(""))
                });
            println!("{name:<12} {description:<60} {}", path.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn check() -> ExitCode {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| std::env::consts::OS.to_owned());
    println!("kernel:   {release}");
    let support = cant_launch::probe_kernel();
    let mut ok = true;
    match support.landlock_abi {
        Some(abi) if abi >= 4 => {
            println!("landlock: ABI {abi} (filesystem and TCP rules)");
        }
        Some(abi) if abi >= 3 => {
            println!(
                "landlock: ABI {abi} (filesystem rules; no TCP rules, seccomp blocks network)"
            );
        }
        Some(abi) => {
            println!("landlock: ABI {abi} (too old: at least 3 / Linux 6.2 is required)");
            ok = false;
        }
        None => {
            println!(
                "landlock: not available (kernel without Landlock, or not in the `lsm=` list)"
            );
            ok = false;
        }
    }
    println!(
        "seccomp:  {}",
        if support.seccomp_arch {
            format!("supported on {}", std::env::consts::ARCH)
        } else {
            ok = false;
            format!("not supported on {}", std::env::consts::ARCH)
        }
    );
    if ok {
        println!("ok: cants can run here");
        ExitCode::SUCCESS
    } else {
        println!("cants cannot run here");
        ExitCode::from(1)
    }
}
