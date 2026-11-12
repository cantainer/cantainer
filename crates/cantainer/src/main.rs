//! `cant`: run executables as least-privilege capsules. By default, you can't.
//!
//! There is no cantainerd. No daemon. You cant.

#![forbid(unsafe_code)]

mod catalog;
mod compose;
mod scaffold;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cant_launch::{LaunchError, POLICY_ENV, Plan};
use cant_policy::{Context, Origin, Policy, PolicyError, UserGrant, display_path};
use catalog::{Catalog, Found};
use clap::{CommandFactory, Parser, Subcommand};

/// Appends a line to a command's output. Commands write into a buffer that `main` prints, so a
/// closed pipe (`cant list | head`) ends `cant` quietly instead of panicking in `println`.
macro_rules! outln {
    ($out:expr) => {
        $out.push('\n')
    };
    ($out:expr, $($arg:tt)*) => {{
        use std::fmt::Write as _;
        let _ = writeln!($out, $($arg)*); // writing to a String can't fail
    }};
}

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
    /// Print a cant's manifest, e.g. to customize it:
    /// `cant show git > ~/.config/cantainer/cants/git.toml`
    Show {
        /// Cant name or path to a manifest
        cant: String,
    },
    /// List the cants that `cant run NAME` can find, and where each comes from
    List,
    /// Write a starting manifest for a program to ~/.config/cantainer/cants/, denying everything
    New {
        /// Program name (looked up in the system bin directories) or absolute path
        program: String,
        /// Overwrite an existing manifest, or shadow a built-in one
        #[arg(long)]
        force: bool,
    },
    /// Check whether this kernel can sandbox cants
    Check,
    /// Print a shell completion script: `cant completions bash > /etc/bash_completion.d/cant`
    Completions {
        /// bash, zsh, fish, elvish or powershell
        shell: clap_complete::Shell,
    },
    /// Write the man pages (cant.1, cant-run.1, ...) into DIR, for packaging
    #[command(hide = true)]
    Man {
        /// Existing directory to write into
        dir: PathBuf,
    },
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

    /// Cant name (looked up in ~/.config/cantainer/cants, /etc/cantainer/cants, then the
    /// built-in cants) or path to a manifest
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
    let mut out = String::new();
    let result = match cli.command {
        Command::Run(args) => run(args, &mut out),
        Command::Inspect { cant } => inspect(&cant, &mut out),
        Command::Show { cant } => show(&cant, &mut out),
        Command::List => list(&mut out),
        Command::New { program, force } => new(&program, force, &mut out),
        Command::Check => Ok(check(&mut out)),
        Command::Completions { shell } => generated(&mut out, |buf| {
            clap_complete::generate(shell, &mut Cli::command(), "cant", buf);
            Ok(())
        }),
        Command::Man { dir } => clap_mangen::generate_to(Cli::command(), &dir)
            .map(|()| ExitCode::SUCCESS)
            .map_err(|e| Failure::new(format!("{}: {e}", dir.display()))),
    };
    if let Err(e) = write_stdout(&out) {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("cant: cannot write to standard output: {e}");
        }
        return ExitCode::from(EXIT_CANT);
    }
    match result {
        Ok(code) => code,
        Err(f) => {
            eprintln!("cant: {}", f.message);
            ExitCode::from(f.code)
        }
    }
}

fn write_stdout(out: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(out.as_bytes())?;
    stdout.flush()
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

fn locate(name: &str) -> Result<Found, Failure> {
    Catalog::standard(&home_dir()?)
        .find(name)
        .map_err(Failure::new)
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
) -> Result<(Found, Context, Plan, Vec<cant_policy::Skipped>), Failure> {
    let found = locate(name)?;
    let ctx = context()?;
    let mut built = cant_policy::build(&found.manifest, &ctx, args, grants)?;
    compose::include_cants(
        &found.manifest,
        &mut built,
        &ctx,
        &Catalog::standard(&home_dir()?),
    )
    .map_err(Failure::new)?;
    let skipped = built.skipped.clone();
    let parent = parent_policy()?;
    let plan = cant_launch::plan(&found.manifest, built, args, parent.as_ref(), &ctx.home)?;
    Ok((found, ctx, plan, skipped))
}

fn run(args: RunArgs, out: &mut String) -> Result<ExitCode, Failure> {
    let (found, ctx, plan, skipped) = prepare(&args.cant, &args.args, &args.grants)?;
    if args.explain {
        print_explain(out, &found, &ctx, &plan, &skipped);
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
        Origin::Cant { .. } => 6,
        Origin::Runtime => 7,
    }
}

fn yes_no(allowed: bool) -> &'static str {
    if allowed { "allowed" } else { "denied" }
}

fn print_policy(out: &mut String, ctx: &Context, policy: &Policy) {
    outln!(out, "network:      {}", yes_no(policy.network));
    outln!(out, "unix sockets: {}", yes_no(policy.unix_sockets));
    let env: Vec<String> = policy.env.iter().map(ToString::to_string).collect();
    outln!(
        out,
        "env:          {}",
        if env.is_empty() {
            "(none)".to_string()
        } else {
            env.join(", ")
        }
    );
    outln!(out, "files:");
    let mut grants: Vec<_> = policy.grants.iter().collect();
    grants.sort_by(|a, b| {
        origin_rank(&a.origin)
            .cmp(&origin_rank(&b.origin))
            .then(a.path.cmp(&b.path))
    });
    for g in grants {
        let note = if g.create { " (will be created)" } else { "" };
        outln!(
            out,
            "  {:<4} {:<48} {}{note}",
            g.access.to_string(),
            ctx.show(&g.path),
            g.origin
        );
    }
    outln!(out, "  everything else: denied");
}

fn print_explain(
    out: &mut String,
    found: &Found,
    ctx: &Context,
    plan: &Plan,
    skipped: &[cant_policy::Skipped],
) {
    outln!(out, "cant:         {} ({})", plan.cant, found.source);
    outln!(out, "program:      {}", plan.program.display());
    let argv: Vec<String> = std::iter::once(&plan.argv0)
        .chain(plan.args.iter())
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    outln!(out, "argv:         {}", argv.join(" "));
    for (name, value) in &found.manifest.env.set {
        outln!(out, "env set:      {name}={value}");
    }
    if plan.nested {
        outln!(
            out,
            "attenuation:  running inside another cant; showing the intersection"
        );
    }
    print_policy(out, ctx, &plan.effective);
    for s in skipped {
        outln!(
            out,
            "not found, not granted: {} ({})",
            display_path(&s.path, &ctx.home),
            s.origin
        );
    }
    if !plan.missing_libs.is_empty() {
        outln!(out, "libraries not found: {}", plan.missing_libs.join(", "));
    }
}

fn inspect(name: &str, out: &mut String) -> Result<ExitCode, Failure> {
    let (found, ctx, plan, skipped) = prepare(name, &[], &[])?;
    let text = found.text;
    let digest = cant_store::Digest::of_file(&plan.program)
        .map_err(|e| Failure::new(format!("{}: {e}", plan.program.display())))?;
    outln!(out, "manifest: {}", found.source);
    outln!(out, "---");
    out.push_str(&text);
    if !text.ends_with('\n') {
        outln!(out);
    }
    outln!(out, "---");
    outln!(out, "binary:       {}", plan.program.display());
    outln!(out, "digest:       {digest}");
    outln!(out, "capabilities (without command-line files):");
    print_policy(out, &ctx, &plan.effective);
    for s in skipped {
        outln!(
            out,
            "not found, not granted: {} ({})",
            display_path(&s.path, &ctx.home),
            s.origin
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn show(name: &str, out: &mut String) -> Result<ExitCode, Failure> {
    let found = locate(name)?;
    out.push_str(&found.text);
    if !found.text.ends_with('\n') {
        outln!(out);
    }
    Ok(ExitCode::SUCCESS)
}

fn list(out: &mut String) -> Result<ExitCode, Failure> {
    for entry in Catalog::standard(&home_dir()?).list() {
        let description = entry
            .description
            .unwrap_or_else(|e| format!("(invalid: {e})"));
        outln!(out, "{:<12} {description:<60} {}", entry.name, entry.source);
    }
    Ok(ExitCode::SUCCESS)
}

fn new(program: &str, force: bool, out: &mut String) -> Result<ExitCode, Failure> {
    let (name, entry, found) = if program.contains('/') {
        let found =
            std::fs::canonicalize(program).map_err(|e| Failure::new(format!("{program}: {e}")))?;
        let name = found
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| Failure::new(format!("{program}: no usable file name")))?;
        (name, found.display().to_string(), found)
    } else {
        let found = cant_policy::find_program(program).ok_or_else(|| {
            Failure::new(format!(
                "no program `{program}` in {}; give its absolute path instead",
                cant_policy::SYSTEM_BIN_DIRS.join(", ")
            ))
        })?;
        (program.to_owned(), program.to_owned(), found)
    };
    cant_manifest::validate_name(&name).map_err(Failure::new)?;

    let catalog = Catalog::standard(&home_dir()?);
    let dest = scaffold::destination(&catalog.dirs[0], &name);
    if !force {
        if dest.exists() {
            return Err(Failure::new(format!(
                "{} already exists (--force overwrites it)",
                dest.display()
            )));
        }
        if catalog::BUILTIN.iter().any(|(n, _)| *n == name) {
            return Err(Failure::new(format!(
                "`{name}` has a built-in manifest; to customize it: cant show {name} > {} \
                 (--force writes an empty one instead)",
                dest.display()
            )));
        }
    }
    let dir = dest.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| Failure::new(format!("{}: {e}", dir.display())))?;
    std::fs::write(&dest, scaffold::template(&name, &entry, &found))
        .map_err(|e| Failure::new(format!("{}: {e}", dest.display())))?;
    outln!(out, "wrote {}", dest.display());
    outln!(
        out,
        "It denies everything. Edit it, then check a run with: cant run --explain {name} ARGS..."
    );
    Ok(ExitCode::SUCCESS)
}

/// Runs a generator that writes bytes (completions, man page) into the output buffer.
fn generated(
    out: &mut String,
    generate: impl FnOnce(&mut Vec<u8>) -> std::io::Result<()>,
) -> Result<ExitCode, Failure> {
    let mut buf = Vec::new();
    generate(&mut buf).map_err(|e| Failure::new(e.to_string()))?;
    out.push_str(&String::from_utf8_lossy(&buf));
    Ok(ExitCode::SUCCESS)
}

fn check(out: &mut String) -> ExitCode {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| std::env::consts::OS.to_owned());
    outln!(out, "kernel:   {release}");
    let support = cant_launch::probe_kernel();
    let mut ok = true;
    match support.landlock_abi {
        Some(abi) if abi >= 4 => {
            outln!(out, "landlock: ABI {abi} (filesystem and TCP rules)");
        }
        Some(abi) if abi >= 3 => {
            outln!(
                out,
                "landlock: ABI {abi} (filesystem rules; no TCP rules, seccomp blocks network)"
            );
        }
        Some(abi) => {
            outln!(
                out,
                "landlock: ABI {abi} (too old: at least 3 / Linux 6.2 is required)"
            );
            ok = false;
        }
        None => {
            outln!(
                out,
                "landlock: not available (kernel without Landlock, or not in the `lsm=` list)"
            );
            ok = false;
        }
    }
    outln!(
        out,
        "seccomp:  {}",
        if support.seccomp_arch {
            format!("supported on {}", std::env::consts::ARCH)
        } else {
            ok = false;
            format!("not supported on {}", std::env::consts::ARCH)
        }
    );
    if ok {
        outln!(out, "ok: cants can run here");
        ExitCode::SUCCESS
    } else {
        outln!(out, "cants cannot run here");
        ExitCode::from(1)
    }
}
