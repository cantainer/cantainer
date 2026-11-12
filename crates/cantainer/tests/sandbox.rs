//! End-to-end tests of the sandbox against the running kernel.
//!
//! Each test builds a throwaway HOME (with a fake `~/.ssh/id_rsa`) and working directory,
//! runs the real `cant` binary, and checks what the kernel allowed. Tests skip, with a message,
//! when the kernel cannot sandbox (`cant check` fails) or a needed program is missing.

#![cfg(target_os = "linux")]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CANT: &str = env!("CARGO_BIN_EXE_cant");

/// Whether sandbox tests can run here; prints why not.
fn supported() -> bool {
    let out = Command::new(CANT)
        .arg("check")
        .output()
        .expect("run cant check");
    if !out.status.success() {
        eprintln!(
            "SKIP: kernel cannot sandbox cants:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        return false;
    }
    true
}

fn have(program: &str) -> bool {
    let found = cant_policy::find_program(program).is_some();
    if !found {
        eprintln!("SKIP: {program} is not installed");
    }
    found
}

struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    work: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        let home = root.join("home");
        let work = home.join("proj");
        std::fs::create_dir_all(home.join(".ssh")).expect("mkdir");
        std::fs::create_dir_all(&work).expect("mkdir");
        std::fs::write(home.join(".ssh/id_rsa"), "PRIVATE KEY\n").expect("write");
        std::fs::write(work.join("notes.txt"), "hello\n").expect("write");
        Fixture {
            _tmp: tmp,
            home,
            work,
        }
    }

    /// Writes a manifest into the working directory and returns its path.
    fn manifest(&self, name: &str, body: &str) -> PathBuf {
        let path = self.home.join(format!("{name}.toml"));
        let text = format!("manifest_version = 1\nname = \"{name}\"\nversion = \"0.0.0\"\n{body}");
        std::fs::write(&path, text).expect("write manifest");
        path
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(CANT);
        c.args(args)
            .current_dir(&self.work)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C");
        c
    }

    fn cant(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run cant")
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---- The demo -------------------------------------------------------------------------------

#[test]
fn demo_cat_secret_is_denied() {
    if !supported() || !have("cat") {
        return;
    }
    let f = Fixture::new();
    let key = f.home.join(".ssh/id_rsa");
    let o = f.cant(&["run", "cat", key.to_str().expect("utf8")]);
    assert_eq!(o.status.code(), Some(125), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("cant: cat can't read ~/.ssh/id_rsa (~/.ssh is protected)"),
        "{}",
        stderr(&o)
    );
    assert!(!stdout(&o).contains("PRIVATE KEY"));
}

#[test]
fn demo_cat_named_file_works() {
    if !supported() || !have("cat") {
        return;
    }
    let f = Fixture::new();
    let o = f.cant(&["run", "cat", "notes.txt"]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o), "hello\n");
}

#[test]
fn demo_curl_has_no_network() {
    if !supported() || !have("curl") {
        return;
    }
    let f = Fixture::new();
    // A local server, so the test needs no internet and proves the sandbox (not the
    // environment) blocked the connection.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let url = format!("http://{}/", listener.local_addr().expect("addr"));
    let o = f.cant(&["run", "curl", "-sS", "--max-time", "5", &url]);
    assert!(!o.status.success(), "curl must fail: {}", stdout(&o));
    assert!(
        listener.accept().is_err(),
        "the sandboxed curl reached the listener"
    );
}

#[test]
fn demo_vim_edits_only_the_named_file() {
    if !supported() || !have("vim") {
        return;
    }
    let f = Fixture::new();
    let o = f.cant(&[
        "run",
        "vim",
        "-es",
        "-c",
        "normal Goworld",
        "-c",
        "wq",
        "notes.txt",
    ]);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(
        std::fs::read_to_string(f.work.join("notes.txt")).expect("read"),
        "hello\nworld\n"
    );

    let other = f.work.join("other.txt");
    let cmd = format!("w! {}", other.display());
    let o = f.cant(&["run", "vim", "-es", "-c", &cmd, "-c", "q!", "notes.txt"]);
    assert!(!o.status.success());
    assert!(!other.exists(), "vim wrote a file it was not given");
}

// ---- Powerbox and protection -----------------------------------------------------------------

#[test]
fn ungranted_file_is_denied_by_the_kernel() {
    if !supported() || !have("cat") {
        return;
    }
    let f = Fixture::new();
    // Operands are not files for this cant, so nothing is granted and Landlock says no.
    let m = f.manifest("blindcat", "[entrypoint]\npath = \"cat\"\n");
    let o = f.cant(&["run", m.to_str().expect("utf8"), "notes.txt"]);
    assert!(!o.status.success());
    assert!(stderr(&o).contains("Permission denied"), "{}", stderr(&o));
}

#[test]
fn symlink_to_secret_is_refused() {
    if !supported() || !have("cat") {
        return;
    }
    let f = Fixture::new();
    std::os::unix::fs::symlink(f.home.join(".ssh/id_rsa"), f.work.join("innocent.txt"))
        .expect("symlink");
    let o = f.cant(&["run", "cat", "innocent.txt"]);
    assert_eq!(o.status.code(), Some(125));
    assert!(stderr(&o).contains("~/.ssh/id_rsa"), "{}", stderr(&o));
}

#[test]
fn explicit_grant_unlocks_a_protected_file() {
    if !supported() || !have("cat") {
        return;
    }
    let f = Fixture::new();
    let key = f.home.join(".ssh/id_rsa");
    let key = key.to_str().expect("utf8");
    let o = f.cant(&["run", "--grant", key, "cat", key]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o), "PRIVATE KEY\n");
}

#[test]
fn explain_does_not_run() {
    if !have("cat") {
        return;
    }
    let f = Fixture::new();
    let o = f.cant(&["run", "--explain", "cat", "notes.txt"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("~/proj/notes.txt"), "{out}");
    assert!(out.contains("argument 1"), "{out}");
    assert!(out.contains("network:      denied"), "{out}");
    assert!(!out.contains("hello"), "explain must not run cat");
}

// ---- cant new ------------------------------------------------------------------------------

#[test]
fn new_writes_a_deny_all_manifest_that_runs() {
    if !supported() || !have("sh") {
        return;
    }
    let f = Fixture::new();
    let o = f.cant(&["new", "sh"]);
    assert!(o.status.success(), "{}", stderr(&o));
    let written = f.home.join(".config/cantainer/cants/sh.toml");
    assert!(
        stdout(&o).contains(&written.display().to_string()),
        "{}",
        stdout(&o)
    );

    // It runs, by name, and can't read a file it wasn't given.
    let o = f.cant(&["run", "sh", "-c", "exit 3"]);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    let o = f.cant(&["run", "sh", "-c", "read x < notes.txt"]);
    assert!(!o.status.success(), "{}", stderr(&o));

    // Never overwrites without --force, and points at `cant show` for built-in names.
    let o = f.cant(&["new", "sh"]);
    assert_eq!(o.status.code(), Some(125));
    assert!(stderr(&o).contains("already exists"), "{}", stderr(&o));
    let o = f.cant(&["new", "cat"]);
    assert_eq!(o.status.code(), Some(125));
    assert!(stderr(&o).contains("cant show cat"), "{}", stderr(&o));
}

#[test]
fn exec_directories_get_the_dynamic_loader() {
    // A static launcher (rustup on arm64) starting a dynamic build script from $CWD needs
    // execute access to the loader; cant can't resolve libraries for files that don't exist yet.
    let f = Fixture::new();
    let m = f.manifest(
        "runner",
        "[entrypoint]\npath = \"sh\"\n[capabilities]\nexec = [\"$CWD\"]\n",
    );
    let o = f.cant(&["run", "--explain", m.to_str().expect("utf8")]);
    assert!(o.status.success(), "{}", stderr(&o));
    let loader = stdout(&o)
        .lines()
        .find(|l| l.contains("/ld-") && l.ends_with("runtime"))
        .map(str::to_owned);
    assert!(
        loader
            .as_deref()
            .is_some_and(|l| l.trim_start().starts_with("rx")),
        "{}",
        stdout(&o)
    );
}

// ---- Process behaviour -----------------------------------------------------------------------

fn sh_manifest(f: &Fixture, extra: &str) -> PathBuf {
    f.manifest(
        "sh",
        &format!("[entrypoint]\npath = \"sh\"\n[args.options]\n\"-c\" = \"value\"\n{extra}"),
    )
}

#[test]
fn exit_status_passes_through() {
    if !supported() || !have("sh") {
        return;
    }
    let f = Fixture::new();
    let m = sh_manifest(&f, "");
    let o = f.cant(&["run", m.to_str().expect("utf8"), "-c", "exit 42"]);
    assert_eq!(o.status.code(), Some(42));
}

#[test]
fn stdin_passes_through() {
    if !supported() || !have("cat") {
        return;
    }
    let f = Fixture::new();
    let mut child = f
        .command(&["run", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(b"from stdin\n").expect("write");
    }
    let o = child.wait_with_output().expect("wait");
    assert!(o.status.success());
    assert_eq!(stdout(&o), "from stdin\n");
}

#[test]
fn environment_is_filtered() {
    if !supported() || !have("env") {
        return;
    }
    let f = Fixture::new();
    let m = f.manifest(
        "env",
        "[entrypoint]\npath = \"env\"\n[env]\npass = [\"KEEP_*\"]\n",
    );
    let o = f
        .command(&["run", m.to_str().expect("utf8")])
        .env("KEEP_ME", "1")
        .env("DROP_ME", "1")
        .env("LD_PRELOAD", "/nonexistent.so")
        .output()
        .expect("run");
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("KEEP_ME=1"), "{out}");
    assert!(!out.contains("DROP_ME"), "{out}");
    assert!(!out.contains("LD_PRELOAD"), "{out}");
    assert!(!out.contains("HOME="), "{out}");
    assert!(out.contains("CANT_POLICY="), "{out}");
}

#[test]
fn home_entrypoint_and_fixed_environment() {
    if !supported() || !have("env") {
        return;
    }
    let f = Fixture::new();
    let bin = f.home.join("bin");
    std::fs::create_dir_all(&bin).expect("mkdir");
    let env = cant_policy::find_program("env").expect("env");
    std::fs::copy(std::fs::canonicalize(env).expect("env"), bin.join("myenv")).expect("copy");
    let m = f.manifest(
        "myenv",
        "[entrypoint]\npath = \"~/bin/myenv\"\n\
         [env]\npass = [\"KEEP\"]\nset = { KEEP = \"fixed\", OUT = \"$CWD/out\" }\n",
    );
    let o = f
        .command(&["run", m.to_str().expect("utf8")])
        .env("KEEP", "from caller")
        .output()
        .expect("run");
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("KEEP=fixed\n"), "{out}");
    assert!(!out.contains("from caller"), "{out}");
    assert!(
        out.contains(&format!("OUT={}/out\n", f.work.display())),
        "{out}"
    );
}

// ---- seccomp ---------------------------------------------------------------------------------

#[test]
fn namespaces_and_path_chmod_are_blocked() {
    if !supported() || !have("sh") {
        return;
    }
    let f = Fixture::new();
    if have("unshare") {
        let m = f.manifest(
            "unshare",
            "[entrypoint]\npath = \"unshare\"\n[capabilities]\nexec = [\"true\"]\n",
        );
        let o = f.cant(&["run", m.to_str().expect("utf8"), "-U", "true"]);
        assert!(!o.status.success(), "unshare -U must fail");
    }
    if have("chmod") {
        let m = f.manifest(
            "chmod",
            "[entrypoint]\npath = \"chmod\"\n[args]\noperands = \"rw\"\n",
        );
        let o = f.cant(&["run", m.to_str().expect("utf8"), "600", "notes.txt"]);
        assert!(!o.status.success(), "path-based chmod must fail");
        assert!(stderr(&o).contains("not permitted"), "{}", stderr(&o));
    }
}

// ---- Attenuation -----------------------------------------------------------------------------

#[test]
fn nested_cant_cannot_widen_rights() {
    if !supported() || !have("sh") || !have("cat") {
        return;
    }
    let f = Fixture::new();
    let cant_bin = std::fs::canonicalize(CANT).expect("cant path");
    // An "agent shell" that may run cant and cat, but holds no grant on notes.txt. The nested
    // `cant run cat` uses the built-in cat manifest.
    let m = sh_manifest(
        &f,
        &format!(
            "[capabilities]\nexec = [\"{}\", \"cat\"]\n[env]\npass = [\"HOME\"]\n",
            cant_bin.display()
        ),
    );
    let inner = format!("{} run cat notes.txt", cant_bin.display());
    let o = f.cant(&["run", m.to_str().expect("utf8"), "-c", &inner]);
    assert_eq!(o.status.code(), Some(125), "{}{}", stdout(&o), stderr(&o));
    assert!(
        stderr(&o).contains("cat can't read ~/proj/notes.txt (not granted by the enclosing cant)"),
        "{}",
        stderr(&o)
    );

    // Granting notes.txt to the shell lets the nested cat read it.
    let o = f.cant(&[
        "run",
        "--grant",
        "notes.txt",
        m.to_str().expect("utf8"),
        "-c",
        &inner,
    ]);
    assert!(o.status.success(), "{}{}", stdout(&o), stderr(&o));
    assert_eq!(stdout(&o), "hello\n");
}

// ---- Built-in manifest library ---------------------------------------------------------------
//
// Each built-in cant does its job in a project directory, and can't reach what it wasn't given.

impl Fixture {
    /// Adds a few files to the project directory for the library tests.
    fn with_project(self) -> Self {
        std::fs::write(self.work.join("notes2.txt"), "hello\nworld\n").expect("write");
        std::fs::write(self.work.join("data.json"), "{\"a\": 1}\n").expect("write");
        std::fs::create_dir_all(self.work.join("src")).expect("mkdir");
        std::fs::write(self.work.join("src/main.rs"), "fn main() {}\n").expect("write");
        self
    }

    /// Runs `cant run ARGS` and requires success with `expected` in stdout.
    fn works(&self, args: &[&str], expected: &str) {
        let mut full = vec!["run"];
        full.extend_from_slice(args);
        let o = self.cant(&full);
        assert!(
            o.status.success(),
            "cant run {args:?} failed: {}{}",
            stdout(&o),
            stderr(&o)
        );
        assert!(
            stdout(&o).contains(expected),
            "cant run {args:?}: expected {expected:?} in {}",
            stdout(&o)
        );
    }

    /// Runs `cant run ARGS` from `dir` and requires `cant` itself to refuse (exit 125).
    fn refused_in(&self, dir: &Path, args: &[&str]) {
        let mut full = vec!["run"];
        full.extend_from_slice(args);
        let o = self
            .command(&full)
            .current_dir(dir)
            .output()
            .expect("run cant");
        assert_eq!(
            o.status.code(),
            Some(125),
            "cant run {args:?} in {}: {}{}",
            dir.display(),
            stdout(&o),
            stderr(&o)
        );
        assert!(!stdout(&o).contains("PRIVATE KEY"));
    }

    fn refused(&self, args: &[&str]) {
        self.refused_in(&self.work, args);
    }
}

fn library_ready(programs: &[&str]) -> bool {
    supported() && programs.iter().all(|p| have(p))
}

#[test]
fn library_text_tools() {
    if !library_ready(&["head", "tail", "wc", "diff", "sed"]) {
        return;
    }
    let f = Fixture::new().with_project();
    let key = f.home.join(".ssh/id_rsa");
    let key = key.to_str().expect("utf8");

    f.works(&["head", "-n", "1", "notes2.txt"], "hello\n");
    f.works(&["tail", "-n", "1", "notes2.txt"], "world\n");
    f.works(&["wc", "-l", "notes2.txt"], "2 notes2.txt");
    f.works(&["sed", "s/hello/bye/", "notes.txt"], "bye\n");
    f.works(&["sed", "-e", "s/world/earth/", "notes2.txt"], "earth\n");
    for tool in ["head", "tail", "wc", "sed"] {
        let args: Vec<&str> = if tool == "sed" {
            vec![tool, "p", key]
        } else {
            vec![tool, key]
        };
        f.refused(&args);
    }

    // diff exits 1 when the files differ.
    let o = f.cant(&["run", "diff", "notes.txt", "notes2.txt"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(stdout(&o).contains("> world"), "{}", stdout(&o));
    f.refused(&["diff", "notes.txt", key]);

    // sed -i can't write: it needs to create a file next to the original.
    let o = f.cant(&["run", "sed", "-i", "s/hello/bye/", "notes.txt"]);
    assert!(!o.status.success());
    assert_eq!(
        std::fs::read_to_string(f.work.join("notes.txt")).expect("read"),
        "hello\n"
    );
}

#[test]
fn library_jq_filter_is_not_a_file() {
    if !library_ready(&["jq"]) {
        return;
    }
    let f = Fixture::new().with_project();
    f.works(&["jq", ".a", "data.json"], "1");
    f.works(&["jq", "-c", ".", "data.json"], "{\"a\":1}");
    // `.` is the filter, not the current directory: only data.json is granted.
    let o = f.cant(&["run", "--explain", "jq", ".", "data.json"]);
    let out = stdout(&o);
    assert!(out.contains("~/proj/data.json"), "{out}");
    assert!(
        !out.lines()
            .any(|l| l.split_whitespace().nth(1) == Some("~/proj")),
        "{out}"
    );
    // That also means jq works from the home directory, on a file it's given.
    let o = f
        .command(&["run", "jq", ".a", "proj/data.json"])
        .current_dir(&f.home)
        .output()
        .expect("run");
    assert!(o.status.success(), "{}", stderr(&o));
    f.refused(&[
        "jq",
        ".",
        f.home.join(".ssh/id_rsa").to_str().expect("utf8"),
    ]);
}

#[test]
fn library_search_tools() {
    if !library_ready(&["grep", "rg", "find"]) {
        return;
    }
    let f = Fixture::new().with_project();
    f.works(&["grep", "-rn", "world"], "notes2.txt:2:world");
    f.works(&["grep", "-e", "hello", "notes.txt"], "hello");
    f.works(&["rg", "-n", "fn main"], "src/main.rs:1:fn main() {}");
    f.works(&["rg", "world", "notes2.txt"], "world");
    f.works(&["find", ".", "-name", "*.rs"], "./src/main.rs");

    // Secrets stay out of reach, by name or through `..`.
    f.refused(&["grep", "-r", "PRIVATE", "../.ssh"]);
    f.refused(&["rg", "PRIVATE", "../.ssh"]);
    f.refused(&["find", "../.ssh"]);
    // From the home directory, the current-directory grant would contain ~/.ssh.
    f.refused_in(&f.home, &["grep", "-r", "PRIVATE"]);
    f.refused_in(&f.home, &["rg", "PRIVATE"]);

    // find can't delete or run anything.
    let o = f.cant(&["run", "find", ".", "-name", "notes.txt", "-delete"]);
    assert!(!o.status.success());
    assert!(
        f.work.join("notes.txt").exists(),
        "find -delete deleted a file"
    );
    let o = f.cant(&[
        "run",
        "find",
        ".",
        "-name",
        "notes.txt",
        "-exec",
        "rm",
        "{}",
        ";",
    ]);
    // The kernel refuses to run rm; GNU find treats that as a false test, not an error.
    assert!(stderr(&o).contains("Permission denied"), "{}", stderr(&o));
    assert!(f.work.join("notes.txt").exists(), "find -exec ran rm");
}

#[test]
fn library_listing_tools() {
    if !library_ready(&["ls", "tree"]) {
        return;
    }
    let f = Fixture::new().with_project();
    f.works(&["ls"], "notes.txt");
    f.works(&["ls", "-l", "src"], "main.rs");
    f.works(&["tree"], "main.rs");
    f.refused(&["ls", "../.ssh"]);
    f.refused_in(&f.home, &["ls"]);
    f.refused_in(&f.home, &["tree"]);
}

#[test]
fn library_curl_net_reaches_the_network_but_not_secrets() {
    if !library_ready(&["curl"]) {
        return;
    }
    let f = Fixture::new().with_project();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/", listener.local_addr().expect("addr"));
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut conn, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 1024];
        let _ = conn.read(&mut buf);
        let _ = conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n");
    });
    f.works(&["curl-net", "-sS", "--max-time", "5", &url], "ok");
    server.join().expect("server");

    let ssh = f.home.join(".ssh/stolen");
    f.refused(&["curl-net", "-o", ssh.to_str().expect("utf8"), &url]);
    let key = format!("@{}", f.home.join(".ssh/id_rsa").display());
    // `-d @file` isn't a grant, so curl can't read the key to upload it.
    let o = f.cant(&[
        "run",
        "curl-net",
        "-sS",
        "--max-time",
        "2",
        "-d",
        &key,
        &url,
    ]);
    assert!(!o.status.success(), "{}", stdout(&o));
}

// ---- agent-sh and capabilities.cants ---------------------------------------------------------

/// Runs `cant run agent-sh -c SCRIPT` in the project, with `cant` on PATH and stdin closed.
fn agent(f: &Fixture, dir: &Path, script: &str) -> Output {
    let bin = std::fs::canonicalize(CANT).expect("cant path");
    let path = format!("{}:/usr/bin:/bin", bin.parent().expect("bin dir").display());
    f.command(&["run", "agent-sh", "-c", script])
        .current_dir(dir)
        .env("PATH", path)
        .stdin(Stdio::null())
        .output()
        .expect("run agent-sh")
}

#[test]
fn agent_sh_runs_tools_only_as_cants() {
    if !library_ready(&["bash", "git", "grep", "cat"]) {
        return;
    }
    let f = Fixture::new().with_project();
    let git = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&f.work)
        .status()
        .expect("git init");
    assert!(git.success());

    let ok = |script: &str, expected: &str| {
        let o = agent(&f, &f.work, script);
        assert!(o.status.success(), "{script}: {}{}", stdout(&o), stderr(&o));
        assert!(
            stdout(&o).contains(expected),
            "{script}: expected {expected:?} in {}",
            stdout(&o)
        );
    };
    ok("cant run cat notes.txt", "hello");
    ok("cant run grep -rn world", "notes2.txt:2:world");
    ok("cant run git status --short", "?? notes.txt");
    ok("echo made > new.txt && cant run cat new.txt", "made");
    ok("cat notes.txt", "hello"); // directly, within agent-sh's own rights

    // Secrets: refused by the nested cant, and denied by the kernel when tried directly.
    let o = agent(&f, &f.work, "cant run cat ~/.ssh/id_rsa");
    assert_eq!(o.status.code(), Some(125), "{}", stderr(&o));
    let o = agent(&f, &f.work, "cat ~/.ssh/id_rsa");
    assert!(!o.status.success());
    assert!(!stdout(&o).contains("PRIVATE KEY"));

    // A cant agent-sh doesn't list isn't available, and says why.
    let o = agent(&f, &f.work, "cant run curl-net http://127.0.0.1:9/");
    assert_eq!(o.status.code(), Some(125), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("curl-net isn't available here"),
        "{}",
        stderr(&o)
    );

    // No network for anything inside, and no start from a directory holding secrets.
    let o = agent(&f, &f.home, "true");
    assert_eq!(o.status.code(), Some(125), "{}", stderr(&o));
}

// ---- cargo -----------------------------------------------------------------------------------

/// The built-in cargo manifest, with `~/.cargo` and `~/.rustup` pointing at this machine's
/// real toolchain (the fixture's HOME is fake). None if there's no rustup-managed cargo.
/// Returns (manifest, toolchain bin directory, rustup home).
fn cargo_manifest(f: &Fixture) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let path = std::env::var_os("PATH")?;
    let proxy = std::env::split_paths(&path)
        .map(|d| d.join("cargo"))
        .find(|p| p.is_file())?;
    let cargo_home = proxy.parent()?.parent()?.to_path_buf();
    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".rustup")))?;
    if !rustup_home.join("toolchains").is_dir() {
        eprintln!("SKIP: no rustup toolchains at {}", rustup_home.display());
        return None;
    }
    let shown = Command::new(CANT)
        .args(["show", "cargo"])
        .output()
        .expect("cant show cargo");
    let text = String::from_utf8(shown.stdout)
        .expect("utf8")
        .replace("~/.cargo", &cargo_home.display().to_string())
        .replace("~/.rustup", &rustup_home.display().to_string());
    let m = f.home.join("cargo.toml");
    std::fs::write(&m, text).expect("write");
    Some((m, cargo_home.join("bin"), rustup_home))
}

#[test]
fn cargo_builds_but_build_scripts_cannot_reach_secrets() {
    if !library_ready(&["cc"]) {
        return;
    }
    let f = Fixture::new();
    let Some((m, cargo_bin, rustup_home)) = cargo_manifest(&f) else {
        eprintln!("SKIP: no rustup-managed cargo on PATH");
        return;
    };
    let m = m.to_str().expect("utf8");
    std::fs::create_dir_all(f.work.join("src")).expect("mkdir");
    std::fs::write(
        f.work.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write");
    std::fs::write(
        f.work.join("build.rs"),
        "fn main() { println!(\"cargo:rustc-env=GREETING=built\"); }\n",
    )
    .expect("write");
    std::fs::write(
        f.work.join("src/main.rs"),
        "fn main() { println!(\"{}\", env!(\"GREETING\")); }\n",
    )
    .expect("write");
    let run = |args: &[&str]| {
        let mut full = vec!["run", m];
        full.extend_from_slice(args);
        f.command(&full)
            .env("RUSTUP_HOME", &rustup_home)
            .env("PATH", format!("{}:/usr/bin:/bin", cargo_bin.display()))
            .stdin(Stdio::null())
            .output()
            .expect("run cargo")
    };

    let o = run(&["run", "-q"]);
    if !o.status.success() {
        // Enough to debug a failure on a CI runner: the grants, and what the build script is.
        let explained = f
            .command(&["run", "--explain", m, "build"])
            .output()
            .expect("explain");
        let scripts = Command::new("sh")
            .arg("-c")
            .arg(
                "find target -name 'build_script_build*' -type f -exec file {} + ; uname -m; \
                 grep -E ' /tmp | / ' /proc/self/mountinfo; \
                 s=$(find target -name build_script_build -type f | head -n1); \
                 echo \"outside a cant:\"; \"$s\" >/dev/null; echo \"exit $?\"",
            )
            .current_dir(&f.work)
            .output()
            .expect("find");
        let runner = f.manifest(
            "runner",
            "[entrypoint]\npath = \"sh\"\n[args.options]\n\"-c\" = \"value\"\n\
             [capabilities]\nexec = [\"$CWD\"]\nfs.ro = [\"/usr/lib\"]\n",
        );
        let inside = f
            .command(&[
                "run",
                runner.to_str().expect("utf8"),
                "-c",
                "s=$(find target -name build_script_build -type f | head -n1); \
                 \"$s\" >/dev/null; echo \"inside a cant: exit $?\"; \
                 cp \"$s\" ./copied 2>&1; ./copied >/dev/null; echo \"copied: exit $?\"",
            ])
            .output()
            .expect("runner");
        panic!(
            "cargo run failed:\n{}{}\n--- explain ---\n{}\n--- build scripts ---\n{}{}\n\
             --- in a minimal cant ---\n{}{}",
            stdout(&o),
            stderr(&o),
            stdout(&explained),
            stdout(&scripts),
            stderr(&scripts),
            stdout(&inside),
            stderr(&inside)
        );
    }
    assert_eq!(stdout(&o), "built\n");

    // A build script that tries to steal a key.
    let key = f.home.join(".ssh/id_rsa");
    std::fs::write(
        f.work.join("build.rs"),
        format!(
            "fn main() {{ let k = std::fs::read({:?}); assert!(k.is_ok(), \"{{k:?}}\"); }}\n",
            key
        ),
    )
    .expect("write");
    let o = run(&["build", "-q"]);
    assert!(!o.status.success(), "the build script read the key");
    assert!(stderr(&o).contains("PermissionDenied"), "{}", stderr(&o));
}
