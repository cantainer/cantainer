# Running an AI agent's tools in cants

An agent that runs shell commands runs them with all your rights: it can read `~/.ssh`, push to
your remotes, and send anything to the network. Prompt injection, a confused model, or a
malicious dependency's build script is all it takes. Cantainer's answer is a shell for the
agent that is itself a cant: **`agent-sh`**.

```sh
cd ~/src/myproject
cant run agent-sh -c 'cant run rg TODO && cant run cargo test && cant run git diff'
```

## What agent-sh allows

`cant show agent-sh` prints the manifest. In short:

| | |
|---|---|
| Files | read and write the current directory; nothing else of yours |
| Secrets | `~/.ssh`, `~/.aws`, `~/.gnupg`, credentials, shell startup files: never |
| Network | none (no sockets at all) |
| Programs | the tools listed in `cants`, either as `cant run TOOL` or directly |
| Tools | `cat`, `head`, `tail`, `wc`, `diff`, `sed`, `jq`, `grep`, `rg`, `find`, `ls`, `tree`, `git`, `cargo` |

Each `cant run TOOL` inside agent-sh is a nested cant: it gets the intersection of the tool's
manifest and agent-sh's rights, enforced by the kernel. So `cant run git` can't reach the
network, and `cant run cat ~/.ssh/id_rsa` is refused before anything runs:

```console
$ cant run agent-sh -c 'cant run cat ~/.ssh/id_rsa'
cant: cat can't read ~/.ssh/id_rsa (~/.ssh is protected); to allow it anyway: cant run --grant ~/.ssh/id_rsa:r cat ...
$ cant run agent-sh -c 'cat ~/.ssh/id_rsa'
cat: /home/you/.ssh/id_rsa: Permission denied
$ cant run agent-sh -c 'cant run curl-net https://example.com'
cant: curl-net isn't available here: the enclosing cant may not run /usr/bin/curl (list `curl-net` in its capabilities.cants)
```

The tests in `crates/cantainer/tests/sandbox.rs` (`agent_sh_runs_tools_only_as_cants`,
`cargo_builds_but_build_scripts_cannot_reach_secrets`) check these behaviours against the
kernel on every CI run.

Things to know:

- **It refuses to start in a directory that contains a protected path**, such as your home
  directory. Run it in a project directory.
- **`cant` must be on `PATH`** inside agent-sh (it passes `PATH` through).
- **Programs can also run directly**, without `cant run`: `cat notes.txt` works. They then have
  agent-sh's rights, which are the boundary. Because agent-sh may run `cargo`, it can execute
  files in the current directory (build scripts, tests), and it can read the Rust toolchain and
  `/usr/lib`.
- **The agent can modify the project**, including `.git`. Review its changes; commit or stash
  your own work first. It can't push: there's no network.

## Wiring it into an agent

agent-sh is a command, so it fits any agent whose command execution you control. Run each
command the agent asks for as:

```
cant run agent-sh -c '<the command>'
```

with the project as the working directory and stdin closed or connected to the agent. For
example, in a tool you implement for an agent (Python):

```python
import subprocess

def run_shell(command: str, project: str) -> str:
    result = subprocess.run(
        ["cant", "run", "agent-sh", "-c", command],
        cwd=project, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600,
    )
    return f"exit {result.returncode}\n{result.stdout}{result.stderr}"
```

`cant` exits with 125 when it refuses something; the message on stderr says what and why, which
is useful feedback for the model.

**Agents with their own shell tool** (Claude Code, and others) don't let you swap the shell
out from under them. Their permission rules can restrict which commands run without asking,
for example Claude Code's `"permissions": {"allow": ["Bash(cant run agent-sh *)"]}`. But
Claude Code's documentation is explicit that Bash permission rules are not a security
boundary, and that read-only commands such as `cat` run without approval in every mode. Treat
such rules as convenience, not containment. Use the agent's own sandbox if it has one, and
agent-sh for the commands you route through it.

Running a whole agent (its own process, network access to its API, its config directory) inside
a cant is not tested yet.

## Giving the agent more, or less

Copy the manifest and edit it; your copy takes precedence:

```sh
mkdir -p ~/.config/cantainer/cants
cant show agent-sh > ~/.config/cantainer/cants/agent-sh.toml
```

- **More tools:** add names to `cants` (any cant from `cant list`, including your own from
  `cant new`). A listed cant whose program isn't installed is skipped.
- **Network:** adding `curl-net` or `cargo-net` gives agent-sh the network too, and so
  everything inside it, including programs run directly. Prefer fetching dependencies yourself
  (`cant run cargo-net fetch`) and keeping the agent offline.
- **Less:** remove tools, or make a read-only variant with `fs.ro = ["$CWD"]` instead of
  `fs.rw`.

`cant run --explain agent-sh -c true` shows every grant and which cant it came from.

## Limits

agent-sh inherits Cantainer's limits ([SECURITY.md](../SECURITY.md)): the kernel is trusted,
file metadata (names, sizes) outside the grants can still be seen with `stat`, inherited file
descriptors stay usable, and seccomp is a deny list. Signals to your other processes are only
blocked on Linux ≥ 6.12 (Landlock ABI 6).
