# Running an AI agent's tools in cants

An agent that runs shell commands runs them with all your rights: it can read `~/.ssh`, push to
your remotes, and send anything to the network. Prompt injection, a confused model, or a
malicious dependency's build script is all it takes. Cantainer's answers:

- **`agent-sh`**, a shell for the agent that is itself a cant (this page);
- **watched cants**, which report when an agent changes files that run code later, with a
  one-command undo ([below](#noticing-planted-files-sessions));
- **cans**, tools that carry their permissions, so an agent can be allowed to install tools
  within limits you set (experimental, [below](#tools-for-agents-as-cans)).

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
- **The agent can modify the project, including `.git`, `.envrc` and `.vscode`.** That lets it
  commit, which agents need, but it also lets it plant code that runs later with your full
  rights, outside any cant: `core.fsmonitor`, `core.pager` or an alias in `.git/config`, a hook
  in `.git/hooks`, an `.envrc`, a VS Code task. Landlock can't make those read-only inside a
  writable directory, so `cant` **detects** it instead and tells you, with a one-command
  undo. See [Noticing planted files](#noticing-planted-files-sessions). It can't push: there's
  no network.

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

## Noticing planted files: sessions

agent-sh (like any cant that may write the project directory, such as `git` and `cargo`) runs
**watched**: `cant` records the files that run code outside the sandbox before the run, waits
until the program and everything it started have finished, and compares. If something changed,
it says so and opens a **session**:

```console
$ cant run agent-sh -c '…'
…
cant: agent-sh changed files that can run code outside the sandbox:
  changed: .git/config
    RUNS CODE: core.fsmonitor = /tmp/evil.sh
  new: .git/hooks/post-checkout
    RUNS CODE: git runs this hook (post-checkout)
review: cant diff 7f3a2c    undo: cant revert 7f3a2c    accept: cant keep 7f3a2c
```

Nothing is undone automatically: you (or the agent, if you let it run `cant` outside agent-sh)
decide.

| Command | What it does |
|---|---|
| `cant diff ID` | The changed files, with `+`/`-` lines and what each change can run |
| `cant revert ID` | Puts the files back as they were before the session. Refuses if they changed again since (`--force` overwrites); never follows symlinks |
| `cant keep ID` | Accepts the changes |
| `cant log [DIR]` | Sessions, newest first |
| `cant verify [DIR]` | Lists unresolved sessions; exits 1 if there are any (for a shell prompt or CI) |

Until you decide, every `cant run` in that directory starts with a one-line reminder. IDs are
the first six digits of a random ID; four are enough when unique.

What is watched, in the project directory and in subdirectories up to three levels deep
(skipping `node_modules`, `target` and virtualenvs): `.git/config`, `.git/hooks/`, `.git` when it
is a file pointing elsewhere, `.envrc`, `.pre-commit-config.yaml`, `.cargo/config(.toml)`,
`.githooks/`, `.husky/`, `.vscode/` and `.idea/runConfigurations/`.

- **Inside a cant, a session can't be read or accepted.** The copies live in
  `~/.local/state/cantainer/sessions/`, a protected path (they may hold tokens from
  `.git/config`). An agent can't `cant keep` its own change; `cant revert` and `cant keep` run
  outside the sandbox.
- **Processes left running** are given two seconds after the program exits, then stopped, so
  nothing can change files after the check (`cant: stopped what agent-sh left running: npm`).
  A watched cant can't leave a server running in the background.
- **It is detection with a window, not prevention.** A shell prompt or IDE that runs
  `git status` while the agent works can run a planted `core.fsmonitor` before the session ends.
- Harmless changes aren't reported: new remotes or branches in `.git/config`, new repositories
  (`git init`), git's sample hooks. Settings `cant` doesn't recognise are reported.
- Other files that run later (`Makefile`, `package.json` scripts, `build.rs`, tests) aren't
  watched; they change all the time. Review the diff before running them outside a cant.
- If `cant` itself is killed during the run (on kernels before 6.12 the cant can signal it),
  the next `cant run` or `cant verify` in that directory finishes the check.

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

## Tools for agents, as cans

Agents install tools for themselves. MCP servers are the clearest case: today they come from
`npx` or `uvx`, unsigned, and run with all your rights. A **can**
([USING-CANS.md](USING-CANS.md)) is a tool packed with its libraries and its manifest, so what
it may do is written on it and enforced by the kernel wherever it runs.

**Today (experimental):** you can pack a tool, push it to a registry, pull it on another machine
and run it there under its manifest. Cans are not signed yet, so a can from a registry runs only
after *you* `cant pull` it. An agent can't install one by itself. Running a can inside agent-sh
isn't supported yet.

**Planned** ([CANS.md](CANS.md) §5 and §7):

- **Signed cans and an approval prompt.** The first run shows the label in plain language ("git
  2.47, signed by github.com/acme, wants: read and write the current directory; no network").
  An update that asks for more shows only the difference. The prompt reads the terminal, never
  stdin, so a tool's input stream can't answer it.
- **`--approve-if-within POLICY.toml`**, the feature for agents. A can is approved automatically
  only if everything it asks for fits a policy you wrote (paths, network, environment variables,
  trusted signers). Nothing outside the policy runs without you. Protected paths stay
  unreachable, whatever a can or a policy says.
- **MCP servers as cans**, starting with static Go servers, with configuration snippets for
  Claude Code and other clients:

  ```json
  { "mcpServers": { "github": {
      "command": "cant",
      "args": ["run", "ghcr.io/cantainer/github-mcp-server:VERSION", "stdio"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PAT}" }
  } } }
  ```

  (Illustrative: this can doesn't exist yet.) A can's network access is all-or-nothing for now:
  Landlock can limit ports but not hosts, so "only `api.github.com`" needs a network namespace
  with a proxy, which is on the backlog.

## Limits

agent-sh inherits Cantainer's limits ([SECURITY.md](../SECURITY.md)): the kernel is trusted,
file metadata (names, sizes) outside the grants can still be seen with `stat`, inherited file
descriptors stay usable, and seccomp is a deny list. Signals to your other processes are only
blocked on Linux ≥ 6.12 (Landlock ABI 6).
