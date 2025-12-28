# Toolcap

A library for specifying tool use permissions in agentic applications.

## Overview

Toolcap provides a ruleset-based system for controlling what operations AI agents can perform. It integrates with the [Agent Client Protocol (ACP)](https://agentclientprotocol.com/) to intercept permission requests and automatically allow, deny, or defer to user judgment.

## Quick Start

```rust
use toolcap::{Ruleset, Rule, Matcher, Outcome};

let ruleset = Ruleset::new(vec![
    // Allow read-only git commands
    Rule::new(
        Matcher::command("git").with_subcommands(["status", "log", "diff"]),
        Outcome::Allow,
    ),
    // Deny destructive commands
    Rule::new(
        Matcher::command("git").with_subcommand("push"),
        Outcome::Deny,
    ),
]);

// Evaluate a command
let op = Operation::execute("git status");
assert_eq!(ruleset.evaluate(&op), Outcome::Allow);
```

## Using with Zed and Claude Code

Toolcap includes an example proxy (`toolcap_proxy`) that integrates with `sacp-conductor` to provide automatic permission handling for Claude Code in Zed.

### Prerequisites

1. Install sacp-conductor (version 9.0.0+):
   ```bash
   cargo install sacp-conductor --force
   ```

2. Build the example proxy:
   ```bash
   cargo build --release --example toolcap_proxy --features="acp matchers"
   ```

### Zed Configuration

Add to `~/.config/zed/settings.json`:

```json
{
  "agent_servers": {
    "Claude Code (with default permissions)": {
      "type": "custom",
      "command": "/path/to/home/.cargo/bin/sacp-conductor",
      "args": [
        "--debug",
        "agent",
        "/path/to/toolcap/target/release/examples/toolcap_proxy",
        "npx -y '@zed-industries/claude-code-acp'"
      ]
    }
  }
}
```

<details>
<summary>Default Ruleset</summary>

The proxy includes a default ruleset:

**Allows** (auto-permitted):
- Git read-only: `status`, `log`, `diff`, `show`, `blame`, `branch`, `tag`, `remote`, `describe`, `rev-parse`, `ls-files`, `ls-tree`, `cat-file`, `shortlog`, `annotate`
- Cargo: `build`, `check`, `test`, `clippy`, `fmt`, `doc`, `tree`, `metadata`
- npm read-only: `list`, `view`, `search`, `audit`, `outdated`, `ls`
- Common tools: `ls`, `cat`, `head`, `tail`, `grep`, `rg`, `find`, `wc`, `pwd`, `which`, `echo`, `printf`
- Go: `build`, `test`, `vet`, `fmt`, `mod`
- Build tools: `make`, `tsc`, `node`, `npx`

**Denies** (auto-blocked):
- Destructive git: `push`, `reset`, `rebase`, `force-push`
- System commands: `sudo`, `su`, `chmod`, `chown`, `rm -rf`, `rm -r`, `mkfs`, `dd`
- Network exfiltration: `curl`, `wget`, `nc`, `netcat`

</details>

<details>
<summary>How It Works</summary>

The conductor chain is:

```
Zed (Client) <-> sacp-conductor <-> toolcap_proxy <-> claude-code-acp (Agent)
```

1. **toolcap_proxy** intercepts `request_permission` requests from the agent
2. Evaluates them against the built-in ruleset
3. For **Allow** outcomes: auto-responds with permission granted
4. For **Deny** outcomes: auto-responds with permission rejected
5. For **Unknown** outcomes: forwards to Zed for user decision

</details>

<details>
<summary>Debug Logging</summary>

Add `--debug` to the conductor args to create timestamped log files:

```json
"args": ["--debug", "agent", ...]
```

Log format:
- `C ->` = conductor to client
- `0 ->` = conductor to component 0 (proxy)
- `0 <-` = component 0 to conductor
- `1 ->` = conductor to component 1 (agent)
- `1 <-` = component 1 to conductor
- `0 !` / `1 !` = component stderr output

</details>

## Features

- **Shell parsing**: Full POSIX shell command parsing
- **Compound commands**: Evaluate pipelines (`|`), logical operators (`&&`, `||`)
- **Composable matchers**: `command()`, `with_subcommand()`, `with_flag()`, `and()`, `or()`
- **Directory scoping**: Restrict rules to specific directory trees with `within_directory()`
- **ACP integration**: Direct integration with Agent Client Protocol

## License

MIT
