# Toolcap MVP RFC

## Summary

Toolcap is a Rust library for expressing and evaluating tool-use permissions in agentic applications, built on the Agent Client Protocol (ACP) to enable wrapping existing agents with fine-grained access control without modifying the agents themselves.

## Motivation

AI coding agents like Claude Code and Codex are powerful tools, but their power comes with risk: they can execute arbitrary shell commands, read and write files, and interact with external systems. Today, users face a binary choice—either trust the agent completely or constantly interrupt their workflow with permission prompts.

Toolcap addresses this gap by providing an expressive permission system that sits between the editor and the agent. By building on ACP, Toolcap can intercept tool calls from any ACP-compatible agent and apply user-defined rules to determine whether operations should be allowed, denied, or escalated for user approval.

Key motivations:

- **Safety without friction**: Users should be able to define once what operations they trust, reducing interruptions while maintaining security boundaries.
- **Expressiveness**: Simple allow/deny lists aren't enough. Users need to express nuanced policies like "allow git commands, but not `git push --force`" or "allow file edits only within the `src/` directory."
- **Composability**: Permission rules should be composable and reusable. A "safe compilation" policy should work across projects regardless of whether they use TypeScript, Go, or Rust.
- **Agent-agnostic**: By building on ACP, Toolcap works with any compliant agent without requiring agent modifications.

## Guide-level Design

### Core Concepts

Toolcap evaluates **operations** against **rulesets** to produce permission decisions.

#### Operations

An operation represents an attempted tool use by an agent. Operations are typed according to ACP's `ToolKind` variants:

- `Read` — Reading files or data
- `Edit` — Modifying files or content
- `Delete` — Removing files or data
- `Move` — Moving or renaming files
- `Search` — Searching for information
- `Execute` — Running commands or code
- `Fetch` — Retrieving external data
- `Think` — Internal reasoning (typically always allowed)
- `SwitchMode` — Switching session mode
- `Other` — Uncategorized operations

The MVP focuses primarily on `Execute` operations, which are the most security-sensitive.

#### Rulesets

A ruleset is an ordered list of rules. When evaluating an operation, Toolcap checks each rule in order until one matches:

```rust
use toolcap::{Ruleset, Rule, Matcher, Outcome};

let ruleset = Ruleset::new(vec![
    // Allow read-only git commands
    Rule::new(
        Matcher::command("git").with_subcommands(["status", "log", "diff", "show"]),
        Outcome::Allow,
    ),
    // Deny destructive git commands
    Rule::new(
        Matcher::command("git").with_subcommands(["push", "reset", "rebase"]),
        Outcome::Deny,
    ),
    // Allow cargo in read-only mode
    Rule::new(
        Matcher::command("cargo").with_subcommands(["check", "build", "test", "clippy"]),
        Outcome::Allow,
    ),
]);
```

#### Rules and Matchers

A **rule** pairs a **matcher** (predicate) with an **outcome** (allow or deny).

**Matchers** describe which operations a rule applies to. They can be combined with `and` and `or`:

```rust
// Match any compilation command
let compile_matcher = Matcher::or(vec![
    Matcher::command("cargo").with_subcommand("build"),
    Matcher::command("go").with_subcommand("build"),
    Matcher::command("tsc"),
    Matcher::command("javac"),
]);

// Match npm commands only in the project directory
let scoped_npm = Matcher::and(vec![
    Matcher::command("npm"),
    Matcher::within_directory("/home/user/my-project"),
]);
```

#### Outcomes

Evaluating an operation against a ruleset produces one of three outcomes:

- `Allow` — The operation is permitted
- `Deny` — The operation is forbidden
- `Unknown` — No rule matched; the client should escalate to the user

```rust
use toolcap::{Ruleset, Operation, Outcome};

let operation = Operation::execute("git status");
match ruleset.evaluate(&operation) {
    Outcome::Allow => { /* proceed without prompting */ }
    Outcome::Deny => { /* block the operation */ }
    Outcome::Unknown => { /* ask the user */ }
}
```

### Execute Operations: Deep Dive

Execute operations are the most complex because shell commands can be combined in sophisticated ways. Toolcap parses commands to understand their structure.

#### Command Matching

Match commands by name and subcommands:

```rust
// Matches: git status, git status -s, git status --porcelain
Matcher::command("git").with_subcommand("status")

// Matches: git log, git log --oneline, git log -n 10
Matcher::command("git").with_subcommand("log")

// Matches: cargo build, cargo build --release
Matcher::command("cargo").with_subcommand("build")
```

#### Directory Scoping

Restrict rules to specific directory subtrees:

```rust
// Only allow file operations within the project
Rule::new(
    Matcher::any_execute().within_directory("./src"),
    Outcome::Allow,
)
```

#### Shell Combinators

Toolcap understands shell pipelines and logical operators. A compound command is allowed only if all its parts are allowed:

```rust
let ruleset = Ruleset::new(vec![
    Rule::new(Matcher::command("find"), Outcome::Allow),
    Rule::new(Matcher::command("grep"), Outcome::Allow),
    Rule::new(Matcher::command("xargs").with_subcommand("grep"), Outcome::Allow),
]);

// This compound command is allowed because all parts match:
// find . -name '*.ts' | xargs grep 'interface'
let op = Operation::execute("find . -name '*.ts' | xargs grep 'interface'");
assert_eq!(ruleset.evaluate(&op), Outcome::Allow);
```

### Matcher Groups (Abstractions)

For convenience, Toolcap provides predefined matcher groups for common patterns:

```rust
use toolcap::matchers::{Compilation, ReadOnlyGit, SafeNpm};

let ruleset = Ruleset::new(vec![
    // Allow common compilation commands
    Rule::new(Compilation::matcher(), Outcome::Allow),
    // Allow read-only git operations
    Rule::new(ReadOnlyGit::matcher(), Outcome::Allow),
    // Allow safe npm commands
    Rule::new(SafeNpm::matcher(), Outcome::Allow),
]);
```

Matcher groups can be extended:

```rust
// Add zig to the compilation group
let extended_compilation = Matcher::or(vec![
    Compilation::matcher(),
    Matcher::command("zig").with_subcommand("build"),
]);
```

### Integration with ACP

Toolcap is designed to work as an ACP proxy. When an agent requests permission to execute a tool:

1. The ACP conductor routes the `session/request_permission` call to Toolcap
2. Toolcap constructs an `Operation` from the tool call details
3. Toolcap evaluates the operation against the configured ruleset
4. Based on the outcome:
   - `Allow` → Respond with `AllowOnce` (or `AllowAlways` for remembered decisions)
   - `Deny` → Respond with `RejectOnce` (or `RejectAlways`)
   - `Unknown` → Forward the permission request to the user

```
┌────────┐     ┌─────────┐     ┌─────────────┐     ┌───────┐
│  Zed   │ ←→  │ Toolcap │ ←→  │ Claude Code │ ←→  │  LLM  │
│(client)│     │ (proxy) │     │   (agent)   │     │       │
└────────┘     └─────────┘     └─────────────┘     └───────┘
                    ↓
              ┌──────────┐
              │ Ruleset  │
              │ Config   │
              └──────────┘
```

### Example: Complete Ruleset

Here's a complete example showing a typical development workflow policy:

```rust
use toolcap::{Ruleset, Rule, Matcher, Outcome};
use toolcap::matchers::{Compilation, ReadOnlyGit};

fn development_ruleset() -> Ruleset {
    Ruleset::new(vec![
        // Always allow read-only git operations
        Rule::new(ReadOnlyGit::matcher(), Outcome::Allow),

        // Allow compilation within the project
        Rule::new(
            Compilation::matcher().within_directory("."),
            Outcome::Allow,
        ),

        // Allow running tests
        Rule::new(
            Matcher::or(vec![
                Matcher::command("cargo").with_subcommand("test"),
                Matcher::command("npm").with_subcommand("test"),
                Matcher::command("go").with_subcommand("test"),
                Matcher::command("pytest"),
            ]),
            Outcome::Allow,
        ),

        // Allow package listing (not installation)
        Rule::new(
            Matcher::or(vec![
                Matcher::command("npm").with_subcommand("list"),
                Matcher::command("cargo").with_subcommand("tree"),
            ]),
            Outcome::Allow,
        ),

        // Deny dangerous commands
        Rule::new(
            Matcher::or(vec![
                Matcher::command("rm").with_flag("-rf"),
                Matcher::command("sudo"),
                Matcher::command("chmod"),
                Matcher::command("curl").piped_to_shell(),
            ]),
            Outcome::Deny,
        ),
    ])
}
```

## FAQ

### Why build on ACP instead of creating a standalone solution?

ACP provides a standardized protocol for agent-editor communication that's already being adopted by major players (Zed, Claude Code). By building on ACP, Toolcap can work with any compliant agent without modifications—you just insert it as a proxy in the communication chain. This dramatically increases adoption potential and avoids fragmenting the ecosystem.

### How does Toolcap differ from the permission systems built into agents like Claude Code?

Built-in permission systems are typically simple allow/deny lists without much expressiveness. Toolcap provides:
- Fine-grained command parsing (understanding subcommands, flags, arguments)
- Directory scoping
- Shell combinator analysis
- Composable matcher abstractions
- A single policy that works across multiple agents

### What happens when no rule matches?

The ruleset returns `Unknown`, which signals that the operation should be escalated to the user. This is the safe default—Toolcap never auto-allows an operation it doesn't have an explicit rule for.

### How does Toolcap handle shell command parsing?

Toolcap includes a shell parser that understands:
- Simple commands (`git status`)
- Commands with subcommands, flags, and arguments (`git log --oneline -n 10`)
- Pipelines (`find . | grep foo`)
- Logical operators (`make && make test`)
- Command substitution (treated conservatively)

For compound commands, each component is evaluated separately, and the compound is only allowed if all components are allowed.

### Can I use Toolcap without ACP?

Yes. While Toolcap is designed for ACP integration, the core `Ruleset` and `Operation` types are standalone. You can use Toolcap as a library to evaluate permissions in any context:

```rust
let ruleset = load_my_ruleset();
let operation = Operation::execute(user_command);
if ruleset.evaluate(&operation) == Outcome::Allow {
    execute(user_command);
}
```

### How do I handle commands that should sometimes be allowed and sometimes not?

Use more specific matchers to distinguish the cases:

```rust
// Allow npm install for dev dependencies
Rule::new(
    Matcher::command("npm")
        .with_subcommand("install")
        .with_flag("--save-dev"),
    Outcome::Allow,
),

// Deny npm install for production dependencies (require user approval)
// (No rule means Unknown, which escalates to user)
```

### What about symlinks and directory scoping?

Directory scoping uses canonical paths to prevent symlink bypasses. When you scope a rule to `/project/src`, Toolcap resolves symlinks before checking containment, so a symlink pointing outside the allowed directory won't circumvent the restriction.

### Will Toolcap support other operation types besides Execute?

Yes, eventually. The MVP focuses on Execute because it's the highest-risk operation type. Future versions will add specialized matchers for:
- `Read`/`Edit`/`Delete` — File path patterns, glob matching
- `Fetch` — URL patterns, domain allowlists
- And others as needed

### How do I extend a matcher group with custom commands?

Use `Matcher::or` to combine the built-in group with your additions:

```rust
let my_compilation = Matcher::or(vec![
    Compilation::matcher(),
    Matcher::command("bazel").with_subcommand("build"),
    Matcher::command("buck2").with_subcommand("build"),
]);
```

### Is the ruleset evaluation order significant?

Yes. Rules are evaluated in order, and the first matching rule determines the outcome. This lets you create specific exceptions before general rules:

```rust
// Deny force push specifically
Rule::new(
    Matcher::command("git")
        .with_subcommand("push")
        .with_flag("--force"),
    Outcome::Deny,
),
// Allow other git push commands
Rule::new(
    Matcher::command("git").with_subcommand("push"),
    Outcome::Allow,
),
```
