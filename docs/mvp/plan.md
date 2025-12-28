# Toolcap MVP Implementation Plan

This document outlines the implementation phases for the Toolcap MVP. Each phase builds on the previous one, with a focus on getting core functionality working before adding complexity.

## Phase 1: Project Setup and Core Types

Set up the Rust project structure and define the fundamental types.

- [x] Initialize Cargo workspace with `toolcap` library crate
- [x] Add `sacp` crate as a dependency for ACP types
- [x] Define `Outcome` enum with `Allow`, `Deny`, `Unknown` variants
- [x] Define `Operation` enum mirroring ACP `ToolKind` variants
- [x] Define `ExecuteOperation` struct to hold parsed command data
- [x] Define `Rule` struct pairing a `Matcher` with an `Outcome`
- [x] Define `Ruleset` struct as an ordered `Vec<Rule>`
- [x] Implement `Ruleset::evaluate(&self, op: &Operation) -> Outcome`
- [x] Add basic unit tests for ruleset evaluation with trivial matchers

## Phase 2: Shell Command Parsing

Implement parsing of shell commands to enable fine-grained matching.

- [x] Evaluate shell parsing crates (e.g., `shell-words`, `shlex`, or custom)
  - Selected `conch-parser` for full POSIX shell parsing
- [x] Define `ParsedCommand` struct for a single command (name, args, flags)
- [x] Define `ShellAst` enum representing command structures (simple, pipeline, logical operators)
- [x] Implement parser for simple commands with arguments and flags
- [x] Implement parser for pipelines (`|`)
- [x] Implement parser for logical operators (`&&`, `||`, `;`)
- [x] Handle quoted strings and escape sequences
- [x] Add unit tests for various shell command patterns (33 tests)
- [x] Document limitations and unsupported shell features

## Phase 3: Execute Matchers

Build the matcher system for execute operations.

- [x] Define `Matcher` enum/trait for composable predicates
- [x] Implement `Matcher::command(name)` for matching command names
- [x] Implement `Matcher::with_subcommand(subcmd)` for matching subcommands
- [x] Implement `Matcher::with_subcommands([...])` for matching any of several subcommands
- [x] Implement `Matcher::with_flag(flag)` for matching specific flags
- [x] Implement `Matcher::and(vec![...])` for conjunction
- [x] Implement `Matcher::or(vec![...])` for disjunction
- [x] Implement `Matcher::any_execute()` for matching any execute operation
- [x] Add unit tests for individual matcher types
- [x] Add unit tests for composed matchers

## Phase 4: Compound Command Evaluation

Handle evaluation of pipelines and logical operators.

- [x] Implement recursive evaluation of `ShellAst` nodes against a ruleset
- [x] Define evaluation semantics: compound allowed only if all parts allowed
- [x] Define evaluation semantics: compound denied if any part denied
- [x] Define evaluation semantics: compound unknown if any part unknown and none denied
- [x] Integrate compound evaluation into `Ruleset::evaluate`
- [x] Add unit tests for pipeline evaluation
- [x] Add unit tests for logical operator evaluation
- [x] Add unit tests for mixed compound commands

## Phase 5: Directory Scoping

Add support for restricting rules to directory subtrees.

- [x] Extend `ExecuteOperation` to include working directory context
- [x] Implement `Matcher::within_directory(path)` matcher
- [x] Implement canonical path resolution for symlink handling
- [x] Implement directory containment check
- [x] Add unit tests for directory scoping
- [x] Add unit tests for symlink edge cases

## Phase 6: Matcher Groups

Provide convenient abstractions for common command patterns.

- [x] Create `matchers` module for predefined matcher groups (feature-gated)
- [x] Implement `ReadOnlyGit::matcher()` for safe git commands
- [x] Implement `Compilation::matcher()` for common build tools
- [x] Implement `SafeNpm::matcher()` for read-only npm commands
- [x] Document how to extend matcher groups with `Matcher::or`
- [x] Add unit tests for each matcher group

## Phase 7: ACP Integration

Connect Toolcap to the ACP protocol for use as a proxy.

- [x] Study `sacp` crate API for proxy implementation
- [x] Implement conversion from ACP `ToolCall` to Toolcap `Operation`
- [x] Implement conversion from `Outcome` to ACP `PermissionOptionKind`
- [x] Create `ToolcapProxy` struct implementing ACP proxy interface
- [x] Implement permission request interception in proxy
- [x] Implement forwarding of `Unknown` outcomes to upstream client
- [x] Add integration tests with mock ACP messages

## Phase 8: Integration Testing with Claude Code

Validate the full system with a real agent.

- [x] Set up test environment with `sacp-conductor`
- [x] Configure Zed to use Toolcap as a proxy to Claude Code ACP
- [x] Create test ruleset with allow/deny rules
- [x] Verify allowed commands execute without prompts
- [x] Verify denied commands are blocked
- [ ] Verify unknown commands prompt the user
- [ ] Document integration setup steps
