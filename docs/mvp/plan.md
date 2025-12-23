# Toolcap MVP Implementation Plan

This document outlines the implementation phases for the Toolcap MVP. Each phase builds on the previous one, with a focus on getting core functionality working before adding complexity.

## Phase 1: Project Setup and Core Types

Set up the Rust project structure and define the fundamental types.

- [ ] Initialize Cargo workspace with `toolcap` library crate
- [ ] Add `sacp` crate as a dependency for ACP types
- [ ] Define `Outcome` enum with `Allow`, `Deny`, `Unknown` variants
- [ ] Define `Operation` enum mirroring ACP `ToolKind` variants
- [ ] Define `ExecuteOperation` struct to hold parsed command data
- [ ] Define `Rule` struct pairing a `Matcher` with an `Outcome`
- [ ] Define `Ruleset` struct as an ordered `Vec<Rule>`
- [ ] Implement `Ruleset::evaluate(&self, op: &Operation) -> Outcome`
- [ ] Add basic unit tests for ruleset evaluation with trivial matchers

## Phase 2: Shell Command Parsing

Implement parsing of shell commands to enable fine-grained matching.

- [ ] Evaluate shell parsing crates (e.g., `shell-words`, `shlex`, or custom)
- [ ] Define `ParsedCommand` struct for a single command (name, args, flags)
- [ ] Define `ShellAst` enum representing command structures (simple, pipeline, logical operators)
- [ ] Implement parser for simple commands with arguments and flags
- [ ] Implement parser for pipelines (`|`)
- [ ] Implement parser for logical operators (`&&`, `||`, `;`)
- [ ] Handle quoted strings and escape sequences
- [ ] Add unit tests for various shell command patterns
- [ ] Document limitations and unsupported shell features

## Phase 3: Execute Matchers

Build the matcher system for execute operations.

- [ ] Define `Matcher` enum/trait for composable predicates
- [ ] Implement `Matcher::command(name)` for matching command names
- [ ] Implement `Matcher::with_subcommand(subcmd)` for matching subcommands
- [ ] Implement `Matcher::with_subcommands([...])` for matching any of several subcommands
- [ ] Implement `Matcher::with_flag(flag)` for matching specific flags
- [ ] Implement `Matcher::and(vec![...])` for conjunction
- [ ] Implement `Matcher::or(vec![...])` for disjunction
- [ ] Implement `Matcher::any_execute()` for matching any execute operation
- [ ] Add unit tests for individual matcher types
- [ ] Add unit tests for composed matchers

## Phase 4: Compound Command Evaluation

Handle evaluation of pipelines and logical operators.

- [ ] Implement recursive evaluation of `ShellAst` nodes against a ruleset
- [ ] Define evaluation semantics: compound allowed only if all parts allowed
- [ ] Define evaluation semantics: compound denied if any part denied
- [ ] Define evaluation semantics: compound unknown if any part unknown and none denied
- [ ] Integrate compound evaluation into `Ruleset::evaluate`
- [ ] Add unit tests for pipeline evaluation
- [ ] Add unit tests for logical operator evaluation
- [ ] Add unit tests for mixed compound commands

## Phase 5: Directory Scoping

Add support for restricting rules to directory subtrees.

- [ ] Extend `ExecuteOperation` to include working directory context
- [ ] Implement `Matcher::within_directory(path)` matcher
- [ ] Implement canonical path resolution for symlink handling
- [ ] Implement directory containment check
- [ ] Add unit tests for directory scoping
- [ ] Add unit tests for symlink edge cases

## Phase 6: Matcher Groups

Provide convenient abstractions for common command patterns.

- [ ] Create `matchers` module for predefined matcher groups
- [ ] Implement `ReadOnlyGit::matcher()` for safe git commands
- [ ] Implement `Compilation::matcher()` for common build tools
- [ ] Implement `SafeNpm::matcher()` for read-only npm commands
- [ ] Document how to extend matcher groups with `Matcher::or`
- [ ] Add unit tests for each matcher group

## Phase 7: ACP Integration

Connect Toolcap to the ACP protocol for use as a proxy.

- [ ] Study `sacp` crate API for proxy implementation
- [ ] Implement conversion from ACP `ToolCall` to Toolcap `Operation`
- [ ] Implement conversion from `Outcome` to ACP `PermissionOptionKind`
- [ ] Create `ToolcapProxy` struct implementing ACP proxy interface
- [ ] Implement permission request interception in proxy
- [ ] Implement forwarding of `Unknown` outcomes to upstream client
- [ ] Add integration tests with mock ACP messages

## Phase 8: Integration Testing with Claude Code

Validate the full system with a real agent.

- [ ] Set up test environment with `sacp-conductor`
- [ ] Configure Zed to use Toolcap as a proxy to Claude Code ACP
- [ ] Create test ruleset with allow/deny rules
- [ ] Verify allowed commands execute without prompts
- [ ] Verify denied commands are blocked
- [ ] Verify unknown commands prompt the user
- [ ] Document integration setup steps
