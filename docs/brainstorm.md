# Toolcap

Toolcap is an open source Rust library for expressively specifying tool use permissions in agentic applications.

# Design Concepts

## Core

- Builds on [Agent Client Protocol](https://agentclientprotocol.com)
  * This will allow us to wrap agents like Claude Code or Codex with more expressive tool permissions, without having to modify the agents themselves
- Rulesets:
  * Top-level abstraction is a set of permission rules
  * Applying a ruleset to an attempted tool use produces a three-valued result: allow, deny, unknown
  * Rulesets are serializable so they can be persisted and loaded to/from a config file
    - I'm thinking TOML but we can explore syntax options
  * Rulesets are ordered in priority order, so you keep trying the next rule until you get an answer
- Rules:
  * A Rule contains a Matcher (ie a predicate) and an Outcome (allow or deny)
- Matchers:
  * A Matcher is a predicate describing whether a particular operation matches a rule
  * Matchers are combined with AND and OR
    - Should we restrict them to conjunctive normal form (CNF)?
    - Another possibility is that we don't restrict the user-visible language of rulesets, but we compile them to CNF for performance?
    - This is just a hunch, though—we'll need to explore whether it actually provides some performance benefit before we decide whether we need it
- Operations:
  * An attempted tool use is called an "operation"
  * Core operations are the [ToolKind](https://docs.rs/sacp/9.0.0/sacp/schema/enum.ToolKind.html) variants of ACP
  * First operation we'll focus on: Execute tool (see below)
- Scopes:
  * Various operations have domain-specific notions of permission "scopes," which express where a particular rule does or doesn't apply
  * Implemented via ACP [PermissionOptionKind](https://docs.rs/sacp/9.0.0/sacp/schema/enum.PermissionOptionKind.html), particularly AllowOnce/RejectOnce

### Execute permissions

- Permission scope: directory sandboxing
  * allow specifying that a group of permissions is scoped to a particular subtree
  * will need to figure out what to do in the presence of symlinks
- Permission scope: understanding commands and subcommands
  * allow specifying things like allow(git show*)
  * not actually a regexp/glob but based on having parsed commands
- Permission combination: understanding shell combinators
  * relies on fully parsing the Execute operation's command
  * effectively does a conservative static analysis on the parse tree
  * examples:
    - `find . -name '*.ts' | xargs grep 'interface'` is allowed if e.g. `find` and `xargs grep` are both allowed
    - `rm foo.txt || echo failed` is allowed if `rm` and `echo` are both allowed

## Abstractions

- Matchers are a key construct that should be amenable to abstraction
- Should make it possible to define conveniences like a Compilation matcher that includes common compiler commands (`tsc`, `go build`, `cargo build`, `javac`, etc)
- Maybe call these things something like a MatcherGroup
- Should somehow make it possible to extend abstractions -- maybe this is actually nothing more complicated than using OR on a MatcherGroup and another Matcher!
  * Might want to have a way of semi-destructively extending a MatcherGroup in a config file, e.g. a declaration that effectively means "whenever you see Compilation in this file, treat it as also including `zig build`" -- we can probably leave this for future work

# MVP

- core datatypes
- in-memory only, not worrying about serialization yet
- unit tests
- an integration test that uses Zed's Claude Code ACP wrapper (see https://hackmd.io/@nikomatsakis/rJ2HFBzW-g) with a ruleset

# Future Ideas

- if a ruleset doesn't allow an operation, find the most ergonomic rule (or a few alternative rules to choose from?) to propose to the user
  * Does ACP provide enough expressiveness to make use of this? Study the [Tool Calls](https://agentclientprotocol.com/protocol/tool-calls) chapter.
- rich config format that allows convenient matcher abstractions
- rich standard library of common matcher abstractions
