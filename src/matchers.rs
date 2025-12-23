//! Predefined matcher groups for common command patterns.
//!
//! This module provides convenient abstractions for common security policies.
//! Each matcher group represents a category of commands that are typically
//! safe to allow together.
//!
//! # Example
//!
//! ```
//! use toolcap::{Ruleset, Rule, Matcher, Outcome};
//! use toolcap::matchers::{Compilation, ReadOnlyGit, SafeNpm};
//!
//! let ruleset = Ruleset::new(vec![
//!     // Allow common compilation commands
//!     Rule::new(Compilation::matcher(), Outcome::Allow),
//!     // Allow read-only git operations
//!     Rule::new(ReadOnlyGit::matcher(), Outcome::Allow),
//!     // Allow safe npm commands
//!     Rule::new(SafeNpm::matcher(), Outcome::Allow),
//! ]);
//! ```
//!
//! # Extending Matcher Groups
//!
//! Matcher groups can be extended using `Matcher::or`:
//!
//! ```
//! use toolcap::Matcher;
//! use toolcap::matchers::Compilation;
//!
//! // Add zig to the compilation group
//! let extended_compilation = Matcher::or(vec![
//!     Compilation::matcher(),
//!     Matcher::command("zig").with_subcommand("build"),
//! ]);
//! ```

use crate::Matcher;

/// Matcher group for read-only git commands.
///
/// Matches git commands that only read repository state and don't modify
/// the working tree, index, or remote repositories.
///
/// # Included Commands
///
/// - `git status` - Show working tree status
/// - `git log` - Show commit logs
/// - `git diff` - Show changes
/// - `git show` - Show various types of objects
/// - `git branch` - List branches (without -d/-D)
/// - `git tag` - List tags (without -d)
/// - `git remote` - List remotes (without add/remove/set-url)
/// - `git stash list` - List stashed changes
/// - `git blame` - Show what revision and author last modified each line
/// - `git shortlog` - Summarize git log output
/// - `git describe` - Give an object a human readable name
/// - `git rev-parse` - Pick out and massage parameters
/// - `git ls-files` - Show information about files in the index
/// - `git ls-tree` - List the contents of a tree object
/// - `git cat-file` - Provide content or type and size information
/// - `git config` - Get repository or global options (read-only by default)
///
/// # Example
///
/// ```
/// use toolcap::{Matcher, Operation};
/// use toolcap::matchers::ReadOnlyGit;
///
/// let matcher = ReadOnlyGit::matcher();
///
/// assert!(matcher.matches(&Operation::execute("git status")));
/// assert!(matcher.matches(&Operation::execute("git log --oneline -n 10")));
/// assert!(!matcher.matches(&Operation::execute("git push origin main")));
/// ```
pub struct ReadOnlyGit;

impl ReadOnlyGit {
    /// Creates a matcher for read-only git commands.
    pub fn matcher() -> Matcher {
        Matcher::or(vec![
            // Status and diff commands
            Matcher::command("git").with_subcommand("status"),
            Matcher::command("git").with_subcommand("diff"),
            Matcher::command("git").with_subcommand("show"),
            // Log and history commands
            Matcher::command("git").with_subcommand("log"),
            Matcher::command("git").with_subcommand("shortlog"),
            Matcher::command("git").with_subcommand("blame"),
            Matcher::command("git").with_subcommand("annotate"),
            // Branch/tag listing (read-only usage)
            Matcher::command("git").with_subcommand("branch"),
            Matcher::command("git").with_subcommand("tag"),
            Matcher::command("git").with_subcommand("remote"),
            // Stash listing
            Matcher::command("git").with_subcommands(["stash"]),
            // Object inspection
            Matcher::command("git").with_subcommand("describe"),
            Matcher::command("git").with_subcommand("rev-parse"),
            Matcher::command("git").with_subcommand("ls-files"),
            Matcher::command("git").with_subcommand("ls-tree"),
            Matcher::command("git").with_subcommand("cat-file"),
            // Config reading
            Matcher::command("git").with_subcommand("config"),
            // Reference listing
            Matcher::command("git").with_subcommand("for-each-ref"),
            Matcher::command("git").with_subcommand("show-ref"),
            // Worktree listing
            Matcher::command("git").with_subcommand("worktree"),
        ])
    }
}

/// Matcher group for common compilation and build commands.
///
/// Matches build tool invocations that compile code but don't typically
/// have dangerous side effects beyond creating build artifacts.
///
/// # Included Commands
///
/// ## Rust
/// - `cargo build` - Compile the current package
/// - `cargo check` - Analyze the current package without building
/// - `cargo test` - Run tests
/// - `cargo clippy` - Run clippy lints
/// - `cargo doc` - Build documentation
/// - `cargo fmt` - Format code (with `--check`)
/// - `cargo bench` - Run benchmarks
///
/// ## Go
/// - `go build` - Compile packages
/// - `go test` - Test packages
/// - `go vet` - Report likely mistakes
/// - `go fmt` - Format Go source code
///
/// ## Node.js/TypeScript
/// - `tsc` - TypeScript compiler
/// - `node` - Node.js runtime
/// - `npx tsc` - TypeScript via npx
///
/// ## Python
/// - `python -m py_compile` - Compile Python files
/// - `python -m compileall` - Compile Python libraries
/// - `mypy` - Static type checker
/// - `ruff check` - Fast Python linter
/// - `black --check` - Code formatter check
///
/// ## Java
/// - `javac` - Java compiler
/// - `gradle build` - Gradle build
/// - `mvn compile` - Maven compile
/// - `mvn test` - Maven test
///
/// ## C/C++
/// - `make` - Build tool
/// - `cmake` - CMake configuration
/// - `gcc` - GNU C compiler
/// - `g++` - GNU C++ compiler
/// - `clang` - Clang C compiler
/// - `clang++` - Clang C++ compiler
///
/// # Example
///
/// ```
/// use toolcap::{Matcher, Operation};
/// use toolcap::matchers::Compilation;
///
/// let matcher = Compilation::matcher();
///
/// assert!(matcher.matches(&Operation::execute("cargo build --release")));
/// assert!(matcher.matches(&Operation::execute("go test ./...")));
/// assert!(matcher.matches(&Operation::execute("tsc --noEmit")));
/// ```
pub struct Compilation;

impl Compilation {
    /// Creates a matcher for common compilation commands.
    pub fn matcher() -> Matcher {
        Matcher::or(vec![
            // Rust
            Matcher::command("cargo").with_subcommands([
                "build", "check", "test", "clippy", "doc", "fmt", "bench",
            ]),
            Matcher::command("rustc"),
            Matcher::command("rustfmt"),
            // Go
            Matcher::command("go").with_subcommands(["build", "test", "vet", "fmt"]),
            Matcher::command("gofmt"),
            // TypeScript/JavaScript
            Matcher::command("tsc"),
            Matcher::command("node"),
            Matcher::command("npx").with_subcommand("tsc"),
            Matcher::command("esbuild"),
            Matcher::command("swc"),
            // Python
            Matcher::command("python").with_flag("-m"),
            Matcher::command("python3").with_flag("-m"),
            Matcher::command("mypy"),
            Matcher::command("ruff").with_subcommand("check"),
            Matcher::command("black").with_flag("--check"),
            Matcher::command("pylint"),
            Matcher::command("flake8"),
            // Java
            Matcher::command("javac"),
            Matcher::command("gradle").with_subcommands(["build", "test", "check"]),
            Matcher::command("mvn").with_subcommands(["compile", "test", "verify"]),
            // C/C++
            Matcher::command("make"),
            Matcher::command("cmake"),
            Matcher::command("gcc"),
            Matcher::command("g++"),
            Matcher::command("clang"),
            Matcher::command("clang++"),
            Matcher::command("cc"),
            Matcher::command("c++"),
            // Other build tools
            Matcher::command("ninja"),
            Matcher::command("bazel").with_subcommands(["build", "test"]),
            Matcher::command("buck").with_subcommands(["build", "test"]),
            Matcher::command("buck2").with_subcommands(["build", "test"]),
        ])
    }
}

/// Matcher group for safe npm commands.
///
/// Matches npm commands that read package information or run scripts
/// but don't modify package.json or install new dependencies.
///
/// # Included Commands
///
/// - `npm list` / `npm ls` - List installed packages
/// - `npm view` - View registry info about a package
/// - `npm search` - Search for packages
/// - `npm outdated` - Check for outdated packages
/// - `npm audit` - Run a security audit
/// - `npm explain` - Explain installed packages
/// - `npm fund` - Retrieve funding information
/// - `npm doctor` - Check npm environment
/// - `npm config list` - List configuration
/// - `npm help` - Get help on npm
/// - `npm version` - Show npm version (without args that bump version)
/// - `npm run` - Run arbitrary package scripts (use with caution)
/// - `npm test` - Run tests
/// - `npm start` - Start the application
///
/// # Note on `npm run`
///
/// The `npm run` command is included because it's commonly needed for
/// development workflows. However, it executes arbitrary scripts defined
/// in package.json, so consider whether this is appropriate for your
/// security policy.
///
/// # Example
///
/// ```
/// use toolcap::{Matcher, Operation};
/// use toolcap::matchers::SafeNpm;
///
/// let matcher = SafeNpm::matcher();
///
/// assert!(matcher.matches(&Operation::execute("npm list")));
/// assert!(matcher.matches(&Operation::execute("npm test")));
/// assert!(!matcher.matches(&Operation::execute("npm install lodash")));
/// ```
pub struct SafeNpm;

impl SafeNpm {
    /// Creates a matcher for safe npm commands.
    pub fn matcher() -> Matcher {
        Matcher::or(vec![
            // Package information
            Matcher::command("npm").with_subcommands(["list", "ls"]),
            Matcher::command("npm").with_subcommand("view"),
            Matcher::command("npm").with_subcommand("search"),
            Matcher::command("npm").with_subcommand("outdated"),
            Matcher::command("npm").with_subcommand("explain"),
            Matcher::command("npm").with_subcommand("fund"),
            // Security and health
            Matcher::command("npm").with_subcommand("audit"),
            Matcher::command("npm").with_subcommand("doctor"),
            // Configuration (read-only)
            Matcher::command("npm").with_subcommand("config"),
            // Help and version
            Matcher::command("npm").with_subcommand("help"),
            Matcher::command("npm").with_subcommand("version"),
            // Common scripts (potentially risky but commonly needed)
            Matcher::command("npm").with_subcommand("run"),
            Matcher::command("npm").with_subcommand("test"),
            Matcher::command("npm").with_subcommand("start"),
            Matcher::command("npm").with_subcommand("build"),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Operation;

    mod read_only_git {
        use super::*;

        #[test]
        fn test_status_commands() {
            let matcher = ReadOnlyGit::matcher();
            assert!(matcher.matches(&Operation::execute("git status")));
            assert!(matcher.matches(&Operation::execute("git status -s")));
            assert!(matcher.matches(&Operation::execute("git status --porcelain")));
        }

        #[test]
        fn test_log_commands() {
            let matcher = ReadOnlyGit::matcher();
            assert!(matcher.matches(&Operation::execute("git log")));
            assert!(matcher.matches(&Operation::execute("git log --oneline")));
            assert!(matcher.matches(&Operation::execute("git log -n 10")));
            assert!(matcher.matches(&Operation::execute("git log --graph --all")));
        }

        #[test]
        fn test_diff_commands() {
            let matcher = ReadOnlyGit::matcher();
            assert!(matcher.matches(&Operation::execute("git diff")));
            assert!(matcher.matches(&Operation::execute("git diff HEAD~1")));
            assert!(matcher.matches(&Operation::execute("git diff --staged")));
        }

        #[test]
        fn test_show_commands() {
            let matcher = ReadOnlyGit::matcher();
            assert!(matcher.matches(&Operation::execute("git show")));
            assert!(matcher.matches(&Operation::execute("git show HEAD")));
            assert!(matcher.matches(&Operation::execute("git show abc123")));
        }

        #[test]
        fn test_branch_tag_remote() {
            let matcher = ReadOnlyGit::matcher();
            assert!(matcher.matches(&Operation::execute("git branch")));
            assert!(matcher.matches(&Operation::execute("git branch -a")));
            assert!(matcher.matches(&Operation::execute("git tag")));
            assert!(matcher.matches(&Operation::execute("git remote -v")));
        }

        #[test]
        fn test_blame_and_inspection() {
            let matcher = ReadOnlyGit::matcher();
            assert!(matcher.matches(&Operation::execute("git blame src/main.rs")));
            assert!(matcher.matches(&Operation::execute("git describe")));
            assert!(matcher.matches(&Operation::execute("git rev-parse HEAD")));
            assert!(matcher.matches(&Operation::execute("git ls-files")));
        }

        #[test]
        fn test_rejects_write_commands() {
            let matcher = ReadOnlyGit::matcher();
            assert!(!matcher.matches(&Operation::execute("git push origin main")));
            assert!(!matcher.matches(&Operation::execute("git commit -m 'test'")));
            assert!(!matcher.matches(&Operation::execute("git add .")));
            assert!(!matcher.matches(&Operation::execute("git reset --hard")));
            assert!(!matcher.matches(&Operation::execute("git checkout -b new-branch")));
            assert!(!matcher.matches(&Operation::execute("git merge feature")));
            assert!(!matcher.matches(&Operation::execute("git rebase main")));
            assert!(!matcher.matches(&Operation::execute("git pull")));
            assert!(!matcher.matches(&Operation::execute("git fetch")));
        }
    }

    mod compilation {
        use super::*;

        #[test]
        fn test_rust_commands() {
            let matcher = Compilation::matcher();
            assert!(matcher.matches(&Operation::execute("cargo build")));
            assert!(matcher.matches(&Operation::execute("cargo build --release")));
            assert!(matcher.matches(&Operation::execute("cargo check")));
            assert!(matcher.matches(&Operation::execute("cargo test")));
            assert!(matcher.matches(&Operation::execute("cargo test -- --nocapture")));
            assert!(matcher.matches(&Operation::execute("cargo clippy")));
            assert!(matcher.matches(&Operation::execute("cargo doc --open")));
            assert!(matcher.matches(&Operation::execute("cargo fmt")));
            assert!(matcher.matches(&Operation::execute("rustfmt src/main.rs")));
        }

        #[test]
        fn test_go_commands() {
            let matcher = Compilation::matcher();
            assert!(matcher.matches(&Operation::execute("go build")));
            assert!(matcher.matches(&Operation::execute("go build ./...")));
            assert!(matcher.matches(&Operation::execute("go test ./...")));
            assert!(matcher.matches(&Operation::execute("go vet ./...")));
            assert!(matcher.matches(&Operation::execute("go fmt ./...")));
            assert!(matcher.matches(&Operation::execute("gofmt -w .")));
        }

        #[test]
        fn test_typescript_commands() {
            let matcher = Compilation::matcher();
            assert!(matcher.matches(&Operation::execute("tsc")));
            assert!(matcher.matches(&Operation::execute("tsc --noEmit")));
            assert!(matcher.matches(&Operation::execute("npx tsc --build")));
            assert!(matcher.matches(&Operation::execute("node script.js")));
            assert!(matcher.matches(&Operation::execute("esbuild src/index.ts")));
        }

        #[test]
        fn test_python_commands() {
            let matcher = Compilation::matcher();
            assert!(matcher.matches(&Operation::execute("mypy src/")));
            assert!(matcher.matches(&Operation::execute("ruff check .")));
            assert!(matcher.matches(&Operation::execute("black --check .")));
            assert!(matcher.matches(&Operation::execute("pylint src/")));
            assert!(matcher.matches(&Operation::execute("flake8 src/")));
        }

        #[test]
        fn test_java_commands() {
            let matcher = Compilation::matcher();
            assert!(matcher.matches(&Operation::execute("javac Main.java")));
            assert!(matcher.matches(&Operation::execute("gradle build")));
            assert!(matcher.matches(&Operation::execute("gradle test")));
            assert!(matcher.matches(&Operation::execute("mvn compile")));
            assert!(matcher.matches(&Operation::execute("mvn test")));
        }

        #[test]
        fn test_c_cpp_commands() {
            let matcher = Compilation::matcher();
            assert!(matcher.matches(&Operation::execute("make")));
            assert!(matcher.matches(&Operation::execute("make all")));
            assert!(matcher.matches(&Operation::execute("cmake .")));
            assert!(matcher.matches(&Operation::execute("gcc -o main main.c")));
            assert!(matcher.matches(&Operation::execute("g++ -o main main.cpp")));
            assert!(matcher.matches(&Operation::execute("clang main.c")));
            assert!(matcher.matches(&Operation::execute("clang++ main.cpp")));
            assert!(matcher.matches(&Operation::execute("ninja")));
        }

        #[test]
        fn test_rejects_non_build_commands() {
            let matcher = Compilation::matcher();
            assert!(!matcher.matches(&Operation::execute("cargo install ripgrep")));
            assert!(!matcher.matches(&Operation::execute("go install")));
            assert!(!matcher.matches(&Operation::execute("npm install")));
            assert!(!matcher.matches(&Operation::execute("rm -rf /")));
        }
    }

    mod safe_npm {
        use super::*;

        #[test]
        fn test_list_commands() {
            let matcher = SafeNpm::matcher();
            assert!(matcher.matches(&Operation::execute("npm list")));
            assert!(matcher.matches(&Operation::execute("npm ls")));
            assert!(matcher.matches(&Operation::execute("npm list --depth=0")));
        }

        #[test]
        fn test_info_commands() {
            let matcher = SafeNpm::matcher();
            assert!(matcher.matches(&Operation::execute("npm view lodash")));
            assert!(matcher.matches(&Operation::execute("npm search react")));
            assert!(matcher.matches(&Operation::execute("npm outdated")));
            assert!(matcher.matches(&Operation::execute("npm explain lodash")));
            assert!(matcher.matches(&Operation::execute("npm fund")));
        }

        #[test]
        fn test_security_commands() {
            let matcher = SafeNpm::matcher();
            assert!(matcher.matches(&Operation::execute("npm audit")));
            assert!(matcher.matches(&Operation::execute("npm audit --json")));
            assert!(matcher.matches(&Operation::execute("npm doctor")));
        }

        #[test]
        fn test_run_commands() {
            let matcher = SafeNpm::matcher();
            assert!(matcher.matches(&Operation::execute("npm run build")));
            assert!(matcher.matches(&Operation::execute("npm run test")));
            assert!(matcher.matches(&Operation::execute("npm test")));
            assert!(matcher.matches(&Operation::execute("npm start")));
            assert!(matcher.matches(&Operation::execute("npm build")));
        }

        #[test]
        fn test_help_and_config() {
            let matcher = SafeNpm::matcher();
            assert!(matcher.matches(&Operation::execute("npm help")));
            assert!(matcher.matches(&Operation::execute("npm version")));
            assert!(matcher.matches(&Operation::execute("npm config list")));
        }

        #[test]
        fn test_rejects_install_commands() {
            let matcher = SafeNpm::matcher();
            assert!(!matcher.matches(&Operation::execute("npm install")));
            assert!(!matcher.matches(&Operation::execute("npm install lodash")));
            assert!(!matcher.matches(&Operation::execute("npm i lodash")));
            assert!(!matcher.matches(&Operation::execute("npm uninstall lodash")));
            assert!(!matcher.matches(&Operation::execute("npm publish")));
            assert!(!matcher.matches(&Operation::execute("npm update")));
        }
    }

    mod extension {
        use super::*;

        #[test]
        fn test_extend_compilation_with_zig() {
            let extended = Matcher::or(vec![
                Compilation::matcher(),
                Matcher::command("zig").with_subcommand("build"),
            ]);

            // Original commands still work
            assert!(extended.matches(&Operation::execute("cargo build")));
            assert!(extended.matches(&Operation::execute("go test")));

            // Extended command works
            assert!(extended.matches(&Operation::execute("zig build")));
        }

        #[test]
        fn test_combine_multiple_groups() {
            let combined = Matcher::or(vec![
                ReadOnlyGit::matcher(),
                Compilation::matcher(),
                SafeNpm::matcher(),
            ]);

            assert!(combined.matches(&Operation::execute("git status")));
            assert!(combined.matches(&Operation::execute("cargo build")));
            assert!(combined.matches(&Operation::execute("npm list")));
        }
    }
}
