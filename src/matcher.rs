use std::path::PathBuf;

use crate::operation::{ExecuteOperation, Operation};

/// A matcher is a predicate that determines whether a rule applies to an operation.
///
/// Matchers can be composed using `and` and `or` combinators.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Matches any execute operation.
    AnyExecute,

    /// Matches a specific command by name.
    Command {
        name: String,
        subcommands: Option<Vec<String>>,
        required_flags: Vec<String>,
    },

    /// Matches if the operation's working directory is within the specified directory.
    ///
    /// Uses canonical path resolution to handle symlinks.
    WithinDirectory { path: PathBuf },

    /// Matches if all sub-matchers match (logical AND).
    And(Vec<Matcher>),

    /// Matches if any sub-matcher matches (logical OR).
    Or(Vec<Matcher>),
}

impl Matcher {
    /// Creates a matcher that matches any execute operation.
    pub fn any_execute() -> Self {
        Matcher::AnyExecute
    }

    /// Creates a matcher for a specific command name.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::Matcher;
    ///
    /// // Matches any git command
    /// let m = Matcher::command("git");
    /// ```
    pub fn command(name: impl Into<String>) -> Self {
        Matcher::Command {
            name: name.into(),
            subcommands: None,
            required_flags: Vec::new(),
        }
    }

    /// Restricts this matcher to commands with a specific subcommand.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::Matcher;
    ///
    /// // Matches: git status, git status -s
    /// let m = Matcher::command("git").with_subcommand("status");
    /// ```
    pub fn with_subcommand(self, subcmd: impl Into<String>) -> Self {
        self.with_subcommands([subcmd.into()])
    }

    /// Restricts this matcher to commands with any of the specified subcommands.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::Matcher;
    ///
    /// // Matches: git status, git log, git diff
    /// let m = Matcher::command("git").with_subcommands(["status", "log", "diff"]);
    /// ```
    pub fn with_subcommands<I, S>(self, subcmds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        match self {
            Matcher::Command {
                name,
                subcommands: _,
                required_flags,
            } => Matcher::Command {
                name,
                subcommands: Some(subcmds.into_iter().map(|s| s.into()).collect()),
                required_flags,
            },
            other => other,
        }
    }

    /// Restricts this matcher to commands that have a specific flag.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::Matcher;
    ///
    /// // Matches: rm -rf, rm -rf /tmp
    /// let m = Matcher::command("rm").with_flag("-rf");
    /// ```
    pub fn with_flag(self, flag: impl Into<String>) -> Self {
        match self {
            Matcher::Command {
                name,
                subcommands,
                mut required_flags,
            } => {
                required_flags.push(flag.into());
                Matcher::Command {
                    name,
                    subcommands,
                    required_flags,
                }
            }
            other => other,
        }
    }

    /// Creates a matcher that matches if all sub-matchers match.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::Matcher;
    ///
    /// let m = Matcher::and(vec![
    ///     Matcher::command("npm"),
    ///     Matcher::command("npm").with_subcommand("install"),
    /// ]);
    /// ```
    pub fn and(matchers: Vec<Matcher>) -> Self {
        Matcher::And(matchers)
    }

    /// Creates a matcher that matches if any sub-matcher matches.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::Matcher;
    ///
    /// let m = Matcher::or(vec![
    ///     Matcher::command("cargo").with_subcommand("build"),
    ///     Matcher::command("go").with_subcommand("build"),
    ///     Matcher::command("tsc"),
    /// ]);
    /// ```
    pub fn or(matchers: Vec<Matcher>) -> Self {
        Matcher::Or(matchers)
    }

    /// Creates a matcher that matches if the operation's working directory is within
    /// the specified directory subtree.
    ///
    /// This matcher uses canonical path resolution to handle symlinks, preventing
    /// symlink-based bypasses of directory restrictions.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::{Matcher, Operation};
    ///
    /// // Matches operations executed within /home/user/project
    /// let m = Matcher::within_directory("/home/user/project");
    ///
    /// // Combine with command matchers for scoped rules
    /// let scoped_npm = Matcher::and(vec![
    ///     Matcher::command("npm"),
    ///     Matcher::within_directory("/home/user/project"),
    /// ]);
    /// ```
    pub fn within_directory(path: impl Into<PathBuf>) -> Self {
        Matcher::WithinDirectory { path: path.into() }
    }

    /// Tests whether this matcher matches the given operation.
    pub fn matches(&self, operation: &Operation) -> bool {
        match operation {
            Operation::Execute(exec_op) => self.matches_execute(exec_op),
            _ => false, // For MVP, only execute operations are matched
        }
    }

    fn matches_execute(&self, exec_op: &ExecuteOperation) -> bool {
        match self {
            Matcher::AnyExecute => true,

            Matcher::Command {
                name,
                subcommands,
                required_flags,
            } => {
                // Check command name
                let Some(cmd_name) = exec_op.command_name() else {
                    return false;
                };
                if cmd_name != name {
                    return false;
                }

                // Check subcommand if specified
                if let Some(allowed_subcmds) = subcommands {
                    let Some(subcmd) = exec_op.subcommand() else {
                        return false;
                    };
                    if !allowed_subcmds.iter().any(|s| s == subcmd) {
                        return false;
                    }
                }

                // Check required flags
                for flag in required_flags {
                    if !exec_op.has_flag(flag) {
                        return false;
                    }
                }

                true
            }

            Matcher::WithinDirectory { path } => {
                // Get the operation's working directory
                let Some(working_dir) = exec_op.working_dir() else {
                    // No working directory context - can't verify containment
                    return false;
                };

                is_within_directory(working_dir, path)
            }

            Matcher::And(matchers) => matchers
                .iter()
                .all(|m| m.matches(&Operation::Execute(exec_op.clone()))),

            Matcher::Or(matchers) => matchers
                .iter()
                .any(|m| m.matches(&Operation::Execute(exec_op.clone()))),
        }
    }
}

/// Checks if `child` is within the directory subtree rooted at `parent`.
///
/// Uses canonical path resolution to handle symlinks, preventing symlink-based
/// bypasses of directory restrictions.
///
/// Returns `false` if either path cannot be canonicalized (e.g., doesn't exist).
fn is_within_directory(child: &PathBuf, parent: &PathBuf) -> bool {
    // Canonicalize both paths to resolve symlinks and get absolute paths
    let Ok(canonical_child) = child.canonicalize() else {
        return false;
    };
    let Ok(canonical_parent) = parent.canonicalize() else {
        return false;
    };

    // Check if the child path starts with the parent path
    canonical_child.starts_with(&canonical_parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_any_execute() {
        let matcher = Matcher::any_execute();
        let op = Operation::execute("anything at all");
        assert!(matcher.matches(&op));
    }

    #[test]
    fn test_command_match() {
        let matcher = Matcher::command("git");
        assert!(matcher.matches(&Operation::execute("git status")));
        assert!(matcher.matches(&Operation::execute("git log --oneline")));
        assert!(!matcher.matches(&Operation::execute("cargo build")));
    }

    #[test]
    fn test_command_with_subcommand() {
        let matcher = Matcher::command("git").with_subcommand("status");
        assert!(matcher.matches(&Operation::execute("git status")));
        assert!(matcher.matches(&Operation::execute("git status -s")));
        assert!(!matcher.matches(&Operation::execute("git log")));
        assert!(!matcher.matches(&Operation::execute("git")));
    }

    #[test]
    fn test_command_with_subcommands() {
        let matcher = Matcher::command("git").with_subcommands(["status", "log", "diff"]);
        assert!(matcher.matches(&Operation::execute("git status")));
        assert!(matcher.matches(&Operation::execute("git log")));
        assert!(matcher.matches(&Operation::execute("git diff")));
        assert!(!matcher.matches(&Operation::execute("git push")));
    }

    #[test]
    fn test_command_with_flag() {
        let matcher = Matcher::command("rm").with_flag("-rf");
        assert!(matcher.matches(&Operation::execute("rm -rf /tmp")));
        assert!(!matcher.matches(&Operation::execute("rm /tmp")));
        assert!(!matcher.matches(&Operation::execute("rm -r /tmp")));
    }

    #[test]
    fn test_and_matcher() {
        let matcher = Matcher::and(vec![
            Matcher::command("git"),
            Matcher::command("git").with_subcommand("push"),
        ]);
        assert!(matcher.matches(&Operation::execute("git push origin main")));
        assert!(!matcher.matches(&Operation::execute("git status")));
    }

    #[test]
    fn test_or_matcher() {
        let matcher = Matcher::or(vec![
            Matcher::command("cargo").with_subcommand("build"),
            Matcher::command("go").with_subcommand("build"),
        ]);
        assert!(matcher.matches(&Operation::execute("cargo build")));
        assert!(matcher.matches(&Operation::execute("go build")));
        assert!(!matcher.matches(&Operation::execute("npm build")));
    }

    #[test]
    fn test_non_execute_operations() {
        let matcher = Matcher::command("git");
        let op = Operation::Read {
            path: "/etc/passwd".into(),
        };
        assert!(!matcher.matches(&op));
    }

    mod directory_scoping {
        use super::*;
        use std::fs;

        #[test]
        fn test_within_directory_matches_exact_dir() {
            // Use the current directory which we know exists
            let current_dir = std::env::current_dir().unwrap();
            let matcher = Matcher::within_directory(&current_dir);
            let op = Operation::execute_in("ls", &current_dir);
            assert!(matcher.matches(&op));
        }

        #[test]
        fn test_within_directory_matches_subdirectory() {
            let current_dir = std::env::current_dir().unwrap();
            let src_dir = current_dir.join("src");
            let matcher = Matcher::within_directory(&current_dir);
            let op = Operation::execute_in("ls", &src_dir);
            assert!(matcher.matches(&op));
        }

        #[test]
        fn test_within_directory_rejects_parent_directory() {
            let current_dir = std::env::current_dir().unwrap();
            let src_dir = current_dir.join("src");
            let matcher = Matcher::within_directory(&src_dir);
            // Operation in parent directory should not match
            let op = Operation::execute_in("ls", &current_dir);
            assert!(!matcher.matches(&op));
        }

        #[test]
        fn test_within_directory_rejects_sibling_directory() {
            let current_dir = std::env::current_dir().unwrap();
            let src_dir = current_dir.join("src");
            let docs_dir = current_dir.join("docs");
            let matcher = Matcher::within_directory(&src_dir);
            // Operation in sibling directory should not match
            let op = Operation::execute_in("ls", &docs_dir);
            assert!(!matcher.matches(&op));
        }

        #[test]
        fn test_within_directory_no_working_dir_returns_false() {
            let current_dir = std::env::current_dir().unwrap();
            let matcher = Matcher::within_directory(&current_dir);
            // Operation without working directory context
            let op = Operation::execute("ls");
            assert!(!matcher.matches(&op));
        }

        #[test]
        fn test_within_directory_nonexistent_allowed_dir_returns_false() {
            let current_dir = std::env::current_dir().unwrap();
            let matcher = Matcher::within_directory("/nonexistent/path/that/does/not/exist");
            let op = Operation::execute_in("ls", &current_dir);
            // Cannot canonicalize nonexistent allowed directory
            assert!(!matcher.matches(&op));
        }

        #[test]
        fn test_within_directory_nonexistent_working_dir_returns_false() {
            let current_dir = std::env::current_dir().unwrap();
            let matcher = Matcher::within_directory(&current_dir);
            let op = Operation::execute_in("ls", "/nonexistent/path/that/does/not/exist");
            // Cannot canonicalize nonexistent working directory
            assert!(!matcher.matches(&op));
        }

        #[test]
        fn test_within_directory_combined_with_command_matcher() {
            let current_dir = std::env::current_dir().unwrap();
            let src_dir = current_dir.join("src");

            // Only allow npm commands within src directory
            let matcher = Matcher::and(vec![
                Matcher::command("npm"),
                Matcher::within_directory(&src_dir),
            ]);

            // npm in src - should match
            let op = Operation::execute_in("npm install", &src_dir);
            assert!(matcher.matches(&op));

            // npm in parent - should not match
            let op = Operation::execute_in("npm install", &current_dir);
            assert!(!matcher.matches(&op));

            // non-npm in src - should not match
            let op = Operation::execute_in("cargo build", &src_dir);
            assert!(!matcher.matches(&op));
        }

        #[test]
        fn test_within_directory_or_multiple_dirs() {
            let current_dir = std::env::current_dir().unwrap();
            let src_dir = current_dir.join("src");
            let docs_dir = current_dir.join("docs");

            // Allow in either src or docs
            let matcher = Matcher::or(vec![
                Matcher::within_directory(&src_dir),
                Matcher::within_directory(&docs_dir),
            ]);

            let op = Operation::execute_in("ls", &src_dir);
            assert!(matcher.matches(&op));

            let op = Operation::execute_in("ls", &docs_dir);
            assert!(matcher.matches(&op));

            // Not in src or docs - should not match
            let op = Operation::execute_in("ls", &current_dir);
            assert!(!matcher.matches(&op));
        }

        #[test]
        fn test_symlink_resolution() {
            // Create a temporary directory structure with a symlink
            let temp_dir = std::env::temp_dir().join("toolcap_test_symlinks");
            let _ = fs::remove_dir_all(&temp_dir); // Clean up any previous test
            fs::create_dir_all(&temp_dir).unwrap();

            let real_dir = temp_dir.join("real");
            let outside_dir = temp_dir.join("outside");
            fs::create_dir_all(&real_dir).unwrap();
            fs::create_dir_all(&outside_dir).unwrap();

            // Create a symlink inside real_dir that points to outside_dir
            let symlink_path = real_dir.join("sneaky_link");
            #[cfg(unix)]
            std::os::unix::fs::symlink(&outside_dir, &symlink_path).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(&outside_dir, &symlink_path).unwrap();

            // Matcher allows only real_dir
            let matcher = Matcher::within_directory(&real_dir);

            // Direct access to outside_dir should be denied
            let op = Operation::execute_in("ls", &outside_dir);
            assert!(!matcher.matches(&op));

            // Access through symlink should also be denied (canonical path resolves outside)
            let op = Operation::execute_in("ls", &symlink_path);
            assert!(!matcher.matches(&op));

            // Access to real_dir itself should be allowed
            let op = Operation::execute_in("ls", &real_dir);
            assert!(matcher.matches(&op));

            // Clean up
            let _ = fs::remove_dir_all(&temp_dir);
        }

        #[test]
        fn test_symlink_to_subdirectory() {
            // Create a temporary directory structure
            let temp_dir = std::env::temp_dir().join("toolcap_test_symlinks_subdir");
            let _ = fs::remove_dir_all(&temp_dir);
            fs::create_dir_all(&temp_dir).unwrap();

            let project_dir = temp_dir.join("project");
            let subdir = project_dir.join("subdir");
            fs::create_dir_all(&subdir).unwrap();

            // Create a symlink inside project that points to its own subdir
            let symlink_path = project_dir.join("link_to_subdir");
            #[cfg(unix)]
            std::os::unix::fs::symlink(&subdir, &symlink_path).unwrap();
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(&subdir, &symlink_path).unwrap();

            // Matcher allows project_dir
            let matcher = Matcher::within_directory(&project_dir);

            // Access through symlink to internal subdir should be allowed
            // (canonical path resolves to inside project_dir)
            let op = Operation::execute_in("ls", &symlink_path);
            assert!(matcher.matches(&op));

            // Clean up
            let _ = fs::remove_dir_all(&temp_dir);
        }

        #[test]
        fn test_deeply_nested_path() {
            let current_dir = std::env::current_dir().unwrap();
            // src/shell.rs should be within current_dir
            let nested_path = current_dir.join("src");

            let matcher = Matcher::within_directory(&current_dir);
            let op = Operation::execute_in("ls", &nested_path);
            assert!(matcher.matches(&op));
        }
    }
}
