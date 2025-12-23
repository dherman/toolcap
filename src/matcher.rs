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

            Matcher::And(matchers) => matchers
                .iter()
                .all(|m| m.matches(&Operation::Execute(exec_op.clone()))),

            Matcher::Or(matchers) => matchers
                .iter()
                .any(|m| m.matches(&Operation::Execute(exec_op.clone()))),
        }
    }
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
}
