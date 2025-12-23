use std::path::PathBuf;

/// An operation represents an attempted tool use by an agent.
///
/// Operations are typed according to ACP's `ToolKind` variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Reading files or data.
    Read { path: PathBuf },
    /// Modifying files or content.
    Edit { path: PathBuf },
    /// Removing files or data.
    Delete { path: PathBuf },
    /// Moving or renaming files.
    Move { from: PathBuf, to: PathBuf },
    /// Searching for information.
    Search { query: String },
    /// Running commands or code.
    Execute(ExecuteOperation),
    /// Retrieving external data.
    Fetch { url: String },
    /// Internal reasoning (typically always allowed).
    Think,
    /// Switching session mode.
    SwitchMode { mode: String },
    /// Uncategorized operations.
    Other { name: String, description: Option<String> },
}

impl Operation {
    /// Creates an execute operation from a shell command string.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::Operation;
    ///
    /// let op = Operation::execute("git status");
    /// ```
    pub fn execute(command: impl Into<String>) -> Self {
        Operation::Execute(ExecuteOperation::new(command))
    }

    /// Creates an execute operation with a working directory.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::Operation;
    ///
    /// let op = Operation::execute_in("git status", "/home/user/project");
    /// ```
    pub fn execute_in(command: impl Into<String>, working_dir: impl Into<PathBuf>) -> Self {
        Operation::Execute(ExecuteOperation::new(command).with_working_dir(working_dir))
    }
}

/// Holds parsed command data for execute operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteOperation {
    /// The raw command string.
    raw: String,
    /// The working directory context, if known.
    working_dir: Option<PathBuf>,
}

impl ExecuteOperation {
    /// Creates a new execute operation from a command string.
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            raw: command.into(),
            working_dir: None,
        }
    }

    /// Sets the working directory for this operation.
    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Returns the raw command string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the working directory, if set.
    pub fn working_dir(&self) -> Option<&PathBuf> {
        self.working_dir.as_ref()
    }

    /// Parses the command and returns the command name (the first word).
    ///
    /// This is a simple implementation for the MVP that splits on whitespace.
    /// Phase 2 will add proper shell parsing.
    pub fn command_name(&self) -> Option<&str> {
        self.raw.split_whitespace().next()
    }

    /// Returns the arguments after the command name.
    ///
    /// This is a simple implementation for the MVP that splits on whitespace.
    /// Phase 2 will add proper shell parsing.
    pub fn args(&self) -> impl Iterator<Item = &str> {
        self.raw.split_whitespace().skip(1)
    }

    /// Returns the subcommand (first argument), if present.
    ///
    /// For commands like `git status`, this returns `Some("status")`.
    pub fn subcommand(&self) -> Option<&str> {
        self.args().next()
    }

    /// Checks if a specific flag is present in the arguments.
    ///
    /// This is a simple implementation that does exact string matching.
    pub fn has_flag(&self, flag: &str) -> bool {
        self.args().any(|arg| arg == flag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_name() {
        let op = ExecuteOperation::new("git status");
        assert_eq!(op.command_name(), Some("git"));
    }

    #[test]
    fn test_subcommand() {
        let op = ExecuteOperation::new("git status -s");
        assert_eq!(op.subcommand(), Some("status"));
    }

    #[test]
    fn test_has_flag() {
        let op = ExecuteOperation::new("git log --oneline -n 10");
        assert!(op.has_flag("--oneline"));
        assert!(op.has_flag("-n"));
        assert!(!op.has_flag("--all"));
    }

    #[test]
    fn test_args() {
        let op = ExecuteOperation::new("cargo build --release");
        let args: Vec<_> = op.args().collect();
        assert_eq!(args, vec!["build", "--release"]);
    }

    #[test]
    fn test_working_dir() {
        let op = ExecuteOperation::new("ls").with_working_dir("/home/user");
        assert_eq!(op.working_dir(), Some(&PathBuf::from("/home/user")));
    }
}
