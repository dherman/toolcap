use crate::operation::{ExecuteOperation, Operation};
use crate::outcome::Outcome;
use crate::rule::Rule;
use crate::shell::{parse, ParsedCommand, ShellAst};

/// A ruleset is an ordered list of rules.
///
/// When evaluating an operation, the ruleset checks each rule in order until
/// one matches. The first matching rule determines the outcome.
///
/// If no rule matches, the ruleset returns `Outcome::Unknown`, signaling that
/// the operation should be escalated to the user.
#[derive(Debug, Clone)]
pub struct Ruleset {
    rules: Vec<Rule>,
}

impl Ruleset {
    /// Creates a new ruleset with the given rules.
    ///
    /// Rules are evaluated in order, so more specific rules should come before
    /// more general ones.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::{Ruleset, Rule, Matcher, Outcome};
    ///
    /// let ruleset = Ruleset::new(vec![
    ///     // Specific rule: deny force push
    ///     Rule::new(
    ///         Matcher::command("git")
    ///             .with_subcommand("push")
    ///             .with_flag("--force"),
    ///         Outcome::Deny,
    ///     ),
    ///     // General rule: allow push
    ///     Rule::new(
    ///         Matcher::command("git").with_subcommand("push"),
    ///         Outcome::Allow,
    ///     ),
    /// ]);
    /// ```
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Creates an empty ruleset.
    ///
    /// An empty ruleset returns `Outcome::Unknown` for all operations.
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Returns the rules in this ruleset.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Evaluates an operation against this ruleset.
    ///
    /// For execute operations, this parses the command and evaluates compound
    /// commands (pipelines, logical operators) recursively. A compound command
    /// is allowed only if all parts are allowed, denied if any part is denied,
    /// and unknown if any part is unknown and none are denied.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::{Ruleset, Rule, Matcher, Operation, Outcome};
    ///
    /// let ruleset = Ruleset::new(vec![
    ///     Rule::new(Matcher::command("git"), Outcome::Allow),
    /// ]);
    ///
    /// assert_eq!(ruleset.evaluate(&Operation::execute("git status")), Outcome::Allow);
    /// assert_eq!(ruleset.evaluate(&Operation::execute("rm -rf /")), Outcome::Unknown);
    /// ```
    pub fn evaluate(&self, operation: &Operation) -> Outcome {
        match operation {
            Operation::Execute(exec_op) => self.evaluate_execute(exec_op),
            _ => self.evaluate_simple(operation),
        }
    }

    /// Evaluates a non-execute operation using simple rule matching.
    fn evaluate_simple(&self, operation: &Operation) -> Outcome {
        for rule in &self.rules {
            if let Some(outcome) = rule.evaluate(operation) {
                return outcome;
            }
        }
        Outcome::Unknown
    }

    /// Evaluates an execute operation, handling compound commands.
    fn evaluate_execute(&self, exec_op: &ExecuteOperation) -> Outcome {
        // Try to parse the command
        match parse(exec_op.raw()) {
            Ok(ast) => self.evaluate_ast(&ast, exec_op.working_dir()),
            Err(_) => {
                // If parsing fails (e.g., unsupported shell features),
                // return Unknown to escalate to the user
                Outcome::Unknown
            }
        }
    }

    /// Recursively evaluates a shell AST node.
    ///
    /// The evaluation semantics are:
    /// - Compound allowed only if all parts allowed
    /// - Compound denied if any part denied
    /// - Compound unknown if any part unknown and none denied
    fn evaluate_ast(&self, ast: &ShellAst, working_dir: Option<&std::path::PathBuf>) -> Outcome {
        match ast {
            ShellAst::Simple(cmd) => self.evaluate_simple_command(cmd, working_dir),

            ShellAst::Pipeline(cmds)
            | ShellAst::And(cmds)
            | ShellAst::Or(cmds)
            | ShellAst::Sequence(cmds) => self.evaluate_compound(cmds, working_dir),

            ShellAst::Unsupported(_) => {
                // Unsupported constructs should escalate to the user
                Outcome::Unknown
            }
        }
    }

    /// Evaluates a compound command (pipeline, &&, ||, ;).
    ///
    /// Semantics:
    /// - If any component is Deny, the compound is Deny
    /// - If all components are Allow, the compound is Allow
    /// - Otherwise (any Unknown, none Deny), the compound is Unknown
    fn evaluate_compound(
        &self,
        cmds: &[ShellAst],
        working_dir: Option<&std::path::PathBuf>,
    ) -> Outcome {
        let mut has_unknown = false;

        for cmd in cmds {
            match self.evaluate_ast(cmd, working_dir) {
                Outcome::Deny => return Outcome::Deny,
                Outcome::Unknown => has_unknown = true,
                Outcome::Allow => {}
            }
        }

        if has_unknown {
            Outcome::Unknown
        } else {
            Outcome::Allow
        }
    }

    /// Evaluates a simple (non-compound) command.
    fn evaluate_simple_command(
        &self,
        cmd: &ParsedCommand,
        working_dir: Option<&std::path::PathBuf>,
    ) -> Outcome {
        // Create an ExecuteOperation from the parsed command
        let raw = if cmd.args.is_empty() {
            cmd.name.clone()
        } else {
            format!("{} {}", cmd.name, cmd.args.join(" "))
        };

        let mut exec_op = ExecuteOperation::new(raw);
        if let Some(dir) = working_dir {
            exec_op = exec_op.with_working_dir(dir.clone());
        }

        let operation = Operation::Execute(exec_op);
        self.evaluate_simple(&operation)
    }
}

impl Default for Ruleset {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::Matcher;

    #[test]
    fn test_empty_ruleset() {
        let ruleset = Ruleset::empty();
        let op = Operation::execute("git status");
        assert_eq!(ruleset.evaluate(&op), Outcome::Unknown);
    }

    #[test]
    fn test_single_allow_rule() {
        let ruleset = Ruleset::new(vec![Rule::new(Matcher::command("git"), Outcome::Allow)]);

        assert_eq!(
            ruleset.evaluate(&Operation::execute("git status")),
            Outcome::Allow
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("cargo build")),
            Outcome::Unknown
        );
    }

    #[test]
    fn test_single_deny_rule() {
        let ruleset = Ruleset::new(vec![Rule::new(Matcher::command("sudo"), Outcome::Deny)]);

        assert_eq!(
            ruleset.evaluate(&Operation::execute("sudo rm -rf /")),
            Outcome::Deny
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("rm -rf /")),
            Outcome::Unknown
        );
    }

    #[test]
    fn test_rule_order_matters() {
        // Specific deny before general allow
        let ruleset = Ruleset::new(vec![
            Rule::new(
                Matcher::command("git")
                    .with_subcommand("push")
                    .with_flag("--force"),
                Outcome::Deny,
            ),
            Rule::new(Matcher::command("git").with_subcommand("push"), Outcome::Allow),
        ]);

        // Force push is denied
        assert_eq!(
            ruleset.evaluate(&Operation::execute("git push --force")),
            Outcome::Deny
        );
        // Regular push is allowed
        assert_eq!(
            ruleset.evaluate(&Operation::execute("git push origin main")),
            Outcome::Allow
        );
    }

    #[test]
    fn test_first_match_wins() {
        let ruleset = Ruleset::new(vec![
            Rule::new(Matcher::command("git"), Outcome::Allow),
            Rule::new(Matcher::command("git"), Outcome::Deny), // Never reached
        ]);

        assert_eq!(
            ruleset.evaluate(&Operation::execute("git status")),
            Outcome::Allow
        );
    }

    #[test]
    fn test_multiple_command_rules() {
        let ruleset = Ruleset::new(vec![
            Rule::new(
                Matcher::command("git").with_subcommands(["status", "log", "diff"]),
                Outcome::Allow,
            ),
            Rule::new(
                Matcher::command("cargo").with_subcommands(["build", "test", "check"]),
                Outcome::Allow,
            ),
            Rule::new(Matcher::command("sudo"), Outcome::Deny),
        ]);

        assert_eq!(
            ruleset.evaluate(&Operation::execute("git status")),
            Outcome::Allow
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("git log --oneline")),
            Outcome::Allow
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("cargo build --release")),
            Outcome::Allow
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("cargo test")),
            Outcome::Allow
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("sudo apt install")),
            Outcome::Deny
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("rm -rf /")),
            Outcome::Unknown
        );
    }

    #[test]
    fn test_development_workflow_ruleset() {
        // Example from the RFC
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

        // Read-only git allowed
        assert_eq!(
            ruleset.evaluate(&Operation::execute("git status")),
            Outcome::Allow
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("git log --oneline")),
            Outcome::Allow
        );

        // Destructive git denied
        assert_eq!(
            ruleset.evaluate(&Operation::execute("git push origin main")),
            Outcome::Deny
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("git reset --hard HEAD~1")),
            Outcome::Deny
        );

        // Cargo allowed
        assert_eq!(
            ruleset.evaluate(&Operation::execute("cargo build --release")),
            Outcome::Allow
        );
        assert_eq!(
            ruleset.evaluate(&Operation::execute("cargo test")),
            Outcome::Allow
        );

        // Unknown commands
        assert_eq!(
            ruleset.evaluate(&Operation::execute("npm install")),
            Outcome::Unknown
        );
    }

    // ============================================================
    // Phase 4: Compound Command Evaluation Tests
    // ============================================================

    mod compound_evaluation {
        use super::*;

        fn test_ruleset() -> Ruleset {
            Ruleset::new(vec![
                Rule::new(Matcher::command("find"), Outcome::Allow),
                Rule::new(Matcher::command("grep"), Outcome::Allow),
                Rule::new(Matcher::command("head"), Outcome::Allow),
                Rule::new(Matcher::command("sort"), Outcome::Allow),
                Rule::new(Matcher::command("uniq"), Outcome::Allow),
                Rule::new(Matcher::command("xargs"), Outcome::Allow),
                Rule::new(Matcher::command("cat"), Outcome::Allow),
                Rule::new(Matcher::command("echo"), Outcome::Allow),
                Rule::new(Matcher::command("make"), Outcome::Allow),
                Rule::new(Matcher::command("cargo").with_subcommand("build"), Outcome::Allow),
                Rule::new(Matcher::command("cargo").with_subcommand("test"), Outcome::Allow),
                Rule::new(Matcher::command("rm").with_flag("-rf"), Outcome::Deny),
                Rule::new(Matcher::command("sudo"), Outcome::Deny),
            ])
        }

        // ========== Pipeline Tests ==========

        #[test]
        fn test_pipeline_all_allowed() {
            let ruleset = test_ruleset();
            // All commands in the pipeline are allowed
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . | grep foo")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_pipeline_all_allowed_long() {
            let ruleset = test_ruleset();
            // Long pipeline with all allowed commands
            assert_eq!(
                ruleset.evaluate(&Operation::execute("cat file | grep pattern | sort | uniq | head -10")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_pipeline_one_denied() {
            let ruleset = test_ruleset();
            // Pipeline with one denied command should be denied
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . | sudo cat /etc/shadow")),
                Outcome::Deny
            );
        }

        #[test]
        fn test_pipeline_one_unknown() {
            let ruleset = test_ruleset();
            // Pipeline with one unknown command (wget not in ruleset)
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . | wget")),
                Outcome::Unknown
            );
        }

        #[test]
        fn test_pipeline_denied_beats_unknown() {
            let ruleset = test_ruleset();
            // Pipeline with both unknown and denied - denied wins
            assert_eq!(
                ruleset.evaluate(&Operation::execute("wget foo | sudo bar")),
                Outcome::Deny
            );
        }

        // ========== Logical AND (&&) Tests ==========

        #[test]
        fn test_and_all_allowed() {
            let ruleset = test_ruleset();
            // Both commands allowed
            assert_eq!(
                ruleset.evaluate(&Operation::execute("make && make")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_and_chained_allowed() {
            let ruleset = test_ruleset();
            // Multiple chained commands all allowed
            assert_eq!(
                ruleset.evaluate(&Operation::execute("cargo build && cargo test && echo done")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_and_one_denied() {
            let ruleset = test_ruleset();
            // One denied command in the chain
            assert_eq!(
                ruleset.evaluate(&Operation::execute("cargo build && rm -rf /")),
                Outcome::Deny
            );
        }

        #[test]
        fn test_and_first_denied() {
            let ruleset = test_ruleset();
            // First command denied
            assert_eq!(
                ruleset.evaluate(&Operation::execute("sudo apt update && cargo build")),
                Outcome::Deny
            );
        }

        #[test]
        fn test_and_one_unknown() {
            let ruleset = test_ruleset();
            // One unknown command in the chain
            assert_eq!(
                ruleset.evaluate(&Operation::execute("make && npm install")),
                Outcome::Unknown
            );
        }

        // ========== Logical OR (||) Tests ==========

        #[test]
        fn test_or_all_allowed() {
            let ruleset = test_ruleset();
            // Both commands allowed
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . || echo not found")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_or_one_denied() {
            let ruleset = test_ruleset();
            // One denied in OR - still denied because it could execute
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . || sudo rm -rf /")),
                Outcome::Deny
            );
        }

        #[test]
        fn test_or_one_unknown() {
            let ruleset = test_ruleset();
            // One unknown in OR
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . || unknown_cmd")),
                Outcome::Unknown
            );
        }

        // ========== Mixed Compound Commands ==========

        #[test]
        fn test_mixed_pipeline_and_and() {
            let ruleset = test_ruleset();
            // Pipeline followed by &&
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . | grep foo && echo done")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_mixed_and_and_pipeline() {
            let ruleset = test_ruleset();
            // && followed by pipeline
            assert_eq!(
                ruleset.evaluate(&Operation::execute("make && cat file | head -10")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_mixed_complex() {
            let ruleset = test_ruleset();
            // Complex nested structure
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . | grep foo && sort | uniq")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_mixed_with_denied() {
            let ruleset = test_ruleset();
            // Complex with one denied component
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . | grep foo && sudo cat /etc/shadow")),
                Outcome::Deny
            );
        }

        #[test]
        fn test_mixed_pipeline_or() {
            let ruleset = test_ruleset();
            // Pipeline with OR
            assert_eq!(
                ruleset.evaluate(&Operation::execute("cat file | grep pattern || echo not found")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_mixed_and_or() {
            let ruleset = test_ruleset();
            // AND then OR: (a && b) || c
            assert_eq!(
                ruleset.evaluate(&Operation::execute("make && make || echo failed")),
                Outcome::Allow
            );
        }

        // ========== Edge Cases ==========

        #[test]
        fn test_unsupported_shell_features_return_unknown() {
            let ruleset = test_ruleset();
            // Commands with unsupported features should return Unknown
            assert_eq!(
                ruleset.evaluate(&Operation::execute("echo $HOME")),
                Outcome::Unknown
            );
        }

        #[test]
        fn test_command_substitution_returns_unknown() {
            let ruleset = test_ruleset();
            assert_eq!(
                ruleset.evaluate(&Operation::execute("echo $(whoami)")),
                Outcome::Unknown
            );
        }

        #[test]
        fn test_simple_command_still_works() {
            let ruleset = test_ruleset();
            // Simple commands should still work
            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . -name '*.rs'")),
                Outcome::Allow
            );
        }

        #[test]
        fn test_empty_pipeline_components() {
            // Regression test: ensure we don't panic on edge cases
            let ruleset = test_ruleset();
            let result = ruleset.evaluate(&Operation::execute("cat"));
            assert_eq!(result, Outcome::Allow);
        }

        #[test]
        fn test_rfc_example_compound_allowed() {
            // Example from the RFC: compound allowed if all parts allowed
            // Note: "xargs grep" parses as xargs with arg "grep", not a subcommand
            // so we need to also allow grep for this to work
            let ruleset = Ruleset::new(vec![
                Rule::new(Matcher::command("find"), Outcome::Allow),
                Rule::new(Matcher::command("grep"), Outcome::Allow),
                Rule::new(Matcher::command("xargs"), Outcome::Allow),
            ]);

            assert_eq!(
                ruleset.evaluate(&Operation::execute("find . -name '*.ts' | xargs grep interface")),
                Outcome::Allow
            );
        }
    }
}
