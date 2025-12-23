use crate::operation::Operation;
use crate::outcome::Outcome;
use crate::rule::Rule;

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
    /// Returns the outcome of the first matching rule, or `Outcome::Unknown`
    /// if no rule matches.
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
        for rule in &self.rules {
            if let Some(outcome) = rule.evaluate(operation) {
                return outcome;
            }
        }
        Outcome::Unknown
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
}
