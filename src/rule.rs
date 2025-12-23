use crate::matcher::Matcher;
use crate::operation::Operation;
use crate::outcome::Outcome;

/// A rule pairs a matcher (predicate) with an outcome (allow or deny).
///
/// When a rule's matcher matches an operation, the rule's outcome is returned.
#[derive(Debug, Clone)]
pub struct Rule {
    matcher: Matcher,
    outcome: Outcome,
}

impl Rule {
    /// Creates a new rule with the given matcher and outcome.
    ///
    /// # Example
    ///
    /// ```
    /// use toolcap::{Rule, Matcher, Outcome};
    ///
    /// let rule = Rule::new(
    ///     Matcher::command("git").with_subcommand("status"),
    ///     Outcome::Allow,
    /// );
    /// ```
    pub fn new(matcher: Matcher, outcome: Outcome) -> Self {
        Self { matcher, outcome }
    }

    /// Returns the matcher for this rule.
    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    /// Returns the outcome for this rule.
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Evaluates this rule against an operation.
    ///
    /// Returns `Some(outcome)` if the rule matches, `None` otherwise.
    pub fn evaluate(&self, operation: &Operation) -> Option<Outcome> {
        if self.matcher.matches(operation) {
            Some(self.outcome)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_matches() {
        let rule = Rule::new(Matcher::command("git"), Outcome::Allow);

        let op = Operation::execute("git status");
        assert_eq!(rule.evaluate(&op), Some(Outcome::Allow));
    }

    #[test]
    fn test_rule_no_match() {
        let rule = Rule::new(Matcher::command("git"), Outcome::Allow);

        let op = Operation::execute("cargo build");
        assert_eq!(rule.evaluate(&op), None);
    }

    #[test]
    fn test_rule_deny() {
        let rule = Rule::new(Matcher::command("sudo"), Outcome::Deny);

        let op = Operation::execute("sudo rm -rf /");
        assert_eq!(rule.evaluate(&op), Some(Outcome::Deny));
    }
}
