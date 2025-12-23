/// The result of evaluating an operation against a ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The operation is permitted.
    Allow,
    /// The operation is forbidden.
    Deny,
    /// No rule matched; the client should escalate to the user.
    Unknown,
}
