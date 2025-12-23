//! Toolcap: A library for expressing and evaluating tool-use permissions in agentic applications.
//!
//! Toolcap evaluates **operations** against **rulesets** to produce permission decisions.
//!
//! # Example
//!
//! ```
//! use toolcap::{Ruleset, Rule, Matcher, Operation, Outcome};
//!
//! let ruleset = Ruleset::new(vec![
//!     // Allow read-only git commands
//!     Rule::new(
//!         Matcher::command("git").with_subcommands(["status", "log", "diff"]),
//!         Outcome::Allow,
//!     ),
//!     // Deny destructive git commands
//!     Rule::new(
//!         Matcher::command("git").with_subcommands(["push", "reset"]),
//!         Outcome::Deny,
//!     ),
//! ]);
//!
//! let op = Operation::execute("git status");
//! assert_eq!(ruleset.evaluate(&op), Outcome::Allow);
//!
//! let op = Operation::execute("git push");
//! assert_eq!(ruleset.evaluate(&op), Outcome::Deny);
//!
//! let op = Operation::execute("rm -rf /");
//! assert_eq!(ruleset.evaluate(&op), Outcome::Unknown);
//! ```

mod outcome;
mod operation;
mod matcher;
mod rule;
mod ruleset;

#[cfg(feature = "acp")]
mod acp;

pub use outcome::Outcome;
pub use operation::{Operation, ExecuteOperation};
pub use matcher::Matcher;
pub use rule::Rule;
pub use ruleset::Ruleset;
