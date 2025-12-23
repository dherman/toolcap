//! ACP (Agent Control Protocol) integration.
//!
//! This module provides conversions between ACP types and Toolcap types,
//! enabling Toolcap to evaluate permission requests from ACP-compatible agents.
//!
//! # Example
//!
//! ```ignore
//! use toolcap::{Ruleset, Rule, Matcher, Outcome};
//! use sacp::schema::RequestPermissionRequest;
//!
//! let ruleset = Ruleset::new(vec![
//!     Rule::new(Matcher::command("git"), Outcome::Allow),
//! ]);
//!
//! // When you receive a permission request from an ACP agent:
//! let outcome = ruleset.evaluate_request(&request);
//! ```

use sacp::schema::{RequestPermissionRequest, ToolKind};

use crate::operation::{ExecuteOperation, Operation};
use crate::outcome::Outcome;
use crate::ruleset::Ruleset;

impl Operation {
    /// Constructs an `Operation` from an ACP `RequestPermissionRequest`.
    ///
    /// This extracts the tool kind and relevant data from the request to create
    /// the appropriate `Operation` variant.
    pub fn from_request(req: &RequestPermissionRequest) -> Self {
        let fields = &req.tool_call.fields;

        // Get the tool kind, defaulting to Other if not specified
        let kind = fields.kind.unwrap_or_default();

        match kind {
            ToolKind::Execute => {
                // For execute operations, extract the command from raw_input
                let command = extract_command_from_input(fields.raw_input.as_ref());
                Operation::Execute(ExecuteOperation::new(command))
            }
            ToolKind::Read => {
                let path = extract_path_from_input(fields.raw_input.as_ref());
                Operation::Read { path: path.into() }
            }
            ToolKind::Edit => {
                let path = extract_path_from_input(fields.raw_input.as_ref());
                Operation::Edit { path: path.into() }
            }
            ToolKind::Delete => {
                let path = extract_path_from_input(fields.raw_input.as_ref());
                Operation::Delete { path: path.into() }
            }
            ToolKind::Move => {
                // Move operations typically have "from" and "to" fields
                let (from, to) = extract_move_paths_from_input(fields.raw_input.as_ref());
                Operation::Move {
                    from: from.into(),
                    to: to.into(),
                }
            }
            ToolKind::Search => {
                let query = extract_string_field(fields.raw_input.as_ref(), "query")
                    .unwrap_or_default();
                Operation::Search { query }
            }
            ToolKind::Fetch => {
                let url =
                    extract_string_field(fields.raw_input.as_ref(), "url").unwrap_or_default();
                Operation::Fetch { url }
            }
            ToolKind::Think => Operation::Think,
            ToolKind::SwitchMode => {
                let mode = extract_string_field(fields.raw_input.as_ref(), "mode")
                    .unwrap_or_default();
                Operation::SwitchMode { mode }
            }
            ToolKind::Other => {
                let name = fields.title.clone().unwrap_or_else(|| "unknown".to_string());
                Operation::Other {
                    name,
                    description: None,
                }
            }
        }
    }
}

impl Ruleset {
    /// Evaluates an ACP permission request against this ruleset.
    ///
    /// This is a convenience method that extracts the operation from the request
    /// and evaluates it.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use toolcap::{Ruleset, Rule, Matcher, Outcome};
    /// use sacp::schema::RequestPermissionRequest;
    ///
    /// let ruleset = Ruleset::new(vec![
    ///     Rule::new(Matcher::command("git"), Outcome::Allow),
    /// ]);
    ///
    /// let outcome = ruleset.evaluate_request(&request);
    /// match outcome {
    ///     Outcome::Allow => { /* proceed */ }
    ///     Outcome::Deny => { /* block */ }
    ///     Outcome::Unknown => { /* ask user */ }
    /// }
    /// ```
    pub fn evaluate_request(&self, req: &RequestPermissionRequest) -> Outcome {
        let operation = Operation::from_request(req);
        self.evaluate(&operation)
    }
}

/// Extracts a command string from the raw input JSON.
///
/// Looks for common field names used by agents: "command", "cmd", or falls back
/// to stringifying the entire input.
fn extract_command_from_input(input: Option<&serde_json::Value>) -> String {
    let Some(input) = input else {
        return String::new();
    };

    // Try common field names for commands
    for field in ["command", "cmd", "script"] {
        if let Some(cmd) = extract_string_field(Some(input), field) {
            return cmd;
        }
    }

    // If input is a string, use it directly
    if let Some(s) = input.as_str() {
        return String::from(s);
    }

    // Fall back to empty string
    String::new()
}

/// Extracts a path from the raw input JSON.
fn extract_path_from_input(input: Option<&serde_json::Value>) -> String {
    let Some(input) = input else {
        return String::new();
    };

    // Try common field names for paths
    for field in ["path", "file", "file_path", "filename"] {
        if let Some(path) = extract_string_field(Some(input), field) {
            return path;
        }
    }

    // If input is a string, use it directly
    if let Some(s) = input.as_str() {
        return String::from(s);
    }

    String::new()
}

/// Extracts move operation paths from the raw input JSON.
fn extract_move_paths_from_input(input: Option<&serde_json::Value>) -> (String, String) {
    let Some(input) = input else {
        return (String::new(), String::new());
    };

    let from = extract_string_field(Some(input), "from")
        .or_else(|| extract_string_field(Some(input), "source"))
        .or_else(|| extract_string_field(Some(input), "src"))
        .unwrap_or_default();

    let to = extract_string_field(Some(input), "to")
        .or_else(|| extract_string_field(Some(input), "destination"))
        .or_else(|| extract_string_field(Some(input), "dest"))
        .unwrap_or_default();

    (from, to)
}

/// Extracts a string field from a JSON object.
fn extract_string_field(input: Option<&serde_json::Value>, field: &str) -> Option<String> {
    input?
        .as_object()?
        .get(field)?
        .as_str()
        .map(|s: &str| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::Matcher;
    use crate::rule::Rule;
    use sacp::schema::{ToolCallId, ToolCallUpdate, ToolCallUpdateFields};
    use serde_json::json;

    fn make_request(kind: ToolKind, raw_input: Option<serde_json::Value>) -> RequestPermissionRequest {
        RequestPermissionRequest {
            session_id: "test-session".to_string().into(),
            tool_call: ToolCallUpdate {
                id: ToolCallId::from("test-call"),
                fields: ToolCallUpdateFields {
                    kind: Some(kind),
                    raw_input,
                    ..Default::default()
                },
                meta: None,
            },
            options: vec![],
            meta: None,
        }
    }

    #[test]
    fn test_execute_operation_from_request() {
        let req = make_request(ToolKind::Execute, Some(json!({"command": "git status"})));
        let op = Operation::from_request(&req);

        match op {
            Operation::Execute(exec) => {
                assert_eq!(exec.raw(), "git status");
            }
            _ => panic!("Expected Execute operation"),
        }
    }

    #[test]
    fn test_read_operation_from_request() {
        let req = make_request(ToolKind::Read, Some(json!({"path": "/etc/passwd"})));
        let op = Operation::from_request(&req);

        match op {
            Operation::Read { path } => {
                assert_eq!(path.to_str().unwrap(), "/etc/passwd");
            }
            _ => panic!("Expected Read operation"),
        }
    }

    #[test]
    fn test_evaluate_request() {
        let ruleset = Ruleset::new(vec![
            Rule::new(
                Matcher::command("git").with_subcommand("status"),
                Outcome::Allow,
            ),
            Rule::new(Matcher::command("sudo"), Outcome::Deny),
        ]);

        // Allowed command
        let req = make_request(ToolKind::Execute, Some(json!({"command": "git status"})));
        assert_eq!(ruleset.evaluate_request(&req), Outcome::Allow);

        // Denied command
        let req = make_request(ToolKind::Execute, Some(json!({"command": "sudo rm -rf /"})));
        assert_eq!(ruleset.evaluate_request(&req), Outcome::Deny);

        // Unknown command
        let req = make_request(ToolKind::Execute, Some(json!({"command": "npm install"})));
        assert_eq!(ruleset.evaluate_request(&req), Outcome::Unknown);
    }

    #[test]
    fn test_think_always_matches_any() {
        let req = make_request(ToolKind::Think, None);
        let op = Operation::from_request(&req);
        assert_eq!(op, Operation::Think);
    }
}
