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
//!
//! # Using the ToolcapProxy
//!
//! The [`ToolcapProxy`] struct wraps a ruleset and provides methods for
//! handling permission requests in a proxy context:
//!
//! ```ignore
//! use toolcap::{Ruleset, Rule, Matcher, Outcome};
//! use toolcap::acp::ToolcapProxy;
//!
//! let ruleset = Ruleset::new(vec![
//!     Rule::new(Matcher::command("git").with_subcommand("status"), Outcome::Allow),
//!     Rule::new(Matcher::command("sudo"), Outcome::Deny),
//! ]);
//!
//! let proxy = ToolcapProxy::new(ruleset);
//!
//! // When handling a permission request:
//! match proxy.handle_permission_request(&request) {
//!     PermissionDecision::Respond(response) => {
//!         // Send this response back to the agent
//!     }
//!     PermissionDecision::Forward => {
//!         // Forward to the upstream client for user decision
//!     }
//! }
//! ```

use sacp::schema::{
    PermissionOption, PermissionOptionId, PermissionOptionKind, RequestPermissionOutcome,
    RequestPermissionRequest, RequestPermissionResponse, ToolKind,
};

use crate::operation::{ExecuteOperation, Operation};
use crate::outcome::Outcome;
use crate::ruleset::Ruleset;

impl Operation {
    /// Constructs an `Operation` from an ACP `RequestPermissionRequest`.
    ///
    /// This extracts the tool kind and relevant data from the request to create
    /// the appropriate `Operation` variant.
    ///
    /// When `kind` is not specified in the request, this function attempts to
    /// infer it from the `raw_input` fields (e.g., presence of "command" suggests
    /// an Execute operation).
    pub fn from_request(req: &RequestPermissionRequest) -> Self {
        let fields = &req.tool_call.fields;

        // Try to get explicit kind, or infer from raw_input
        let kind = fields
            .kind
            .or_else(|| infer_kind_from_input(fields.raw_input.as_ref()))
            .unwrap_or_default();

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

/// Infers the tool kind from the raw_input fields.
///
/// This is used when the agent doesn't explicitly specify a `kind` in the
/// permission request. We look for characteristic fields to determine the
/// operation type.
fn infer_kind_from_input(input: Option<&serde_json::Value>) -> Option<ToolKind> {
    let obj = input?.as_object()?;

    // Check for Execute indicators (command, cmd, script)
    if obj.contains_key("command") || obj.contains_key("cmd") || obj.contains_key("script") {
        return Some(ToolKind::Execute);
    }

    // Check for file operation indicators
    if obj.contains_key("file_path") || obj.contains_key("path") || obj.contains_key("file") {
        // Distinguish between read/edit based on other fields
        if obj.contains_key("content") || obj.contains_key("new_content") {
            return Some(ToolKind::Edit);
        }
        return Some(ToolKind::Read);
    }

    // Check for Move indicators
    if obj.contains_key("from") && obj.contains_key("to") {
        return Some(ToolKind::Move);
    }

    // Check for Search indicators
    if obj.contains_key("query") && !obj.contains_key("url") {
        return Some(ToolKind::Search);
    }

    // Check for Fetch indicators
    if obj.contains_key("url") {
        return Some(ToolKind::Fetch);
    }

    None
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

// =============================================================================
// Outcome to PermissionOptionKind conversion
// =============================================================================

impl Outcome {
    /// Returns the corresponding `PermissionOptionKind` for this outcome.
    ///
    /// - `Allow` maps to `AllowOnce`
    /// - `Deny` maps to `RejectOnce`
    /// - `Unknown` returns `None` (should be forwarded to user)
    ///
    /// Use `to_option_kind_remembered` for "always" variants.
    pub fn to_option_kind(&self) -> Option<PermissionOptionKind> {
        match self {
            Outcome::Allow => Some(PermissionOptionKind::AllowOnce),
            Outcome::Deny => Some(PermissionOptionKind::RejectOnce),
            Outcome::Unknown => None,
        }
    }

    /// Returns the "remembered" `PermissionOptionKind` for this outcome.
    ///
    /// - `Allow` maps to `AllowAlways`
    /// - `Deny` maps to `RejectAlways`
    /// - `Unknown` returns `None` (should be forwarded to user)
    pub fn to_option_kind_remembered(&self) -> Option<PermissionOptionKind> {
        match self {
            Outcome::Allow => Some(PermissionOptionKind::AllowAlways),
            Outcome::Deny => Some(PermissionOptionKind::RejectAlways),
            Outcome::Unknown => None,
        }
    }
}

// =============================================================================
// ToolcapProxy - Permission request handling for proxies
// =============================================================================

/// The decision made by the proxy for a permission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionDecision {
    /// The proxy has decided and can respond directly to the agent.
    Respond(RequestPermissionResponse),

    /// The proxy cannot decide; forward to the upstream client.
    Forward,
}

/// A proxy component that evaluates permission requests against a ruleset.
///
/// `ToolcapProxy` wraps a [`Ruleset`] and provides methods for handling
/// ACP permission requests in a proxy context. When a permission request
/// is received:
///
/// - If the ruleset produces `Allow` or `Deny`, the proxy creates a response
///   selecting the appropriate option from the request's available options.
/// - If the ruleset produces `Unknown`, the proxy signals that the request
///   should be forwarded to the upstream client for user decision.
///
/// # Example
///
/// ```ignore
/// use toolcap::{Ruleset, Rule, Matcher, Outcome};
/// use toolcap::acp::{ToolcapProxy, PermissionDecision};
///
/// let ruleset = Ruleset::new(vec![
///     Rule::new(Matcher::command("git").with_subcommand("status"), Outcome::Allow),
///     Rule::new(Matcher::command("sudo"), Outcome::Deny),
/// ]);
///
/// let proxy = ToolcapProxy::new(ruleset);
///
/// // In your message handler:
/// match proxy.handle_permission_request(&request) {
///     PermissionDecision::Respond(response) => {
///         // Send response back to agent
///     }
///     PermissionDecision::Forward => {
///         // Forward to upstream client
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ToolcapProxy {
    ruleset: Ruleset,
    /// Whether to use "Always" variants when responding.
    remember_decisions: bool,
}

impl ToolcapProxy {
    /// Creates a new proxy with the given ruleset.
    ///
    /// By default, decisions are not remembered (uses `AllowOnce`/`RejectOnce`).
    pub fn new(ruleset: Ruleset) -> Self {
        Self {
            ruleset,
            remember_decisions: false,
        }
    }

    /// Sets whether the proxy should use "Always" variants for responses.
    ///
    /// When `true`, the proxy will select `AllowAlways` or `RejectAlways`
    /// options when available.
    pub fn with_remembered_decisions(mut self, remember: bool) -> Self {
        self.remember_decisions = remember;
        self
    }

    /// Returns a reference to the underlying ruleset.
    pub fn ruleset(&self) -> &Ruleset {
        &self.ruleset
    }

    /// Handles a permission request, returning either a response or a forward decision.
    ///
    /// This evaluates the request against the ruleset and:
    /// - For `Allow`/`Deny`: finds the matching option from the request and
    ///   creates a response selecting that option.
    /// - For `Unknown`: returns `PermissionDecision::Forward`.
    ///
    /// If the expected option kind is not available in the request's options,
    /// falls back to `Forward`.
    pub fn handle_permission_request(
        &self,
        request: &RequestPermissionRequest,
    ) -> PermissionDecision {
        let outcome = self.ruleset.evaluate_request(request);

        // Determine which option kind we're looking for
        let target_kind = if self.remember_decisions {
            outcome.to_option_kind_remembered()
        } else {
            outcome.to_option_kind()
        };

        // If outcome is Unknown, we should forward
        let Some(target_kind) = target_kind else {
            return PermissionDecision::Forward;
        };

        // Find a matching option in the request
        if let Some(option) = find_option_by_kind(&request.options, target_kind) {
            PermissionDecision::Respond(RequestPermissionResponse {
                outcome: RequestPermissionOutcome::Selected {
                    option_id: option.id.clone(),
                },
                meta: None,
            })
        } else if self.remember_decisions {
            // Fall back to non-remembered variant if remembered not available
            if let Some(fallback_kind) = outcome.to_option_kind() {
                if let Some(option) = find_option_by_kind(&request.options, fallback_kind) {
                    return PermissionDecision::Respond(RequestPermissionResponse {
                        outcome: RequestPermissionOutcome::Selected {
                            option_id: option.id.clone(),
                        },
                        meta: None,
                    });
                }
            }
            // No suitable option found, must forward
            PermissionDecision::Forward
        } else {
            // No suitable option found, must forward
            PermissionDecision::Forward
        }
    }

    /// Evaluates a request and returns the outcome without creating a response.
    ///
    /// This is useful when you need the outcome for logging or other purposes
    /// before deciding how to handle the request.
    pub fn evaluate(&self, request: &RequestPermissionRequest) -> Outcome {
        self.ruleset.evaluate_request(request)
    }
}

/// Finds an option with the specified kind in the options list.
fn find_option_by_kind(
    options: &[PermissionOption],
    kind: PermissionOptionKind,
) -> Option<&PermissionOption> {
    options.iter().find(|opt| opt.kind == kind)
}

/// Creates a permission option with the given ID and kind.
///
/// This is a helper for creating options in tests.
pub fn make_permission_option(id: impl Into<String>, kind: PermissionOptionKind) -> PermissionOption {
    PermissionOption {
        id: PermissionOptionId::from(id.into()),
        kind,
        name: String::new(),
        meta: None,
    }
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

    mod outcome_conversion {
        use super::*;

        #[test]
        fn test_allow_to_option_kind() {
            assert_eq!(
                Outcome::Allow.to_option_kind(),
                Some(PermissionOptionKind::AllowOnce)
            );
            assert_eq!(
                Outcome::Allow.to_option_kind_remembered(),
                Some(PermissionOptionKind::AllowAlways)
            );
        }

        #[test]
        fn test_deny_to_option_kind() {
            assert_eq!(
                Outcome::Deny.to_option_kind(),
                Some(PermissionOptionKind::RejectOnce)
            );
            assert_eq!(
                Outcome::Deny.to_option_kind_remembered(),
                Some(PermissionOptionKind::RejectAlways)
            );
        }

        #[test]
        fn test_unknown_to_option_kind() {
            assert_eq!(Outcome::Unknown.to_option_kind(), None);
            assert_eq!(Outcome::Unknown.to_option_kind_remembered(), None);
        }
    }

    mod toolcap_proxy {
        use super::*;

        fn make_request_with_options(
            kind: ToolKind,
            raw_input: Option<serde_json::Value>,
            options: Vec<PermissionOption>,
        ) -> RequestPermissionRequest {
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
                options,
                meta: None,
            }
        }

        fn standard_options() -> Vec<PermissionOption> {
            vec![
                make_permission_option("allow-once", PermissionOptionKind::AllowOnce),
                make_permission_option("allow-always", PermissionOptionKind::AllowAlways),
                make_permission_option("reject-once", PermissionOptionKind::RejectOnce),
                make_permission_option("reject-always", PermissionOptionKind::RejectAlways),
            ]
        }

        #[test]
        fn test_proxy_allows_matching_command() {
            let ruleset = Ruleset::new(vec![Rule::new(
                Matcher::command("git").with_subcommand("status"),
                Outcome::Allow,
            )]);
            let proxy = ToolcapProxy::new(ruleset);

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "git status"})),
                standard_options(),
            );

            match proxy.handle_permission_request(&req) {
                PermissionDecision::Respond(response) => {
                    assert_eq!(
                        response.outcome,
                        RequestPermissionOutcome::Selected {
                            option_id: PermissionOptionId::from("allow-once".to_string())
                        }
                    );
                }
                PermissionDecision::Forward => panic!("Expected Respond, got Forward"),
            }
        }

        #[test]
        fn test_proxy_denies_matching_command() {
            let ruleset = Ruleset::new(vec![Rule::new(Matcher::command("sudo"), Outcome::Deny)]);
            let proxy = ToolcapProxy::new(ruleset);

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "sudo rm -rf /"})),
                standard_options(),
            );

            match proxy.handle_permission_request(&req) {
                PermissionDecision::Respond(response) => {
                    assert_eq!(
                        response.outcome,
                        RequestPermissionOutcome::Selected {
                            option_id: PermissionOptionId::from("reject-once".to_string())
                        }
                    );
                }
                PermissionDecision::Forward => panic!("Expected Respond, got Forward"),
            }
        }

        #[test]
        fn test_proxy_forwards_unknown_command() {
            let ruleset = Ruleset::new(vec![Rule::new(
                Matcher::command("git").with_subcommand("status"),
                Outcome::Allow,
            )]);
            let proxy = ToolcapProxy::new(ruleset);

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "npm install"})),
                standard_options(),
            );

            assert_eq!(
                proxy.handle_permission_request(&req),
                PermissionDecision::Forward
            );
        }

        #[test]
        fn test_proxy_with_remembered_decisions() {
            let ruleset = Ruleset::new(vec![Rule::new(
                Matcher::command("git").with_subcommand("status"),
                Outcome::Allow,
            )]);
            let proxy = ToolcapProxy::new(ruleset).with_remembered_decisions(true);

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "git status"})),
                standard_options(),
            );

            match proxy.handle_permission_request(&req) {
                PermissionDecision::Respond(response) => {
                    assert_eq!(
                        response.outcome,
                        RequestPermissionOutcome::Selected {
                            option_id: PermissionOptionId::from("allow-always".to_string())
                        }
                    );
                }
                PermissionDecision::Forward => panic!("Expected Respond, got Forward"),
            }
        }

        #[test]
        fn test_proxy_falls_back_to_once_if_always_not_available() {
            let ruleset = Ruleset::new(vec![Rule::new(
                Matcher::command("git").with_subcommand("status"),
                Outcome::Allow,
            )]);
            let proxy = ToolcapProxy::new(ruleset).with_remembered_decisions(true);

            // Only provide "once" options
            let options = vec![
                make_permission_option("allow-once", PermissionOptionKind::AllowOnce),
                make_permission_option("reject-once", PermissionOptionKind::RejectOnce),
            ];

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "git status"})),
                options,
            );

            match proxy.handle_permission_request(&req) {
                PermissionDecision::Respond(response) => {
                    assert_eq!(
                        response.outcome,
                        RequestPermissionOutcome::Selected {
                            option_id: PermissionOptionId::from("allow-once".to_string())
                        }
                    );
                }
                PermissionDecision::Forward => panic!("Expected Respond, got Forward"),
            }
        }

        #[test]
        fn test_proxy_forwards_if_no_suitable_option() {
            let ruleset = Ruleset::new(vec![Rule::new(
                Matcher::command("git").with_subcommand("status"),
                Outcome::Allow,
            )]);
            let proxy = ToolcapProxy::new(ruleset);

            // Only provide reject options (no allow options)
            let options = vec![
                make_permission_option("reject-once", PermissionOptionKind::RejectOnce),
                make_permission_option("reject-always", PermissionOptionKind::RejectAlways),
            ];

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "git status"})),
                options,
            );

            // Should forward because there's no AllowOnce option to select
            assert_eq!(
                proxy.handle_permission_request(&req),
                PermissionDecision::Forward
            );
        }

        #[test]
        fn test_proxy_evaluate_returns_outcome() {
            let ruleset = Ruleset::new(vec![
                Rule::new(
                    Matcher::command("git").with_subcommand("status"),
                    Outcome::Allow,
                ),
                Rule::new(Matcher::command("sudo"), Outcome::Deny),
            ]);
            let proxy = ToolcapProxy::new(ruleset);

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "git status"})),
                vec![],
            );
            assert_eq!(proxy.evaluate(&req), Outcome::Allow);

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "sudo rm -rf /"})),
                vec![],
            );
            assert_eq!(proxy.evaluate(&req), Outcome::Deny);

            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "npm install"})),
                vec![],
            );
            assert_eq!(proxy.evaluate(&req), Outcome::Unknown);
        }

        #[test]
        fn test_proxy_ruleset_accessor() {
            let ruleset = Ruleset::new(vec![Rule::new(
                Matcher::command("git"),
                Outcome::Allow,
            )]);
            let proxy = ToolcapProxy::new(ruleset.clone());

            // Verify the ruleset is accessible
            let req = make_request_with_options(
                ToolKind::Execute,
                Some(json!({"command": "git status"})),
                vec![],
            );
            assert_eq!(proxy.ruleset().evaluate_request(&req), Outcome::Allow);
        }
    }
}
