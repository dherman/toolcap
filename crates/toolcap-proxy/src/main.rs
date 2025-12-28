//! Toolcap ACP Proxy
//!
//! An ACP proxy that evaluates permission requests against a Toolcap ruleset.
//! Insert this proxy into an ACP conductor chain to automatically allow/deny
//! tool calls based on your configured rules.
//!
//! # Usage
//!
//! ```bash
//! sacp-conductor toolcap-proxy -- npx -y '@zed-industries/claude-code-acp'
//! ```

use clap::Parser;
use sacp::role::{Agent, Client, ProxyToConductor};
use sacp::schema::RequestPermissionRequest;
use sacp::util::MatchMessageFrom;
use sacp::{ByteStreams, Handled, JrConnectionCx, JrMessageHandler, JrRequestCx, MessageCx};
use std::sync::Arc;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use toolcap::acp::{PermissionDecision, ToolcapProxy};
use toolcap::{Matcher, Outcome, Rule, Ruleset};
use tracing::{debug, info};

#[derive(Parser, Debug)]
#[command(name = "toolcap-proxy")]
#[command(about = "ACP proxy for Toolcap permission evaluation")]
struct Args {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Use "Always" variants for permission responses (remember decisions)
    #[arg(long)]
    remember: bool,
}

/// Our custom message handler for the Toolcap proxy.
/// This intercepts RequestPermissionRequest messages and evaluates them against the ruleset.
/// All other messages are passed through to ProxyToConductor's default handler.
struct ToolcapProxyHandler {
    proxy: Arc<ToolcapProxy>,
}

impl JrMessageHandler for ToolcapProxyHandler {
    type Role = ProxyToConductor;

    fn describe_chain(&self) -> impl std::fmt::Debug {
        "ToolcapProxyHandler"
    }

    async fn handle_message(
        &mut self,
        message: MessageCx,
        cx: JrConnectionCx<Self::Role>,
    ) -> Result<Handled<MessageCx>, sacp::Error> {
        let proxy = self.proxy.clone();

        // Use MatchMessageFrom to handle specific request types
        MatchMessageFrom::new(message, &cx)
            // Handle permission requests from the client
            .if_request_from(
                Client,
                async move |req: RequestPermissionRequest, request_cx: JrRequestCx<_>| {
                    let command_info = extract_command_info(&req);
                    debug!("Evaluating permission request: {}", command_info);

                    match proxy.handle_permission_request(&req) {
                        PermissionDecision::Respond(response) => {
                            info!(
                                "Auto-responding to '{}': {:?}",
                                command_info, response.outcome
                            );
                            request_cx.respond(response)
                        }
                        PermissionDecision::Forward => {
                            info!("Forwarding request to agent: {}", command_info);
                            // Forward to agent using forward_to_request_cx (non-blocking)
                            cx.send_request_to(Agent, req)
                                .forward_to_request_cx(request_cx)
                        }
                    }
                },
            )
            .await
            .done()
    }
}

#[tokio::main]
async fn main() -> Result<(), sacp::Error> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose {
        "toolcap_proxy=trace,sacp=debug"
    } else {
        "toolcap_proxy=info,sacp=warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    info!("Starting toolcap-proxy");

    // Create a sample ruleset for demonstration
    let ruleset = create_default_ruleset();
    let proxy = Arc::new(ToolcapProxy::new(ruleset).with_remembered_decisions(args.remember));

    info!("Loaded ruleset");

    // Create our custom handler
    let handler = ToolcapProxyHandler { proxy };

    // Use ProxyToConductor role with our custom handler.
    // ProxyToConductor's default_message_handler will:
    // - Handle _proxy/initialize by forwarding to agent
    // - Handle SuccessorMessage from agent by forwarding to client
    // - Forward all other client messages to agent
    // - Forward all other agent notifications to client
    //
    // Our custom handler intercepts RequestPermissionRequest before the default handler.
    ProxyToConductor::builder()
        .name("toolcap-proxy")
        .with_handler(handler)
        .serve(ByteStreams::new(
            tokio::io::stdout().compat_write(),
            tokio::io::stdin().compat(),
        ))
        .await?;

    Ok(())
}

/// Extracts a human-readable command description from a permission request.
fn extract_command_info(request: &RequestPermissionRequest) -> String {
    let kind = request
        .tool_call
        .fields
        .kind
        .map(|k| format!("{:?}", k))
        .unwrap_or_else(|| "Unknown".to_string());

    let raw_input = request
        .tool_call
        .fields
        .raw_input
        .as_ref()
        .and_then(|v| {
            // Try to extract command from common field names
            v.get("command")
                .or_else(|| v.get("cmd"))
                .or_else(|| v.get("script"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "?".to_string());

    format!("{}:{}", kind, raw_input)
}

/// Creates a default ruleset for demonstration purposes.
fn create_default_ruleset() -> Ruleset {
    Ruleset::new(vec![
        // ===== ALLOW: Read-only git commands =====
        Rule::new(
            Matcher::command("git").with_subcommands([
                "status",
                "log",
                "diff",
                "show",
                "blame",
                "branch",
                "tag",
                "remote",
                "describe",
                "rev-parse",
                "ls-files",
                "ls-tree",
                "cat-file",
                "shortlog",
                "annotate",
            ]),
            Outcome::Allow,
        ),
        // ===== ALLOW: Safe cargo commands =====
        Rule::new(
            Matcher::command("cargo").with_subcommands([
                "build", "check", "test", "clippy", "fmt", "doc", "tree", "metadata",
            ]),
            Outcome::Allow,
        ),
        // ===== ALLOW: Safe npm commands =====
        Rule::new(
            Matcher::command("npm")
                .with_subcommands(["list", "view", "search", "audit", "outdated", "ls"]),
            Outcome::Allow,
        ),
        // ===== ALLOW: Common read-only tools =====
        Rule::new(
            Matcher::or(vec![
                Matcher::command("ls"),
                Matcher::command("cat"),
                Matcher::command("head"),
                Matcher::command("tail"),
                Matcher::command("grep"),
                Matcher::command("rg"),
                Matcher::command("find"),
                Matcher::command("wc"),
                Matcher::command("pwd"),
                Matcher::command("which"),
                Matcher::command("echo"),
                Matcher::command("printf"),
            ]),
            Outcome::Allow,
        ),
        // ===== ALLOW: Go read-only commands =====
        Rule::new(
            Matcher::command("go").with_subcommands(["build", "test", "vet", "fmt", "mod"]),
            Outcome::Allow,
        ),
        // ===== ALLOW: Make =====
        Rule::new(Matcher::command("make"), Outcome::Allow),
        // ===== ALLOW: TypeScript/JavaScript =====
        Rule::new(
            Matcher::or(vec![
                Matcher::command("tsc"),
                Matcher::command("node"),
                Matcher::command("npx"),
            ]),
            Outcome::Allow,
        ),
        // ===== DENY: Destructive git commands =====
        Rule::new(
            Matcher::command("git").with_subcommands(["push", "reset", "rebase", "force-push"]),
            Outcome::Deny,
        ),
        // ===== DENY: Dangerous system commands =====
        Rule::new(
            Matcher::or(vec![
                Matcher::command("sudo"),
                Matcher::command("su"),
                Matcher::command("chmod"),
                Matcher::command("chown"),
                Matcher::command("rm").with_flag("-rf"),
                Matcher::command("rm").with_flag("-r"),
                Matcher::command("mkfs"),
                Matcher::command("dd"),
            ]),
            Outcome::Deny,
        ),
        // ===== DENY: Network commands that could exfiltrate data =====
        Rule::new(
            Matcher::or(vec![
                Matcher::command("curl"),
                Matcher::command("wget"),
                Matcher::command("nc"),
                Matcher::command("netcat"),
            ]),
            Outcome::Deny,
        ),
    ])
}
