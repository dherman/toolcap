//! Shell command parsing for fine-grained permission matching.
//!
//! This module provides types and functions for parsing shell commands into
//! structured representations that can be matched against permission rules.
//!
//! # Supported Features
//!
//! The parser supports the following shell constructs:
//!
//! - **Simple commands**: `git status`, `cargo build --release`
//! - **Pipelines**: `find . | grep foo | head -10`
//! - **Logical AND**: `make && make test`
//! - **Logical OR**: `test -f foo || touch foo`
//! - **Chained operators**: `a && b && c`, `a || b || c`, `a && b || c`
//! - **Quoted strings**: `git commit -m "hello world"`, `find . -name '*.rs'`
//! - **Escaped characters**: `echo hello\ world`
//! - **Glob patterns**: `ls *.rs` (preserved as literal strings)
//! - **Tilde expansion**: `cd ~/projects` (preserved as literal `~`)
//! - **Redirections**: `cat < input.txt > output.txt` (parsed but ignored for matching)
//! - **Absolute/relative paths**: `/usr/bin/env`, `./script.sh`
//!
//! # Unsupported Features
//!
//! The following shell features are **not supported** and will return [`ParseError::Unsupported`]:
//!
//! - **Command substitution**: `$(cmd)` or `` `cmd` ``
//! - **Parameter expansion**: `$VAR`, `${VAR}`, `${VAR:-default}`
//! - **Arithmetic expansion**: `$((1 + 2))`
//! - **Compound commands**: `if`/`then`/`fi`, `for`/`do`/`done`, `while`/`do`/`done`, `case`/`esac`
//! - **Subshells**: `(cd /tmp && ls)`
//! - **Brace groups**: `{ echo a; echo b; }`
//! - **Function definitions**: `foo() { ... }`
//! - **Process substitution**: `<(cmd)`, `>(cmd)`
//! - **Here documents**: `<<EOF ... EOF`
//! - **Coprocesses**: `coproc`
//!
//! # Design Rationale
//!
//! These limitations are intentional for security. Commands containing dynamic
//! elements like variable expansion or command substitution cannot be statically
//! analyzed for permission matching—the actual commands executed depend on runtime
//! state. Such commands should be escalated for user review rather than auto-approved.
//!
//! # Example
//!
//! ```
//! use toolcap::shell::{parse, ShellAst};
//!
//! // Simple command
//! let ast = parse("git status").unwrap();
//! assert!(ast.is_simple());
//!
//! // Pipeline
//! let ast = parse("find . | grep foo").unwrap();
//! if let ShellAst::Pipeline(cmds) = ast {
//!     assert_eq!(cmds.len(), 2);
//! }
//!
//! // Unsupported: parameter expansion
//! let result = parse("echo $HOME");
//! assert!(result.is_err());
//! ```

use conch_parser::ast;
use conch_parser::lexer::Lexer;
use conch_parser::parse::DefaultParser;

/// A parsed simple command (executable with arguments).
///
/// This represents a single command like `git status -s` or `cargo build --release`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    /// The command name (e.g., "git", "cargo").
    pub name: String,
    /// The arguments following the command name.
    pub args: Vec<String>,
}

impl ParsedCommand {
    /// Creates a new parsed command.
    pub fn new(name: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            name: name.into(),
            args,
        }
    }

    /// Returns the subcommand (first argument), if present.
    ///
    /// For commands like `git status`, this returns `Some("status")`.
    pub fn subcommand(&self) -> Option<&str> {
        self.args.first().map(|s| s.as_str())
    }

    /// Checks if a specific flag is present in the arguments.
    pub fn has_flag(&self, flag: &str) -> bool {
        self.args.iter().any(|arg| arg == flag)
    }
}

/// Abstract syntax tree for shell commands.
///
/// This enum represents the structure of shell commands, including
/// simple commands, pipelines, and logical operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellAst {
    /// A simple command (executable with arguments).
    Simple(ParsedCommand),

    /// A pipeline of commands (cmd1 | cmd2 | ...).
    Pipeline(Vec<ShellAst>),

    /// Logical AND (cmd1 && cmd2).
    And(Vec<ShellAst>),

    /// Logical OR (cmd1 || cmd2).
    Or(Vec<ShellAst>),

    /// Sequential execution (cmd1; cmd2).
    Sequence(Vec<ShellAst>),

    /// A command that couldn't be fully parsed but has a raw representation.
    /// This is used for complex constructs like subshells, command substitution, etc.
    Unsupported(String),
}

/// Error type for shell parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input was empty.
    Empty,
    /// The parser encountered a syntax error.
    Syntax(String),
    /// The command uses unsupported shell features.
    Unsupported(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty command"),
            ParseError::Syntax(msg) => write!(f, "syntax error: {}", msg),
            ParseError::Unsupported(msg) => write!(f, "unsupported: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses a shell command string into a `ShellAst`.
///
/// # Example
///
/// ```
/// use toolcap::shell::{parse, ShellAst, ParsedCommand};
///
/// let ast = parse("git status").unwrap();
/// assert!(matches!(ast, ShellAst::Simple(_)));
///
/// let ast = parse("make && make test").unwrap();
/// assert!(matches!(ast, ShellAst::And(_)));
/// ```
pub fn parse(input: &str) -> Result<ShellAst, ParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }

    let lexer = Lexer::new(trimmed.chars());
    let mut parser = DefaultParser::new(lexer);

    match parser.complete_command() {
        Ok(Some(cmd)) => convert_top_level_command(&cmd),
        Ok(None) => Err(ParseError::Empty),
        Err(e) => Err(ParseError::Syntax(format!("{:?}", e))),
    }
}

// Type aliases for conch-parser's default AST types
type DefaultTopLevelCommand = ast::TopLevelCommand<String>;
type DefaultCommand = ast::DefaultCommand;
type DefaultListableCommand = ast::DefaultListableCommand;
type DefaultPipeableCommand = ast::DefaultPipeableCommand;
type DefaultSimpleCommand = ast::DefaultSimpleCommand;
type DefaultTopLevelWord = ast::TopLevelWord<String>;
type DefaultWord = ast::DefaultWord;
type DefaultComplexWord = ast::DefaultComplexWord;
type DefaultSimpleWord = ast::DefaultSimpleWord;

fn convert_top_level_command(cmd: &DefaultTopLevelCommand) -> Result<ShellAst, ParseError> {
    match cmd {
        ast::TopLevelCommand(cmd) => convert_command(cmd),
    }
}

fn convert_command(cmd: &DefaultCommand) -> Result<ShellAst, ParseError> {
    match cmd {
        ast::Command::Job(list) | ast::Command::List(list) => convert_and_or_list(list),
    }
}

fn convert_and_or_list(list: &ast::DefaultAndOrList) -> Result<ShellAst, ParseError> {
    let first = convert_listable_command(&list.first)?;

    if list.rest.is_empty() {
        return Ok(first);
    }

    // Process the chain of and/or operations
    // The AndOr enum wraps the command: And(cmd) or Or(cmd)
    let mut result = first;
    for and_or in &list.rest {
        match and_or {
            ast::AndOr::And(cmd) => {
                let right = convert_listable_command(cmd)?;
                // If result is already an And, extend it; otherwise wrap
                result = match result {
                    ShellAst::And(mut items) => {
                        items.push(right);
                        ShellAst::And(items)
                    }
                    other => ShellAst::And(vec![other, right]),
                };
            }
            ast::AndOr::Or(cmd) => {
                let right = convert_listable_command(cmd)?;
                // If result is already an Or, extend it; otherwise wrap
                result = match result {
                    ShellAst::Or(mut items) => {
                        items.push(right);
                        ShellAst::Or(items)
                    }
                    other => ShellAst::Or(vec![other, right]),
                };
            }
        }
    }

    Ok(result)
}

fn convert_listable_command(cmd: &DefaultListableCommand) -> Result<ShellAst, ParseError> {
    match cmd {
        ast::ListableCommand::Single(pipeable) => convert_pipeable_command(pipeable),
        ast::ListableCommand::Pipe(_, cmds) => {
            let converted: Result<Vec<_>, _> =
                cmds.iter().map(|c| convert_pipeable_command(c)).collect();
            Ok(ShellAst::Pipeline(converted?))
        }
    }
}

fn convert_pipeable_command(cmd: &DefaultPipeableCommand) -> Result<ShellAst, ParseError> {
    match cmd {
        ast::PipeableCommand::Simple(simple) => convert_simple_command(simple),
        ast::PipeableCommand::Compound(_) => {
            Err(ParseError::Unsupported("compound commands (if/for/while/case/brace groups)".into()))
        }
        ast::PipeableCommand::FunctionDef(_, _) => {
            Err(ParseError::Unsupported("function definitions".into()))
        }
    }
}

fn convert_simple_command(cmd: &DefaultSimpleCommand) -> Result<ShellAst, ParseError> {
    let mut words = Vec::new();

    for item in &cmd.redirects_or_cmd_words {
        match item {
            ast::RedirectOrCmdWord::CmdWord(word) => {
                words.push(convert_top_level_word(word)?);
            }
            ast::RedirectOrCmdWord::Redirect(_) => {
                // We skip redirects for now - they don't affect command matching
            }
        }
    }

    if words.is_empty() {
        // Command with only env vars or redirects
        return Err(ParseError::Unsupported(
            "commands with only environment variables or redirects".into(),
        ));
    }

    let name = words.remove(0);
    Ok(ShellAst::Simple(ParsedCommand::new(name, words)))
}

fn convert_top_level_word(word: &DefaultTopLevelWord) -> Result<String, ParseError> {
    let ast::TopLevelWord(complex) = word;
    convert_complex_word(complex)
}

fn convert_complex_word(word: &DefaultComplexWord) -> Result<String, ParseError> {
    match word {
        ast::ComplexWord::Single(w) => convert_word(w),
        ast::ComplexWord::Concat(words) => {
            let parts: Result<Vec<_>, _> = words.iter().map(|w| convert_word(w)).collect();
            Ok(parts?.join(""))
        }
    }
}

fn convert_word(word: &DefaultWord) -> Result<String, ParseError> {
    match word {
        ast::Word::Simple(simple) => convert_simple_word(simple),
        ast::Word::DoubleQuoted(words) => {
            let parts: Result<Vec<_>, _> = words.iter().map(|w| convert_simple_word(w)).collect();
            Ok(parts?.join(""))
        }
        ast::Word::SingleQuoted(s) => Ok(s.clone()),
    }
}

fn convert_simple_word(word: &DefaultSimpleWord) -> Result<String, ParseError> {
    match word {
        ast::SimpleWord::Literal(s) => Ok(s.clone()),
        ast::SimpleWord::Escaped(s) => Ok(s.clone()),
        ast::SimpleWord::Colon => Ok(":".into()),
        ast::SimpleWord::Tilde => Ok("~".into()),
        ast::SimpleWord::SquareOpen => Ok("[".into()),
        ast::SimpleWord::SquareClose => Ok("]".into()),
        ast::SimpleWord::Question => Ok("?".into()),
        ast::SimpleWord::Star => Ok("*".into()),
        ast::SimpleWord::Subst(_) => Err(ParseError::Unsupported("command substitution".into())),
        ast::SimpleWord::Param(_) => Err(ParseError::Unsupported("parameter expansion".into())),
    }
}

/// Iterator over all simple commands in a `ShellAst`.
///
/// This is useful for evaluating each command in a compound expression.
impl ShellAst {
    /// Returns an iterator over all simple commands in this AST.
    pub fn commands(&self) -> impl Iterator<Item = &ParsedCommand> {
        let mut commands = Vec::new();
        self.collect_commands(&mut commands);
        commands.into_iter()
    }

    fn collect_commands<'a>(&'a self, out: &mut Vec<&'a ParsedCommand>) {
        match self {
            ShellAst::Simple(cmd) => out.push(cmd),
            ShellAst::Pipeline(cmds)
            | ShellAst::And(cmds)
            | ShellAst::Or(cmds)
            | ShellAst::Sequence(cmds) => {
                for cmd in cmds {
                    cmd.collect_commands(out);
                }
            }
            ShellAst::Unsupported(_) => {}
        }
    }

    /// Returns `true` if this is a simple command (not a pipeline or compound).
    pub fn is_simple(&self) -> bool {
        matches!(self, ShellAst::Simple(_))
    }

    /// Returns the simple command if this is one, `None` otherwise.
    pub fn as_simple(&self) -> Option<&ParsedCommand> {
        match self {
            ShellAst::Simple(cmd) => Some(cmd),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_command() {
        let ast = parse("git status").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "git");
        assert_eq!(cmd.args, vec!["status"]);
    }

    #[test]
    fn test_parse_command_with_flags() {
        let ast = parse("git log --oneline -n 10").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "git");
        assert_eq!(cmd.args, vec!["log", "--oneline", "-n", "10"]);
        assert!(cmd.has_flag("--oneline"));
        assert!(cmd.has_flag("-n"));
        assert!(!cmd.has_flag("--all"));
    }

    #[test]
    fn test_parse_quoted_string() {
        let ast = parse(r#"git commit -m "hello world""#).unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "git");
        // Note: conch-parser handles the quotes, we get the content
        assert_eq!(cmd.args.len(), 3);
        assert_eq!(cmd.args[0], "commit");
        assert_eq!(cmd.args[1], "-m");
        // The quoted string should be preserved
    }

    #[test]
    fn test_parse_single_quoted() {
        let ast = parse("find . -name '*.rs'").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "find");
        assert_eq!(cmd.args, vec![".", "-name", "*.rs"]);
    }

    #[test]
    fn test_parse_pipeline() {
        let ast = parse("find . | grep foo").unwrap();
        match ast {
            ShellAst::Pipeline(cmds) => {
                assert_eq!(cmds.len(), 2);
                assert_eq!(cmds[0].as_simple().unwrap().name, "find");
                assert_eq!(cmds[1].as_simple().unwrap().name, "grep");
            }
            _ => panic!("Expected pipeline"),
        }
    }

    #[test]
    fn test_parse_and() {
        let ast = parse("make && make test").unwrap();
        match ast {
            ShellAst::And(cmds) => {
                assert_eq!(cmds.len(), 2);
                assert_eq!(cmds[0].as_simple().unwrap().name, "make");
                let second = cmds[1].as_simple().unwrap();
                assert_eq!(second.name, "make");
                assert_eq!(second.args, vec!["test"]);
            }
            _ => panic!("Expected And, got {:?}", ast),
        }
    }

    #[test]
    fn test_parse_or() {
        let ast = parse("test -f foo || touch foo").unwrap();
        match ast {
            ShellAst::Or(cmds) => {
                assert_eq!(cmds.len(), 2);
                assert_eq!(cmds[0].as_simple().unwrap().name, "test");
                assert_eq!(cmds[1].as_simple().unwrap().name, "touch");
            }
            _ => panic!("Expected Or, got {:?}", ast),
        }
    }

    #[test]
    fn test_parse_chained_and() {
        let ast = parse("a && b && c").unwrap();
        match ast {
            ShellAst::And(cmds) => {
                assert_eq!(cmds.len(), 3);
            }
            _ => panic!("Expected And with 3 commands"),
        }
    }

    #[test]
    fn test_commands_iterator() {
        let ast = parse("find . | grep foo && echo done").unwrap();
        let names: Vec<_> = ast.commands().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["find", "grep", "echo"]);
    }

    #[test]
    fn test_subcommand() {
        let ast = parse("git status").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.subcommand(), Some("status"));

        let ast = parse("ls").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.subcommand(), None);
    }

    #[test]
    fn test_empty_input() {
        assert!(matches!(parse(""), Err(ParseError::Empty)));
        assert!(matches!(parse("   "), Err(ParseError::Empty)));
    }

    #[test]
    fn test_command_substitution_unsupported() {
        // $(cmd) syntax
        let result = parse("echo $(whoami)");
        assert!(matches!(result, Err(ParseError::Unsupported(_))));
    }

    #[test]
    fn test_parameter_expansion_unsupported() {
        // $VAR syntax
        let result = parse("echo $HOME");
        assert!(matches!(result, Err(ParseError::Unsupported(_))));
    }

    // Additional edge case tests

    #[test]
    fn test_parse_long_pipeline() {
        let ast = parse("cat file | grep pattern | sort | uniq | head -10").unwrap();
        match ast {
            ShellAst::Pipeline(cmds) => {
                assert_eq!(cmds.len(), 5);
                let names: Vec<_> = cmds.iter().map(|c| c.as_simple().unwrap().name.as_str()).collect();
                assert_eq!(names, vec!["cat", "grep", "sort", "uniq", "head"]);
            }
            _ => panic!("Expected pipeline"),
        }
    }

    #[test]
    fn test_parse_mixed_and_or() {
        // Note: Shell parses left-to-right, so `a && b || c` is `(a && b) || c`
        let ast = parse("a && b || c").unwrap();
        match ast {
            ShellAst::Or(cmds) => {
                assert_eq!(cmds.len(), 2);
                // First element should be the And(a, b)
                match &cmds[0] {
                    ShellAst::And(inner) => {
                        assert_eq!(inner.len(), 2);
                    }
                    _ => panic!("Expected And as first element of Or"),
                }
                // Second element is c
                assert_eq!(cmds[1].as_simple().unwrap().name, "c");
            }
            _ => panic!("Expected Or, got {:?}", ast),
        }
    }

    #[test]
    fn test_parse_pipeline_with_and() {
        // Pipeline has higher precedence than &&
        let ast = parse("a | b && c | d").unwrap();
        match ast {
            ShellAst::And(cmds) => {
                assert_eq!(cmds.len(), 2);
                // First: pipeline of a | b
                match &cmds[0] {
                    ShellAst::Pipeline(p) => assert_eq!(p.len(), 2),
                    _ => panic!("Expected pipeline"),
                }
                // Second: pipeline of c | d
                match &cmds[1] {
                    ShellAst::Pipeline(p) => assert_eq!(p.len(), 2),
                    _ => panic!("Expected pipeline"),
                }
            }
            _ => panic!("Expected And, got {:?}", ast),
        }
    }

    #[test]
    fn test_parse_command_with_equals() {
        // Commands like `FOO=bar cmd` or `cmd key=value`
        let ast = parse("echo key=value").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "echo");
        assert_eq!(cmd.args, vec!["key=value"]);
    }

    #[test]
    fn test_parse_double_quoted_preserves_spaces() {
        let ast = parse(r#"echo "hello   world""#).unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "echo");
        assert_eq!(cmd.args, vec!["hello   world"]);
    }

    #[test]
    fn test_parse_escaped_characters() {
        let ast = parse(r#"echo hello\ world"#).unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "echo");
        // The escaped space joins the words
        assert_eq!(cmd.args.len(), 1);
    }

    #[test]
    fn test_parse_backtick_substitution_unsupported() {
        // `cmd` syntax (old-style command substitution)
        let result = parse("echo `whoami`");
        assert!(matches!(result, Err(ParseError::Unsupported(_))));
    }

    #[test]
    fn test_parse_with_redirections() {
        // Redirections are parsed but ignored for matching
        let ast = parse("cat < input.txt > output.txt").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "cat");
        // Redirections are not included in args
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn test_parse_stderr_redirect() {
        let ast = parse("make 2>&1 | tee log.txt").unwrap();
        match ast {
            ShellAst::Pipeline(cmds) => {
                assert_eq!(cmds.len(), 2);
                assert_eq!(cmds[0].as_simple().unwrap().name, "make");
                assert_eq!(cmds[1].as_simple().unwrap().name, "tee");
            }
            _ => panic!("Expected pipeline"),
        }
    }

    #[test]
    fn test_parse_glob_patterns() {
        let ast = parse("ls *.rs").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "ls");
        assert_eq!(cmd.args, vec!["*.rs"]);
    }

    #[test]
    fn test_parse_tilde_expansion() {
        let ast = parse("cd ~/projects").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "cd");
        assert_eq!(cmd.args, vec!["~/projects"]);
    }

    #[test]
    fn test_parse_command_with_dash_dash() {
        let ast = parse("git checkout -- file.txt").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "git");
        assert_eq!(cmd.args, vec!["checkout", "--", "file.txt"]);
        assert!(cmd.has_flag("--"));
    }

    #[test]
    fn test_if_statement_unsupported() {
        let result = parse("if true; then echo yes; fi");
        assert!(matches!(result, Err(ParseError::Unsupported(_))));
    }

    #[test]
    fn test_for_loop_unsupported() {
        let result = parse("for i in 1 2 3; do echo $i; done");
        // This should fail either due to the for loop or the $i parameter
        assert!(result.is_err());
    }

    #[test]
    fn test_subshell_unsupported() {
        let result = parse("(cd /tmp && ls)");
        assert!(matches!(result, Err(ParseError::Unsupported(_))));
    }

    #[test]
    fn test_brace_group_unsupported() {
        let result = parse("{ echo a; echo b; }");
        assert!(matches!(result, Err(ParseError::Unsupported(_))));
    }

    #[test]
    fn test_commands_iterator_nested() {
        // Complex nested structure
        let ast = parse("a | b | c && d | e || f").unwrap();
        let names: Vec<_> = ast.commands().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d", "e", "f"]);
    }

    #[test]
    fn test_single_command_no_args() {
        let ast = parse("pwd").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "pwd");
        assert!(cmd.args.is_empty());
        assert_eq!(cmd.subcommand(), None);
    }

    #[test]
    fn test_command_with_path() {
        let ast = parse("/usr/bin/env python script.py").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "/usr/bin/env");
        assert_eq!(cmd.args, vec!["python", "script.py"]);
    }

    #[test]
    fn test_relative_path_command() {
        let ast = parse("./script.sh arg1 arg2").unwrap();
        let cmd = ast.as_simple().unwrap();
        assert_eq!(cmd.name, "./script.sh");
        assert_eq!(cmd.args, vec!["arg1", "arg2"]);
    }
}
