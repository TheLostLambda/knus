//! Runs the official KDL test suite (<https://github.com/kdl-org/kdl>) against
//! the parser.
//!
//! The suite isn't vendored here. Clone it wherever you like and set the
//! environment variable `$KNUS_KDL_TEST_CASES` to its `tests/test_cases` directory.
//!
//! ```text
//! git clone https://github.com/kdl-org/kdl /some/where
//! KNUS_KDL_TEST_CASES=/some/where/tests/test_cases cargo run --example conformance
//! ```
//!
//! This example accepts one optional argument, which is intepreted as a substring
//! to filter the test cases by name. For example, to run only the `escline` case:
//!
//! ```text
//! cargo run --example conformance -- escline
//! ```
//!
//! # How a case is checked
//!
//! In the KDL test suite, each `input/*.kdl` file is paired with an `expected_kdl/*.kdl` file
//! holding the same document re-printed in the canonical form, which the suite's `README.md`
//! spells out (comments stripped, numbers in decimal, properties sorted, …).
//! Inputs whose name ends in `_fail` must not parse.
//!
//! The `render()` function in this file reproduces that canonical form, so a case
//! passes when the rendered input equals the contents of the `expected_kdl` file.

use std::fmt::Write as _;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use knus::ast::{Document, Literal, Node, Radix, SpannedNode, Value};
use similar::{ChangeTag, TextDiff};

const USAGE: &str = "\
Set $KNUS_KDL_TEST_CASES to the tests/test_cases directory of a checkout of
https://github.com/kdl-org/kdl, for example:

    git clone https://github.com/kdl-org/kdl /some/where
    KNUS_KDL_TEST_CASES=/some/where/tests/test_cases cargo run --example conformance";

fn main() -> ExitCode {
    let Some(dir) = std::env::var_os("KNUS_KDL_TEST_CASES").map(PathBuf::from) else {
        eprintln!("error: $KNUS_KDL_TEST_CASES is not set\n\n{USAGE}");
        return ExitCode::FAILURE;
    };
    let input_dir = dir.join("input");
    let expected_dir = dir.join("expected_kdl");
    if !input_dir.is_dir() {
        eprintln!(
            "error: {} has no input/ directory\n\n{USAGE}",
            dir.display()
        );
        return ExitCode::FAILURE;
    }

    let filter = std::env::args().nth(1);
    let style = Style::detect();

    let mut inputs: Vec<PathBuf> = match std::fs::read_dir(&input_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "kdl"))
            .filter(|p| match &filter {
                Some(f) => p.to_string_lossy().contains(f.as_str()),
                None => true,
            })
            .collect(),
        Err(err) => {
            eprintln!("error: cannot read {}: {err}", input_dir.display());
            return ExitCode::FAILURE;
        }
    };
    inputs.sort();

    if inputs.is_empty() {
        eprintln!("error: no test cases matched");
        return ExitCode::FAILURE;
    }

    // Every case runs; a failure is reported and then we carry on to the next.
    let mut passed = 0usize;
    let mut failures: Vec<(String, Failure)> = Vec::new();
    for input in &inputs {
        let name = input.file_name().unwrap().to_string_lossy().into_owned();
        match run_case(input, &expected_dir.join(&name)) {
            Ok(()) => passed += 1,
            Err(failure) => {
                report(&name, &failure, &style);
                failures.push((name, failure));
            }
        }
    }

    summarize(passed, &failures, &style);
    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

enum Failure {
    /// A case that should have parsed, but didn't.
    ParseError(knus::Error),
    /// A `_fail` case that parsed anyway.
    UnexpectedSuccess(String),
    /// Parsed, but disagrees with the `expected_kdl` file.
    Mismatch { want: String, got: String },
    /// Something wrong with the suite itself rather than with knus.
    Suite(String),
}

impl Failure {
    fn label(&self) -> &'static str {
        match self {
            Failure::ParseError(_) => "parse error",
            Failure::UnexpectedSuccess(_) => "parsed, but should have failed",
            Failure::Mismatch { .. } => "mismatch",
            Failure::Suite(_) => "broken case",
        }
    }
}

fn run_case(input: &Path, expected: &Path) -> Result<(), Failure> {
    let name = input.file_name().unwrap().to_string_lossy().into_owned();
    let source = std::fs::read_to_string(input)
        .map_err(|e| Failure::Suite(format!("unreadable input: {e}")))?;
    let should_fail = name
        .strip_suffix(".kdl")
        .unwrap_or(&name)
        .ends_with("_fail");

    let parsed = knus::parse_ast(&name, &source);

    if should_fail {
        return match parsed {
            Ok(doc) => Err(Failure::UnexpectedSuccess(render(&doc))),
            Err(_) => Ok(()),
        };
    }

    let doc = parsed.map_err(Failure::ParseError)?;
    let want = std::fs::read_to_string(expected)
        .map_err(|e| Failure::Suite(format!("unreadable expected_kdl file: {e}")))?;

    let got = render(&doc);
    if got == want {
        Ok(())
    } else {
        Err(Failure::Mismatch { want, got })
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// ANSI colours, suppressed when not writing to a terminal or when `$NO_COLOR`
/// is set (see <https://no-color.org>).
struct Style {
    on: bool,
}

impl Style {
    fn detect() -> Style {
        Style {
            on: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }
    fn paint(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
    fn red(&self, text: &str) -> String {
        self.paint("31", text)
    }
    fn green(&self, text: &str) -> String {
        self.paint("32", text)
    }
    fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }
    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }
}

fn report(name: &str, failure: &Failure, style: &Style) {
    println!(
        "{} {} {}",
        style.red("FAIL"),
        style.bold(name),
        style.dim(failure.label())
    );
    match failure {
        Failure::ParseError(err) => {
            // knus::Error implements miette::Diagnostic, so this renders the
            // offending source line with a caret under the bad span.
            let mut rendered = String::new();
            let handler = miette::GraphicalReportHandler::new();
            match handler.render_report(&mut rendered, err) {
                Ok(()) => println!("{}", indent(rendered.trim_end())),
                Err(_) => println!("{}", indent(&format!("{err:?}"))),
            }
        }
        Failure::UnexpectedSuccess(doc) => {
            println!("{}", indent(doc.trim_end()));
        }
        Failure::Mismatch { want, got } => {
            println!(
                "{}",
                indent(&format!(
                    "{}\n{}\n{}",
                    style.dim("--- expected_kdl/"),
                    style.dim("+++ input/"),
                    diff(want, got, style)
                ))
            );
        }
        Failure::Suite(msg) => println!("{}", indent(msg.trim_end())),
    }
    println!();
}

fn summarize(passed: usize, failures: &[(String, Failure)], style: &Style) {
    let total = passed + failures.len();
    if failures.is_empty() {
        println!("{} all {total} cases passed", style.green("ok"));
        return;
    }

    let count = |want: &str| failures.iter().filter(|(_, f)| f.label() == want).count();
    let mut parts = Vec::new();
    for label in [
        "parse error",
        "parsed, but should have failed",
        "mismatch",
        "broken case",
    ] {
        let n = count(label);
        if n > 0 {
            parts.push(format!("{n} {label}"));
        }
    }

    println!(
        "{} {}/{total} cases failed ({})",
        style.red("FAILED"),
        failures.len(),
        parts.join(", ")
    );
    for (name, _) in failures {
        println!("  {name}");
    }
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Full-context line diff, `-` for the expected side and `+` for ours. The
/// documents are a handful of lines each, so there is no point eliding
/// unchanged context.
fn diff(want: &str, got: &str, style: &Style) -> String {
    let mut out = String::new();
    for change in TextDiff::from_lines(want, got).iter_all_changes() {
        let marker = match change.tag() {
            ChangeTag::Delete => '-',
            ChangeTag::Insert => '+',
            ChangeTag::Equal => ' ',
        };
        let text = format!("{marker} {}", change.value().trim_end_matches('\n'));
        let painted = match change.tag() {
            ChangeTag::Delete => style.red(&text),
            ChangeTag::Insert => style.green(&text),
            ChangeTag::Equal => style.dim(&text),
        };
        let _ = writeln!(out, "{painted}");
    }
    out.trim_end().to_owned()
}

// ---------------------------------------------------------------------------
// Canonical rendering
// ---------------------------------------------------------------------------

fn render(doc: &Document) -> String {
    let mut out = String::new();
    render_nodes(&doc.nodes, 0, &mut out);
    // "Extra empty lines removed except for a newline after the last node" —
    // a document with no nodes at all still gets that one newline.
    if out.is_empty() {
        out.push('\n');
    }
    out
}

fn render_nodes(nodes: &[SpannedNode], depth: usize, out: &mut String) {
    for node in nodes {
        render_node(node, depth, out);
    }
}

fn render_node(node: &Node, depth: usize, out: &mut String) {
    let indent = "    ".repeat(depth);
    out.push_str(&indent);
    if let Some(ty) = &node.type_name {
        write!(out, "({})", string(ty.as_str())).unwrap();
    }
    out.push_str(&string(&node.node_name));
    for arg in &node.arguments {
        write!(out, " {}", value(arg)).unwrap();
    }
    // `properties` is a BTreeMap keyed on the (span-insensitive) name, so it is
    // already sorted and already keeps only the last of duplicate keys.
    for (key, val) in &node.properties {
        write!(out, " {}={}", string(key), value(val)).unwrap();
    }
    match &node.children {
        Some(children) if !children.is_empty() => {
            out.push_str(" {\n");
            render_nodes(children, depth + 1, out);
            out.push_str(&indent);
            out.push_str("}\n");
        }
        // An empty `{}` carries no information the suite cares about.
        _ => out.push('\n'),
    }
}

fn value(v: &Value) -> String {
    let mut out = String::new();
    if let Some(ty) = &v.type_name {
        write!(out, "({})", string(ty.as_str())).unwrap();
    }
    out.push_str(&literal(&v.literal));
    out
}

fn literal(lit: &Literal) -> String {
    match lit {
        Literal::Null => "#null".into(),
        Literal::Bool(true) => "#true".into(),
        Literal::Bool(false) => "#false".into(),
        Literal::Nan => "#nan".into(),
        Literal::Inf => "#inf".into(),
        Literal::NegInf => "#-inf".into(),
        Literal::String(s) => string(s),
        Literal::Int(int) => canonical_int(int.0, &int.1),
        Literal::Decimal(dec) => canonical_decimal(&dec.0),
    }
}

/// "All identifiers must be unquoted unless they _must_ be quoted." Node
/// names, property keys, type names and string values are all just strings
/// once parsed, and the suite prints all four the same way.
fn string(s: &str) -> String {
    if is_bare_identifier(s) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                write!(out, "\\u{{{:x}}}", c as u32).unwrap()
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Mirrors `identifier-string` from the KDL grammar: a string may be written
/// bare when re-parsing it yields the same string back.
fn is_bare_identifier(s: &str) -> bool {
    // `-inf` is spelled `#-inf`, so the bare form is reserved rather than free.
    if matches!(s, "true" | "false" | "null" | "nan" | "inf" | "-inf") {
        return false;
    }
    if !s.chars().all(is_identifier_char) {
        return false;
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    // dotted-ident := sign? '.' ((identifier-char - digit) identifier-char*)?
    let dotted = |mut rest: std::str::Chars<'_>| match rest.next() {
        None => true,
        Some(c) => !c.is_ascii_digit(),
    };
    match first {
        // unambiguous-ident := (identifier-char - digit - sign - '.') identifier-char*
        c if !c.is_ascii_digit() && !matches!(c, '.' | '+' | '-') => true,
        // signed-ident := sign ((identifier-char - digit - '.') identifier-char*)?
        '+' | '-' => match chars.next() {
            None => true,
            Some('.') => dotted(chars),
            Some(c) => !c.is_ascii_digit(),
        },
        '.' => dotted(chars),
        _ => false,
    }
}

/// `identifier-char := unicode - unicode-space - newline - [\\/(){};\[\]"#=]
/// - disallowed-literal-code-points`
fn is_identifier_char(c: char) -> bool {
    !matches!(c,
        '\u{0}'..='\u{20}'
            | '\\' | '/' | '(' | ')' | '{' | '}' | ';' | '[' | ']' | '=' | '"' | '#'
            | '\u{7f}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{200e}'..='\u{200f}'
            | '\u{2028}' | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{2066}'..='\u{2069}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// "All numbers must be converted to their simplest decimal representation."
/// Hex, octal and binary become decimal; a leading `+` and any leading zeros
/// go away.
fn canonical_int(radix: Radix, digits: &str) -> String {
    let radix = match radix {
        Radix::Bin => 2,
        Radix::Oct => 8,
        Radix::Dec => 10,
        Radix::Hex => 16,
    };
    let (sign, digits) = split_sign(digits);

    // Schoolbook multiply-and-add over little-endian decimal digits, so that
    // literals wider than any Rust integer still convert exactly.
    let mut decimal: Vec<u8> = vec![0];
    for c in digits.chars() {
        let mut carry = c.to_digit(radix).expect("literal has a valid digit");
        for slot in decimal.iter_mut() {
            let v = u32::from(*slot) * radix + carry;
            *slot = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            decimal.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while decimal.len() > 1 && decimal.last() == Some(&0) {
        decimal.pop();
    }

    let mut out = sign.to_owned();
    out.extend(decimal.iter().rev().map(|d| char::from(b'0' + d)));
    out
}

/// Decimals keep the significand they were written with — the suite only
/// normalises the exponent, to an uppercase `E` with an explicit sign. Working
/// on the text keeps `1.23E+1000`, which no `f64` can hold, exact.
fn canonical_decimal(text: &str) -> String {
    let (sign, rest) = split_sign(text);
    match rest.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => {
            let (esign, edigits) = split_sign(exponent);
            let esign = if esign == "-" { "-" } else { "+" };
            format!("{sign}{mantissa}E{esign}{edigits}")
        }
        None => format!("{sign}{rest}"),
    }
}

fn split_sign(s: &str) -> (&str, &str) {
    match s.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", s.strip_prefix('+').unwrap_or(s)),
    }
}
