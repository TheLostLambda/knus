//! A decoder for the implementation-agnostic KDL test suite
//! (<https://github.com/kdl-org/kdl-test>).
//!
//! The KDL test suite requires a *decoder*: a program that reads one KDL document
//! from stdin and, if it parses, writes the document as JSON to stdout and exits
//! successfully. A document that must be rejected is signalled by a non-zero
//! exit status. Whatever the decoder then writes to stderr is shown in the report.
//!
//! The suite wants a single executable to call, so `kdl_test_decoder.sh` next to
//! this file wraps the example up as one. It execs the built binary rather than
//! going through `cargo run`, which would otherwise re-resolve the workspace on
//! each of the several hundred test cases, so rebuild after editing this file:
//!
//! ```text
//! cargo build --release --example kdl_test_decoder
//! kdl-test run --decoder examples/kdl_test_decoder.sh
//! ```
//!
//! # The JSON shape
//!
//! A document is an array of nodes; every node is
//!
//! ```json
//! {"type": null, "name": "node", "args": [], "props": {}, "children": []}
//! ```
//!
//! where `type` is the node's type annotation, and each entry of `args` and
//! `props` is `{"type": null, "value": <value>}`. A value is tagged with its
//! kind: `{"type": "string", "value": "…"}`, `{"type": "boolean", "value":
//! "true"}`, `{"type": "number", "value": "…"}` or `{"type": "null"}`. Note:
//! the null value carries no `value` key at all and every value is
//! written as a *string*, so that numbers keep their full precision.
//!
//! Numbers are compared as text, in one canonical spelling: the exact value in
//! plain decimal notation (no radix prefix, no exponent) with at least one
//! digit on either side of the point and no trailing zeros in the fraction.
//! So `0x10` is `16.0`, `1.0e-10` is `0.0000000001`, and `#inf`, `#-inf` and
//! `#nan` are `inf`, `-inf` and `nan`.

use std::io::{Read as _, Write as _};
use std::process::ExitCode;

use knus::ast::{Document, Literal, Node, Radix, SpannedNode, Value};
use serde_json::{Map, Value as Json, json};

fn main() -> ExitCode {
    let mut source = Vec::new();
    if let Err(err) = std::io::stdin().read_to_end(&mut source) {
        eprintln!("error: cannot read stdin: {err}");
        return ExitCode::FAILURE;
    }
    // Non-UTF-8 input is not a KDL document, which is a rejection rather than
    // a crash.
    let Ok(source) = String::from_utf8(source) else {
        eprintln!("error: input is not valid UTF-8");
        return ExitCode::FAILURE;
    };

    let doc = match knus::parse_ast("<stdin>", &source) {
        Ok(doc) => doc,
        Err(err) => {
            // knus::Error implements miette::Diagnostic, so this renders the
            // offending source line with a caret under the bad span.
            let mut rendered = String::new();
            let handler = miette::GraphicalReportHandler::new();
            match handler.render_report(&mut rendered, &err) {
                Ok(()) => eprintln!("{}", rendered.trim_end()),
                Err(_) => eprintln!("{err:?}"),
            }
            return ExitCode::FAILURE;
        }
    };

    let json = match document(&doc) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut stdout = std::io::stdout().lock();
    match writeln!(stdout, "{json}").and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: cannot write stdout: {err}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The only thing that can go wrong once a document has parsed is a number too
/// extreme to spell out in plain decimal (see [`decimal`]).
type Error = String;

fn document(doc: &Document) -> Result<Json, Error> {
    nodes(&doc.nodes)
}

fn nodes(nodes: &[SpannedNode]) -> Result<Json, Error> {
    nodes.iter().map(|n| node(n)).collect()
}

fn node(node: &Node) -> Result<Json, Error> {
    // `properties` is a BTreeMap keyed on the (span-insensitive) name, so
    // duplicate keys have already collapsed to the last one written.
    let mut props = Map::new();
    for (key, val) in &node.properties {
        props.insert(key.to_string(), value(val)?);
    }
    Ok(json!({
        "type": node.type_name.as_ref().map(|t| t.as_str()),
        "name": &**node.node_name,
        "args": node.arguments.iter().map(value).collect::<Result<Vec<_>, _>>()?,
        "props": props,
        // A node without braces and a node with empty braces are the same
        // thing here.
        "children": match &node.children {
            Some(children) => nodes(children)?,
            None => json!([]),
        },
    }))
}

fn value(v: &Value) -> Result<Json, Error> {
    Ok(json!({
        "type": v.type_name.as_ref().map(|t| t.as_str()),
        "value": literal(&v.literal)?,
    }))
}

fn literal(lit: &Literal) -> Result<Json, Error> {
    Ok(match lit {
        // The null value is the one value written without a `value` key.
        Literal::Null => json!({"type": "null"}),
        Literal::Bool(b) => json!({"type": "boolean", "value": b.to_string()}),
        Literal::String(s) => json!({"type": "string", "value": s}),
        Literal::Nan => number("nan"),
        Literal::Inf => number("inf"),
        Literal::NegInf => number("-inf"),
        Literal::Int(int) => number(&integer(int.0, &int.1)),
        Literal::Decimal(dec) => number(&decimal(&dec.0)?),
    })
}

fn number(text: &str) -> Json {
    json!({"type": "number", "value": text})
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

/// Hex, octal and binary literals become decimal. We use schoolbook multiply-and-add
/// instead of little-endian decimal digits, so that literals wider than any Rust
/// integer still convert exactly.
fn integer(radix: Radix, digits: &str) -> String {
    let radix = match radix {
        Radix::Bin => 2,
        Radix::Oct => 8,
        Radix::Dec => 10,
        Radix::Hex => 16,
    };
    let (sign, digits) = split_sign(digits);

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
    // Integers still get a fractional part: `10` is `10.0`.
    out.push_str(".0");
    out
}

/// The largest exponent we are willing to write out. `1.23E+1000` is spelled
/// with a thousand-odd digits, which is fine; an exponent in the billions is
/// perfectly legal KDL but has no plain-decimal spelling that fits in memory.
const MAX_EXPONENT: i64 = 1_000_000;

/// Writes a decimal literal out in full: no exponent, at least one digit on
/// either side of the point, no trailing zeros in the fraction. We're comparing
/// digit text rather than an `f64` so that `1.23E-1000` (and every literal too
/// wide for 53 bits of mantissa) can be compared exactly.
fn decimal(text: &str) -> Result<String, Error> {
    let (sign, rest) = split_sign(text);
    let (mantissa, exponent) = match rest.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => {
            let exponent = exponent
                .parse::<i64>()
                .ok()
                .filter(|e| e.abs() <= MAX_EXPONENT)
                .ok_or_else(|| format!("exponent of `{text}` is too large to write out"))?;
            (mantissa, exponent)
        }
        None => (rest, 0),
    };
    let (int_digits, frac_digits) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = format!("{int_digits}{frac_digits}");

    // Where the point sits in `digits`, counted from the left. Outside the
    // digits it is padded with zeros on the corresponding side.
    let point = int_digits.len() as i64 + exponent;

    let zeros = |n: usize| "0".repeat(n);
    let (int_part, frac_part) = if point <= 0 {
        ("0".to_owned(), zeros(-point as usize) + &digits)
    } else if point as usize >= digits.len() {
        (
            digits.clone() + &zeros(point as usize - digits.len()),
            String::new(),
        )
    } else {
        let (int, frac) = digits.split_at(point as usize);
        (int.to_owned(), frac.to_owned())
    };

    // `007.500` is `7.5`, but `0.0` keeps a digit on each side.
    let int_part = int_part.trim_start_matches('0');
    let frac_part = frac_part.trim_end_matches('0');
    Ok(format!(
        "{sign}{}.{}",
        if int_part.is_empty() { "0" } else { int_part },
        if frac_part.is_empty() { "0" } else { frac_part },
    ))
}

fn split_sign(s: &str) -> (&str, &str) {
    match s.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", s.strip_prefix('+').unwrap_or(s)),
    }
}
