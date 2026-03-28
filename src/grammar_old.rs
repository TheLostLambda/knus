use std::collections::{BTreeMap, BTreeSet};

use chumsky::prelude::*;

use crate::ast::{Decimal, Integer, Literal, Node, Radix, TypeName, Value};
use crate::ast::{Document, SpannedName, SpannedNode};
use crate::errors::{ParseError, TokenFormat};
use crate::span::{Span, Spanned};

type Error = extra::Err<ParseError>;
type Input<'src> = &'src str;

pub(crate) fn document<'src>() -> impl Parser<'src, Input<'src>, Document, Error> {
    just('\u{FEFF}')
        .or_not()
        .ignore_then(nodes())
        .map(|nodes| Document { nodes })
}

fn nodes<'src>() -> impl Parser<'src, Input<'src>, Vec<SpannedNode>, Error> + Clone {
    use PropOrArg::*;
    recursive(|nodes| {
        let braced_nodes = just('{').ignore_then(nodes.then_ignore(just('}')).map_err_with_state(
            |e, span: SimpleSpan, _state| {
                if matches!(
                    &e,
                    ParseError::Unexpected {
                        found: TokenFormat::Eoi,
                        ..
                    }
                ) {
                    e.merge(ParseError::Unclosed {
                        label: "curly braces",
                        // we know it's `{` at the start of the span
                        opened_at: Span::from(span).before_start(1),
                        opened: '{'.into(),
                        expected_at: Span::from(span).at_end(),
                        expected: '}'.into(),
                        found: None.into(),
                    })
                } else {
                    e
                }
            },
        ));

        let node = spanned(r#type().then_ignore(unicode_space().repeated()))
            .or_not()
            .then(spanned(identifier()))
            .then(
                node_space()
                    .repeated()
                    .at_least(1)
                    .ignore_then(node_prop_or_arg())
                    .repeated()
                    .collect::<Vec<PropOrArg>>(),
            )
            .then(
                node_space()
                    .repeated()
                    .ignore_then(
                        begin_comment('-')
                            .then_ignore(linespace().repeated())
                            .or_not(),
                    )
                    .then(spanned(braced_nodes))
                    .or_not(),
            )
            .then_ignore(node_space().repeated().then(node_terminator().or_not()))
            .map(|(((type_name, node_name), line_items), opt_children)| {
                let mut node = Node {
                    type_name,
                    node_name,
                    properties: BTreeMap::new(),
                    arguments: Vec::new(),
                    children: match opt_children {
                        Some((Some(_comment), _)) => None,
                        Some((None, children)) => Some(children),
                        None => None,
                    },
                };
                for item in line_items {
                    match item {
                        Prop(name, value) => {
                            node.properties.insert(name, value);
                        }
                        Arg(value) => {
                            node.arguments.push(value);
                        }
                        Ignore => {}
                    }
                }
                node
            });

        begin_comment('-')
            .then_ignore(linespace().repeated())
            .or_not()
            .then(spanned(node))
            .separated_by(linespace().repeated())
            .allow_leading()
            .allow_trailing()
            .collect::<Vec<(Option<()>, Spanned<Node>)>>()
            .map(|vec| {
                vec.into_iter()
                    .filter_map(
                        |(comment, node)| {
                            if comment.is_none() { Some(node) } else { None }
                        },
                    )
                    .collect()
            })
    })
}

#[derive(Clone)]
enum PropOrArg {
    Prop(SpannedName, Value),
    Arg(Value),
    Ignore,
}

fn node_prop_or_arg<'src>() -> impl Parser<'src, Input<'src>, PropOrArg, Error> + Clone {
    begin_comment('-')
        .ignore_then(linespace().repeated())
        .ignore_then(node_prop_or_arg_inner())
        .to(PropOrArg::Ignore)
        .or(node_prop_or_arg_inner())
}

fn node_prop_or_arg_inner<'src>() -> impl Parser<'src, Input<'src>, PropOrArg, Error> + Clone {
    use PropOrArg::*;

    let equals_value = unicode_space()
        .repeated()
        .then(just('='))
        .then(unicode_space().repeated())
        .ignore_then(value());

    choice((
        spanned(literal())
            .then(equals_value.clone().or_not())
            .validate(|(name, value), _, emit| {
                let span = name.span;
                match (&name.value, &value) {
                    (Literal::String(s), Some(_)) => {
                        return Prop(
                            Spanned {
                                span,
                                value: s.clone(),
                            },
                            value.unwrap(),
                        );
                    }
                    (
                        Literal::Bool(_)
                        | Literal::Null
                        | Literal::Nan
                        | Literal::Inf
                        | Literal::NegInf,
                        Some(_),
                    ) => {
                        emit.emit(ParseError::Unexpected {
                            label: Some("unexpected keyword"),
                            span,
                            found: TokenFormat::Kind("keyword"),
                            expected: [
                                TokenFormat::Kind("identifier"),
                                TokenFormat::Kind("string"),
                            ]
                            .into_iter()
                            .collect(),
                        });
                    }
                    (Literal::Int(_) | Literal::Decimal(_), Some(_)) => {
                        emit.emit(ParseError::MessageWithHelp {
                            label: Some("unexpected number"),
                            span,
                            message: "numbers cannot be used as property names".into(),
                            help: "consider enclosing in double quotes \"..\"",
                        });
                    }
                    (_, None) => {
                        return Arg(Value {
                            type_name: None,
                            literal: name,
                        });
                    }
                }
                // Error recovery for invalid property names
                Prop(
                    Spanned {
                        span,
                        value: "".into(),
                    },
                    value.unwrap(),
                )
            }),
        spanned(bare_identifier())
            .then(equals_value.or_not())
            .validate(|(name, value), e, emit| {
                if let Some(value) = value {
                    Prop(name, value)
                } else {
                    emit.emit(ParseError::MessageWithHelp {
                        label: Some("unexpected identifier"),
                        span: e.span().into(),
                        message: "identifiers cannot be used as arguments".into(),
                        help: "consider enclosing in double quotes \"..\"",
                    });
                    // this is invalid, but it's just a fallback
                    Arg(Value {
                        type_name: None,
                        literal: name.map(Literal::String),
                    })
                }
            }),
        type_name_value().map(Arg),
    ))
}

fn node_space<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    ws().or(escline())
}

fn node_terminator<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    choice((newline(), single_line_comment(), just(';').ignored(), end()))
}

fn identifier<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    choice((
        // match -123 so `-` will not be treated as an ident by backtracking
        number().map(Err),
        bare_identifier().map(Ok),
        string().map(Ok),
    ))
    // when backtracking is not already possible,
    // throw error for numbers (mapped to `Result::Err`)
    .validate(|res, extras, emit| {
        res.unwrap_or_else(|_| {
            emit.emit(ParseError::Unexpected {
                label: Some("unexpected number"),
                span: extras.span().into(),
                found: TokenFormat::Kind("number"),
                expected: expected_kind("identifier"),
            });
            "".into()
        })
    })
}

fn bare_identifier<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    let sign = just('+').or(just('-'));
    choice((
        // unambiguous-ident
        id_sans_sign_dig_point()
            .then(identifier_char().repeated())
            .to_slice(),
        // signed-ident
        sign.then(
            id_sans_dig_point()
                .then(identifier_char().repeated())
                .or_not(),
        )
        .to_slice(),
        // dotted-ident
        sign.or_not()
            .then(just('.'))
            .then(id_sans_dig().then(identifier_char().repeated()).or_not())
            .to_slice(),
    ))
    .map(|v: &str| Box::<str>::from(v))
    .try_map(|s, span| match &s[..] {
        "true" | "false" | "null" | "nan" | "inf" | "-inf" => Err(ParseError::Message {
            label: Some("illegal identifier"),
            span: span.into(),
            message: format!("`{s}` is not allowed as a bare string"),
        }),
        "#true" => Err(ParseError::Unexpected {
            label: Some("keyword"),
            span: span.into(),
            found: TokenFormat::Token("#true"),
            expected: expected_kind("identifier"),
        }),
        "#false" => Err(ParseError::Unexpected {
            label: Some("keyword"),
            span: span.into(),
            found: TokenFormat::Token("#false"),
            expected: expected_kind("identifier"),
        }),
        "#null" => Err(ParseError::Unexpected {
            label: Some("keyword"),
            span: span.into(),
            found: TokenFormat::Token("#null"),
            expected: expected_kind("identifier"),
        }),
        "#nan" => Err(ParseError::Unexpected {
            label: Some("keyword"),
            span: span.into(),
            found: TokenFormat::Token("#nan"),
            expected: expected_kind("identifier"),
        }),
        "#inf" => Err(ParseError::Unexpected {
            label: Some("keyword"),
            span: span.into(),
            found: TokenFormat::Token("#inf"),
            expected: expected_kind("identifier"),
        }),
        "#-inf" => Err(ParseError::Unexpected {
            label: Some("keyword"),
            span: span.into(),
            found: TokenFormat::Token("#-inf"),
            expected: expected_kind("identifier"),
        }),
        _ => Ok(s),
    })
}

fn id_sans_dig<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| {
            !matches!(c,
                '0'..='9' |
                '\u{0000}'..='\u{0020}' |
                '\\'|'/'|'('|')'|'{'|'}'|';'|'['|']'|'='|'"'|'#' |
                // whitespace, excluding 0x20
                '\u{00a0}' | '\u{1680}' |
                '\u{2000}'..='\u{200A}' |
                '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}' |
                // newline (excluding <= 0x20)
                '\u{0085}' | '\u{2028}' | '\u{2029}'
            )
        })
        .map_err(|e| e.with_expected_kind("letter"))
}

fn id_sans_dig_point<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| {
            !matches!(c,
                '0'..='9' | '.' |
                '\u{0000}'..='\u{0020}' |
                '\\'|'/'|'('|')'|'{'|'}'|';'|'['|']'|'='|'"'|'#' |
                // whitespace, excluding 0x20
                '\u{00a0}' | '\u{1680}' |
                '\u{2000}'..='\u{200A}' |
                '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}' |
                // newline (excluding <= 0x20)
                '\u{0085}' | '\u{2028}' | '\u{2029}'
            )
        })
        .map_err(|e| e.with_expected_kind("letter"))
}

fn id_sans_sign_dig_point<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| {
            !matches!(c,
                '-'| '+' | '0'..='9' |
                '\u{0000}'..='\u{0020}' |
                '\\'|'/'|'('|')'|'{'|'}'|';'|'['|']'|'='|'"'|'#' |
                // whitespace, excluding 0x20
                '\u{00a0}' | '\u{1680}' |
                '\u{2000}'..='\u{200A}' |
                '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}' |
                // newline (excluding <= 0x20)
                '\u{0085}' | '\u{2028}' | '\u{2029}'
            )
        })
        .map_err(|e| e.with_expected_kind("letter"))
}

fn identifier_char<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| {
            !matches!(c,
                '\u{0000}'..='\u{0021}' |
                '\\'|'/'|'('|')'|'{'|'}'|';'|'['|']'|'='|'"'|'#' |
                // whitespace, excluding 0x20
                '\u{00a0}' | '\u{1680}' |
                '\u{2000}'..='\u{200A}' |
                '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}' |
                // newline (excluding <= 0x20)
                '\u{0085}' | '\u{2028}' | '\u{2029}'
            )
        })
        .map_err(|e| e.with_expected_kind("letter"))
}

fn keyword<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    choice((
        just("#null")
            .map_err(|e: ParseError| e.with_expected_token("#null"))
            .to(Literal::Null),
        just("#true")
            .map_err(|e: ParseError| e.with_expected_token("#true"))
            .to(Literal::Bool(true)),
        just("#false")
            .map_err(|e: ParseError| e.with_expected_token("#false"))
            .to(Literal::Bool(false)),
        just("#nan")
            .map_err(|e: ParseError| e.with_expected_token("#nan"))
            .to(Literal::Nan),
        just("#inf")
            .map_err(|e: ParseError| e.with_expected_token("#inf"))
            .to(Literal::Inf),
        just("#-inf")
            .map_err(|e: ParseError| e.with_expected_token("#-inf"))
            .to(Literal::NegInf),
    ))
}

fn value<'src>() -> impl Parser<'src, Input<'src>, Value, Error> + Clone {
    type_name_value().or(spanned(literal()).map(|literal| Value {
        type_name: None,
        literal,
    }))
}

fn r#type<'src>() -> impl Parser<'src, Input<'src>, TypeName, Error> + Clone {
    identifier()
        .delimited_by(
            just('(').then(unicode_space().repeated()),
            unicode_space().repeated().then(just(')')),
        )
        .map(TypeName::from_string)
}

fn type_name_value<'src>() -> impl Parser<'src, Input<'src>, Value, Error> + Clone {
    spanned(r#type().then_ignore(unicode_space().repeated()))
        .then(spanned(literal()))
        .map(|(type_name, literal)| Value {
            type_name: Some(type_name),
            literal,
        })
}

fn string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    // Beware the order: multi-line variants must be tried before single-line variants
    // to ensure #""" is parsed as multi-line raw string, not single-line with content "".
    choice((
        multiline_raw_string(),
        raw_string(),
        multiline_escaped_string(),
        escaped_string(),
    ))
}

fn escaped_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    // Single quote only - reject """ which is multi-line syntax
    just('"')
        .then_ignore(just("\"\"").not().rewind())
        .ignore_then(
            choice((
                none_of(['"', '\\']),
                just('\\').ignore_then(escape()),
                // ws-escape
                just('\\')
                    .then(unicode_space().or(newline()).repeated().at_least(1))
                    .map(|_| ' '),
            ))
            .repeated()
            .collect::<String>()
            .then_ignore(just('"'))
            .map(|val| val.into())
            .map_err_with_state(|e: ParseError, span, _state| {
                if matches!(
                    &e,
                    ParseError::Unexpected {
                        found: TokenFormat::Eoi,
                        ..
                    }
                ) {
                    e.merge(ParseError::Unclosed {
                        label: "string",
                        opened_at: Span::from(span).before_start(1),
                        opened: '"'.into(),
                        expected_at: Span::from(span).at_end(),
                        expected: '"'.into(),
                        found: None.into(),
                    })
                } else {
                    e
                }
            }),
        )
}

fn escape<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .try_map(|c, span| match c {
            '"' | '\\' => Ok(c),
            'b' => Ok('\u{0008}'),
            'f' => Ok('\u{000C}'),
            'n' => Ok('\n'),
            'r' => Ok('\r'),
            't' => Ok('\t'),
            's' => Ok(' '),
            _ => Err(ParseError::Unexpected {
                label: Some("invalid escape char"),
                span: span.into(),
                found: c.into(),
                expected: "\"\\bfnrts".chars().map(|c| c.into()).collect(),
            }),
        })
        .or(just('u').ignore_then(
            any::<_, Error>()
                .try_map(|c, span| {
                    c.is_ascii_hexdigit()
                        .then_some(c)
                        .ok_or_else(|| ParseError::Unexpected {
                            label: Some("unexpected character"),
                            span: span.into(),
                            found: c.into(),
                            expected: expected_kind("hexadecimal digit"),
                        })
                })
                .repeated()
                .at_least(1)
                .at_most(6)
                .to_slice()
                .delimited_by(just('{'), just('}'))
                .validate(|hex_chars, extras, emit| {
                    u32::from_str_radix(hex_chars, 16)
                        .map_err(|e| e.to_string())
                        .and_then(|n| char::try_from(n).map_err(|e| e.to_string()))
                        .unwrap_or_else(|e| {
                            emit.emit(ParseError::Message {
                                label: Some("invalid character code"),
                                span: extras.span().into(),
                                message: e.to_string(),
                            });
                            '\0'
                        })
                }),
        ))
}

fn radix_number<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    just('-')
        .or(just('+'))
        .or_not()
        .then_ignore(just('0'))
        .then(choice((
            just('b')
                .ignore_then(digit(2).then(integer(2)).to_slice())
                .map(|s| (Radix::Bin, s)),
            just('o')
                .ignore_then(digit(8).then(integer(8)).to_slice())
                .map(|s| (Radix::Oct, s)),
            just('x')
                .ignore_then(digit(16).then(integer(16)).to_slice())
                .map(|s| (Radix::Hex, s)),
        )))
        .map(|(sign, (radix, value))| {
            let mut s = String::with_capacity(value.len() + sign.map_or(0, |_| 1));
            if let Some(c) = sign {
                s.push(c);
            }
            s.extend(value.chars().filter(|&c| c != '_'));
            Literal::Int(Integer(radix, s.into()))
        })
}

fn raw_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    let matching_hashes = just('#')
        .repeated()
        .configure(|cfg, hash_num| cfg.exactly(*hash_num));
    just('#')
        .repeated()
        .at_least(1)
        .count()
        // Single quote only; reject """ which is multi-line syntax
        .then_ignore(just('"').then_ignore(just("\"\"").not().rewind()))
        .ignore_with_ctx(
            any()
                .and_is(just('"').then(matching_hashes).not())
                .repeated()
                .to_slice()
                .then(just('"').ignore_then(matching_hashes.ignored()))
                .map_err_with(move |e: ParseError, extras| {
                    let hash_num = *extras.ctx();
                    if matches!(
                        &e,
                        ParseError::Unexpected {
                            found: TokenFormat::Eoi,
                            ..
                        }
                    ) {
                        e.merge(ParseError::Unclosed {
                            label: "raw string",
                            opened_at: Span::from(extras.span()).before_start(hash_num + 2),
                            opened: TokenFormat::OpenRaw(hash_num),
                            expected_at: Span::from(extras.span()).at_end(),
                            expected: TokenFormat::CloseRaw(hash_num),
                            found: None.into(),
                        })
                    } else {
                        e
                    }
                }),
        )
        .map(|text| text.0.into())
}

/// Normalize newlines: convert all newline variants to LF
fn normalize_newlines(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                // CRLF or CR -> LF
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                result.push('\n');
            }
            '\x0C' | '\x0B' | '\u{0085}' | '\u{2028}' | '\u{2029}' => {
                // Form feed, vertical tab, next line, line/paragraph separator -> LF
                result.push('\n');
            }
            _ => result.push(c),
        }
    }
    result
}

/// Check if a character is a KDL whitespace character
fn is_kdl_ws(c: char) -> bool {
    matches!(
        c,
        '\t' | ' ' | '\u{00a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// Error type for multi-line string dedentation with location information
enum MultilineStringError {
    /// Opening delimiter not followed by newline
    NoOpeningNewline,
    /// Closing delimiter has non-whitespace before it on same line
    ClosingNotOnOwnLine,
    /// A line doesn't start with required indent (offset within content, length of line)
    InsufficientIndent { offset: usize, length: usize },
}

/// Dedent a multi-line string based on the closing line's whitespace prefix.
/// Also strips the first and last newlines.
/// Returns (dedented_string, indent_byte_len) where indent_byte_len is the byte length
/// of the indentation that was stripped from each line.
fn dedent_multiline_string(s: &str) -> Result<(String, usize), MultilineStringError> {
    // Normalize newlines first
    let normalized = normalize_newlines(s);

    // The structure should be: <newline><content-lines><newline><indent>
    // Where the opening newline is required, and the closing newline + indent forms the final line

    // Find the last newline - this separates the content from the closing indent
    let last_newline_pos = match normalized.rfind('\n') {
        Some(pos) => pos,
        None => {
            // No newline at all - invalid
            return Err(MultilineStringError::NoOpeningNewline);
        }
    };

    // The indent is everything after the last newline
    let indent = &normalized[last_newline_pos + 1..];
    let indent_len = indent.len();

    // Validate that indent is all whitespace
    if !indent.chars().all(is_kdl_ws) {
        return Err(MultilineStringError::ClosingNotOnOwnLine);
    }

    // Content before the last newline
    let before_last_newline = &normalized[..last_newline_pos];

    // Special case: empty multi-line string (just one newline)
    // Structure: """<newline>"""  -> content between delimiters is just "\n"
    if before_last_newline.is_empty() {
        // The entire content was just a newline, representing an empty string
        return Ok((String::new(), indent_len));
    }

    // The content must start with a newline (the one after opening delimiter)
    if !before_last_newline.starts_with('\n') {
        return Err(MultilineStringError::NoOpeningNewline);
    }

    // Strip the first newline to get the actual content lines
    let content = &before_last_newline[1..];

    // Dedent each line, tracking offset for error reporting
    let mut result = String::with_capacity(content.len());
    let mut offset_in_content = 0usize;
    let mut first = true;
    for line in content.split('\n') {
        if !first {
            result.push('\n');
        }
        first = false;

        // Whitespace-only lines are kept as empty (don't need to match indent)
        if line.chars().all(is_kdl_ws) {
            offset_in_content += line.len() + 1; // +1 for the newline
            continue;
        }

        // Non-whitespace lines must start with the indent
        if !line.starts_with(indent) {
            // Offset in original content: 1 (for first newline) + offset_in_content
            // Length is just the whitespace prefix (in bytes), not the whole line
            let ws_prefix_byte_len: usize = line
                .chars()
                .take_while(|c| is_kdl_ws(*c))
                .map(|c| c.len_utf8())
                .sum();
            return Err(MultilineStringError::InsufficientIndent {
                offset: 1 + offset_in_content,
                length: ws_prefix_byte_len,
            });
        }
        result.push_str(&line[indent.len()..]);
        offset_in_content += line.len() + 1; // +1 for the newline
    }

    Ok((result, indent_len))
}

/// Process escape sequences in a string
/// Error from process_escapes: (start_offset, end_offset, message)
/// Offsets are byte positions relative to the input string.
fn process_escapes(s: &str) -> Result<String, (usize, usize, String)> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some((_, '"')) => result.push('"'),
                Some((_, '\\')) => result.push('\\'),
                Some((_, 'b')) => result.push('\u{0008}'),
                Some((_, 'f')) => result.push('\u{000C}'),
                Some((_, 'n')) => result.push('\n'),
                Some((_, 'r')) => result.push('\r'),
                Some((_, 't')) => result.push('\t'),
                Some((_, 's')) => result.push(' '),
                Some((_, 'u')) => {
                    // Parse unicode escape \u{XXXX}
                    'check_brace: {
                        let char_len = match chars.next() {
                            Some((_, '{')) => {
                                break 'check_brace;
                            }
                            Some((_, c)) => c.len_utf8(),
                            None => {
                                // String ended after \u
                                0
                            }
                        };
                        // Point to \u and the wrong char
                        return Err((i, i + 2 + char_len, "expected '{' after \\u".to_string()));
                    }
                    let mut hex = String::new();
                    let close_pos = loop {
                        match chars.next() {
                            Some((j, '}')) => {
                                break j + 1;
                            }
                            Some((j, c)) if c.is_ascii_hexdigit() => {
                                if hex.len() >= 6 {
                                    // Too many digits - span the whole escape up to and including the excess digit
                                    return Err((
                                        i,
                                        j + c.len_utf8(),
                                        "unicode escape too long".to_string(),
                                    ));
                                }
                                hex.push(c);
                            }
                            Some((j, c)) => {
                                // Invalid character - span the whole escape up to and including the invalid char
                                return Err((
                                    i,
                                    j + c.len_utf8(),
                                    format!("invalid character '{}' in unicode escape", c),
                                ));
                            }
                            None => {
                                // Unclosed - point from \ to end of string
                                return Err((i, s.len(), "unclosed unicode escape".to_string()));
                            }
                        }
                    };
                    if hex.is_empty() {
                        // Empty \u{} - point to the whole escape
                        return Err((i, close_pos, "empty unicode escape".to_string()));
                    }
                    let code = u32::from_str_radix(&hex, 16).unwrap();
                    match char::try_from(code) {
                        Ok(c) => result.push(c),
                        Err(_) => {
                            // Invalid code point - point to the whole escape
                            return Err((
                                i,
                                close_pos,
                                format!("invalid unicode code point: {}", code),
                            ));
                        }
                    }
                }
                Some((_, c)) if c == ' ' || c == '\t' || c == '\n' || is_kdl_ws(c) => {
                    // Whitespace escape: consume whitespace and newlines, produce space
                    while let Some(&(_, next)) = chars.peek() {
                        if next == ' ' || next == '\t' || next == '\n' || is_kdl_ws(next) {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    result.push(' ');
                }
                Some((j, c)) => {
                    // Invalid escape char - span the backslash and the invalid character
                    return Err((
                        i,
                        j + c.len_utf8(),
                        format!("invalid escape character: '{}'", c),
                    ));
                }
                None => {
                    // Trailing backslash - point just to the backslash
                    return Err((i, i + 1, "trailing backslash".to_string()));
                }
            }
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

/// Multi-line quoted string parser: """..."""
/// The opening """ must be followed by a newline, and the closing """ must be on its own line.
fn multiline_escaped_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    just("\"\"\"").ignore_then(
        // Capture raw content - one or two quotes are allowed, but not three
        choice((
            // One double-quote that isn't followed by two more (not """)
            just('"').then_ignore(just("\"\"").not().rewind()),
            // Regular character (not quote)
            none_of(['"']),
        ))
        .repeated()
        .to_slice()
        .then_ignore(just("\"\"\""))
        .validate(|content: &str, extras, emit| {
            let span = Span::from(extras.span());
            // Note: span covers content + closing """, so span.end includes the closing delimiter
            // Content is at span.start to span.end - 3
            let content_len = content.len();

            // Step 1: Dedent (which includes newline normalization)
            let (dedented, indent_len) = match dedent_multiline_string(content) {
                Ok(d) => d,
                Err(e) => {
                    let (label, error_span, message) = match e {
                        MultilineStringError::NoOpeningNewline => (
                            "must be followed by newline",
                            span.before_start(3), // Point to opening """
                            "opening delimiter must be immediately followed by a newline",
                        ),
                        MultilineStringError::ClosingNotOnOwnLine => (
                            "must be on its own line",
                            // Closing """ is at end of span (last 3 chars)
                            Span(span.0 + content_len, span.1),
                            "closing delimiter must be on its own line with only whitespace prefix",
                        ),
                        MultilineStringError::InsufficientIndent { offset, length } => (
                            "insufficient indentation",
                            // Offset is within content, which starts at span.0
                            Span(span.0 + offset, span.0 + offset + length),
                            "line must start with the same whitespace as the closing delimiter",
                        ),
                    };
                    emit.emit(ParseError::Message {
                        label: Some(label),
                        span: error_span,
                        message: message.to_string(),
                    });
                    return "".into();
                }
            };

            // Step 2: Process escape sequences
            match process_escapes(&dedented) {
                Ok(processed) => processed.into(),
                Err((start, end, msg)) => {
                    // Map dedented offsets to content offsets:
                    // The dedented string has indentation stripped from each line.
                    // To map back to content positions, we need to account for:
                    // - 1 byte for the leading newline
                    // - indent_len bytes for the first line's indentation
                    // - For each newline in the dedented string before the error,
                    //   add indent_len bytes (the stripped indentation of that line)
                    let newlines_before_start = dedented[..start].matches('\n').count();
                    let newlines_before_end = dedented[..end].matches('\n').count();
                    let content_start = 1 + indent_len + start + newlines_before_start * indent_len;
                    let content_end = 1 + indent_len + end + newlines_before_end * indent_len;
                    let error_span = Span(span.0 + content_start, span.0 + content_end);
                    emit.emit(ParseError::Message {
                        label: Some("invalid escape sequence"),
                        span: error_span,
                        message: msg,
                    });
                    "".into()
                }
            }
        })
        .map_err_with_state(|e: ParseError, span: SimpleSpan, _state| {
            // Only produce Unclosed error after opening """ was successfully matched
            let span: Span = span.into();
            if matches!(
                &e,
                ParseError::Unexpected {
                    found: TokenFormat::Eoi,
                    ..
                }
            ) {
                // Go back 3 chars for the """ that was already consumed
                e.merge(ParseError::Unclosed {
                    label: "multi-line string",
                    opened_at: span.before_start(3),
                    opened: TokenFormat::OpenMultiline,
                    expected_at: span.at_end(),
                    expected: TokenFormat::CloseMultiline,
                    found: None.into(),
                })
            } else {
                e
            }
        }),
    )
}

/// Multi-line raw string parser: #"""..."""#, ##"""..."""##, etc.
fn multiline_raw_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    let matching_hashes = just('#')
        .repeated()
        .configure(|cfg, hash_num| cfg.exactly(*hash_num));

    just('#')
        .repeated()
        .at_least(1)
        .count()
        .then_ignore(just("\"\"\""))
        .ignore_with_ctx(
            any()
                .and_is(just("\"\"\"").then(matching_hashes).not())
                .repeated()
                .to_slice()
                .then(just("\"\"\"").ignore_then(matching_hashes.ignored()))
                .map_err_with(move |e: ParseError, extras| {
                    let hash_num = *extras.ctx();
                    if matches!(
                        &e,
                        ParseError::Unexpected {
                            found: TokenFormat::Eoi,
                            ..
                        }
                    ) {
                        e.merge(ParseError::Unclosed {
                            label: "multi-line raw string",
                            opened_at: Span::from(extras.span()).before_start(hash_num + 4),
                            opened: TokenFormat::OpenMultilineRaw(hash_num),
                            expected_at: Span::from(extras.span()).at_end(),
                            expected: TokenFormat::CloseMultilineRaw(hash_num),
                            found: None.into(),
                        })
                    } else {
                        e
                    }
                })
                .validate(|(content, _): (&str, ()), extras, emit| {
                    let span = Span::from(extras.span());
                    // Note: span covers content + closing """# (the # count matches opening)
                    // Content is at span.start to span.end - 3 - hash_count
                    let hash_num = *extras.ctx();

                    match dedent_multiline_string(content) {
                        Ok((dedented, _indent_len)) => dedented.into(),
                        Err(e) => {
                            let (label, error_span, message) = match e {
                                MultilineStringError::NoOpeningNewline => (
                                    "must be followed by newline",
                                    span.before_start(hash_num + 3),
                                    "opening delimiter must be immediately followed by a newline",
                                ),
                                MultilineStringError::ClosingNotOnOwnLine => (
                                    "must be on its own line",
                                    // Point to closing """ (at content_len offset, length 3)
                                    Span(span.1 - 3 - hash_num, span.1),
                                    "closing delimiter must be on its own line with only whitespace prefix",
                                ),
                                MultilineStringError::InsufficientIndent { offset, length } => (
                                    "insufficient indentation",
                                    // Offset is within content, which starts at span.0
                                    Span(span.0 + offset, span.0 + offset + length),
                                    "line must start with the same whitespace as the closing delimiter",
                                ),
                            };
                            emit.emit(ParseError::Message {
                                label: Some(label),
                                span: error_span,
                                message: message.to_string(),
                            });
                            // Return empty string as error recovery
                            "".into()
                        }
                    }
                }),
        )
}

fn number<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    radix_number().or(decimal())
}

fn decimal<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    just('-')
        .or(just('+'))
        .or_not()
        .then(digit(10))
        .then(integer(10))
        .then(just('.').then(digit(10)).then(integer(10)).or_not())
        .then(
            just('e')
                .or(just('E'))
                .then(just('-').or(just('+')).or_not())
                .then(integer(10))
                .or_not(),
        )
        .to_slice()
        .map(|v: &str| {
            let is_decimal = v.chars().any(|c| matches!(c, '.' | 'e' | 'E'));
            let s: String = v.chars().filter(|c| c != &'_').collect();
            if is_decimal {
                Literal::Decimal(Decimal(s.into()))
            } else {
                Literal::Int(Integer(Radix::Dec, s.into()))
            }
        })
}

fn integer<'src>(radix: u32) -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    any::<_, Error>()
        .filter(move |c: &char| c == &'_' || c.is_digit(radix))
        .repeated()
}

fn digit<'src>(radix: u32) -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>().filter(move |c: &char| c.is_digit(radix))
}

fn literal<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    // Check for `ident` last, because `ident` first checks for numbers,
    // and it can confuse keywords with raw strings.
    choice((keyword(), number(), identifier().map(Literal::String)))
}

fn escline<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just('\\')
        .ignore_then(ws().repeated())
        .ignore_then(single_line_comment().or(newline()).or(end()))
}

fn linespace<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    newline().or(ws()).or(single_line_comment())
}

fn newline<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just('\r')
        .or_not()
        .ignore_then(just('\n'))
        .or(just('\r')) // Carriage return
        .or(just('\x0C')) // Form feed
        .or(just('\x0B')) // Vertical tab
        .or(just('\u{0085}')) // Next line
        .or(just('\u{2028}')) // Line separator
        .or(just('\u{2029}')) // Paragraph separator
        .ignored()
        .map_err(|e: ParseError| e.with_expected_kind("newline"))
}

fn ws<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    unicode_space()
        .repeated()
        .at_least(1)
        .ignored()
        .or(multi_line_comment())
        .map_err(|e| e.with_expected_kind("whitespace"))
}

fn unicode_space<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    any::<_, Error>()
        .filter(|c| {
            matches!(
                c,
                '\t' | ' ' | '\u{00a0}' | '\u{1680}' | '\u{2000}'
                    ..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
            )
        })
        .ignored()
}

fn single_line_comment<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    begin_comment('/')
        .then(
            any()
                .and_is(newline().not())
                .and_is(end().not())
                .repeated()
                .then(newline().or(end())),
        )
        .ignored()
}

fn multi_line_comment<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    recursive::<_, _, Error, _, _>(|comment| {
        choice((
            comment,
            none_of('*').ignored(),
            just('*').then_ignore(none_of('/').rewind()).ignored(),
        ))
        .repeated()
        .ignored()
        .delimited_by(begin_comment('*'), just("*/"))
    })
    .map_err_with_state(|e, span, _state| {
        let span: Span = span.into();
        if matches!(
            &e,
            ParseError::Unexpected {
                found: TokenFormat::Eoi,
                ..
            }
        ) && span.length() > 2
        {
            e.merge(ParseError::Unclosed {
                label: "comment",
                opened_at: span.at_start(2),
                opened: "/*".into(),
                expected_at: span.at_end(),
                expected: "*/".into(),
                found: None.into(),
            })
        } else {
            // otherwise opening /* is not matched
            e
        }
    })
}

fn begin_comment<'src>(which: char) -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just('/')
        .map_err(|e: ParseError| e.with_no_expected())
        .ignore_then(just(which).ignored())
}

fn expected_kind(s: &'static str) -> BTreeSet<TokenFormat> {
    [TokenFormat::Kind(s)].into_iter().collect()
}

fn spanned<'src, T, P>(p: P) -> impl Parser<'src, Input<'src>, Spanned<T>, Error> + Clone
where
    P: Parser<'src, Input<'src>, T, Error> + Clone,
{
    p.map_with(|value, e| Spanned {
        span: e.span().into(),
        value,
    })
}
