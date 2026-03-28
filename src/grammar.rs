use std::collections::{BTreeMap, BTreeSet};

use chumsky::input::Emitter;
use chumsky::prelude::*;

use crate::ast::{Decimal, Integer, Literal, Node, Radix, TypeName, Value};
use crate::ast::{Document, SpannedName, SpannedNode};
use crate::errors::{ParseError, TokenFormat};
use crate::span::{Span, Spanned};

type Error = extra::Err<ParseError>;
type Input<'src> = &'src str;

// document := bom? version? nodes
pub(crate) fn document<'src>() -> impl Parser<'src, Input<'src>, Document, Error> {
    bom()
        .or_not()
        .ignore_then(version().or_not())
        .ignore_then(nodes())
        .map(|nodes| Document { nodes })
}

// nodes := (line-space* node)* line-space*
fn nodes<'src>() -> impl Parser<'src, Input<'src>, Vec<SpannedNode>, Error> + Clone {
    use PropOrArg::*;
    recursive(|nodes| {
        let braced_nodes = just('{')
            .ignore_then(
                nodes
                    .then_ignore(just('}'))
                    .map_err_with_state(|e, span: SimpleSpan, _state| {
                        if matches!(
                            &e,
                            ParseError::Unexpected {
                                found: TokenFormat::Eoi,
                                ..
                            }
                        ) {
                            e.merge(ParseError::Unclosed {
                                label: "curly braces",
                                opened_at: Span::from(span).before_start(1),
                                opened: '{'.into(),
                                expected_at: Span::from(span).at_end(),
                                expected: '}'.into(),
                                found: None.into(),
                            })
                        } else {
                            e
                        }
                    }),
            );

        // base-node := slashdash? type? node-space* string
        //     (node-space* (node-space | slashdash) node-prop-or-arg)*
        //     (node-space* slashdash node-children)*
        //     (node-space* node-children)?
        //     (node-space* slashdash node-children)*
        //     node-space*

        // The grammar uses `string` for the node name, but we also try to
        // match numbers so we can report "found number, expected identifier".
        let node_name = choice((
            number().map(Err),
            identifier_string().map(Ok),
            string().map(Ok),
        ))
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
        });

        let base_node = spanned(r#type().then_ignore(node_space().repeated()))
            .or_not()
            .then(spanned(node_name))
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
                        slashdash()
                            .then_ignore(line_space().repeated())
                            .or_not(),
                    )
                    .then(spanned(braced_nodes))
                    .or_not(),
            )
            .then_ignore(node_space().repeated())
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

        // node := base-node node-terminator
        // Include terminator inside spanned() so node span covers the terminator
        let node = spanned(base_node.then_ignore(node_terminator()));

        // nodes := (line-space* node)* line-space*
        slashdash()
            .then_ignore(line_space().repeated())
            .or_not()
            .then(node)
            .separated_by(line_space().repeated())
            .allow_leading()
            .allow_trailing()
            .collect::<Vec<(Option<()>, Spanned<Node>)>>()
            .map(|vec| {
                vec.into_iter()
                    .filter_map(|(comment, node)| {
                        if comment.is_none() {
                            Some(node)
                        } else {
                            None
                        }
                    })
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

// node-prop-or-arg := prop | value
fn node_prop_or_arg<'src>() -> impl Parser<'src, Input<'src>, PropOrArg, Error> + Clone {
    slashdash()
        .ignore_then(line_space().repeated())
        .ignore_then(node_prop_or_arg_inner())
        .to(PropOrArg::Ignore)
        .or(node_prop_or_arg_inner())
}

fn node_prop_or_arg_inner<'src>() -> impl Parser<'src, Input<'src>, PropOrArg, Error> + Clone {
    use PropOrArg::*;

    // prop := string node-space* '=' node-space* value
    // Note: we use unicode_space (not node_space) around '=' so that
    // escline is not allowed around the equals sign. This prevents
    // ambiguity where `a\\\n=b` would parse `a` as a property name.
    let equals_value = unicode_space()
        .repeated()
        .then(just('='))
        .then(unicode_space().repeated())
        .ignore_then(value());

    // string | number | keyword (+ keyword-number), used to parse a
    // potential prop name or argument value
    let value_body = choice((
        keyword(),
        keyword_number(),
        number(),
        string().map(Literal::String),
    ));

    choice((
        spanned(value_body)
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
        spanned(identifier_string())
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
        // Typed value like (string)"hello" — always an argument
        value().map(Arg),
    ))
}

// node-terminator := single-line-comment | newline | ';' | eof
fn node_terminator<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    choice((newline(), single_line_comment(), just(';').ignored(), end()))
}

// value := type? node-space* (string | number | keyword)
fn value<'src>() -> impl Parser<'src, Input<'src>, Value, Error> + Clone {
    // string | number | keyword (+ keyword-number)
    let value_body = choice((
        keyword(),
        keyword_number(),
        number(),
        string().map(Literal::String),
    ));

    spanned(r#type().then_ignore(node_space().repeated()))
        .or_not()
        .then(spanned(value_body))
        .map(|(type_name, literal)| Value {
            type_name,
            literal,
        })
}

// type := '(' node-space* string node-space* ')'
fn r#type<'src>() -> impl Parser<'src, Input<'src>, TypeName, Error> + Clone {
    // The grammar uses `string` here, but we also try to match numbers
    // so we can report "found number, expected identifier" errors.
    choice((
        number().map(Err),
        identifier_string().map(Ok),
        string().map(Ok),
    ))
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
    .delimited_by(
        just('(').then(node_space().repeated()),
        node_space().repeated().then(just(')')),
    )
    .map(TypeName::from_string)
}

// string := identifier-string | quoted-string | raw-string
fn string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    // raw_string before quoted_string so chumsky's error recovery works correctly
    choice((identifier_string(), raw_string(), quoted_string()))
}

// quoted-string :=
//     '"' single-line-string-body '"' |
//     '"""' newline multi-line-string-body? newline ws* '"""'
fn quoted_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    choice((multi_line_quoted_string(), single_line_quoted_string()))
}

// identifier-string :=
//     (unambiguous-ident | signed-ident | dotted-ident)
//     - disallowed-keyword-identifiers
fn identifier_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    choice((
        // unambiguous-ident: (identifier-char - digit - sign - '.') identifier-char*
        unambiguous_ident(),
        // signed-ident: sign ((identifier-char - digit - '.') identifier-char*)?
        signed_ident(),
        // dotted-ident: sign? '.' ((identifier-char - digit) identifier-char*)?
        dotted_ident(),
    ))
    .map(|v: &str| Box::<str>::from(v))
    .try_map(|s, span| {
        // disallowed-keyword-identifiers
        match &s[..] {
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
        }
    })
}

// unambiguous-ident := (identifier-char - digit - sign - '.') identifier-char*
fn unambiguous_ident<'src>() -> impl Parser<'src, Input<'src>, &'src str, Error> + Clone {
    id_sans_sign_dig_point()
        .then(identifier_char().repeated())
        .to_slice()
}

// signed-ident := sign ((identifier-char - digit - '.') identifier-char*)?
fn signed_ident<'src>() -> impl Parser<'src, Input<'src>, &'src str, Error> + Clone {
    sign()
        .then(
            id_sans_dig_point()
                .then(identifier_char().repeated())
                .or_not(),
        )
        .to_slice()
}

// dotted-ident := sign? '.' ((identifier-char - digit) identifier-char*)?
fn dotted_ident<'src>() -> impl Parser<'src, Input<'src>, &'src str, Error> + Clone {
    sign()
        .or_not()
        .then(just('.'))
        .then(id_sans_dig().then(identifier_char().repeated()).or_not())
        .to_slice()
}

// sign := '+' | '-'
fn sign<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    just('+').or(just('-'))
}

// identifier-char := unicode - unicode-space - newline - [\\/(){};\[\]"#=]
//     - disallowed-literal-code-points
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
        .map_err(|e: ParseError| e.with_expected_kind("letter"))
}

// (identifier-char - digit)
fn id_sans_dig<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| {
            !matches!(c,
                '0'..='9' |
                '\u{0000}'..='\u{0020}' |
                '\\'|'/'|'('|')'|'{'|'}'|';'|'['|']'|'='|'"'|'#' |
                '\u{00a0}' | '\u{1680}' |
                '\u{2000}'..='\u{200A}' |
                '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}' |
                '\u{0085}' | '\u{2028}' | '\u{2029}'
            )
        })
        .map_err(|e: ParseError| e.with_expected_kind("letter"))
}

// (identifier-char - digit - '.')
fn id_sans_dig_point<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| {
            !matches!(c,
                '0'..='9' | '.' |
                '\u{0000}'..='\u{0020}' |
                '\\'|'/'|'('|')'|'{'|'}'|';'|'['|']'|'='|'"'|'#' |
                '\u{00a0}' | '\u{1680}' |
                '\u{2000}'..='\u{200A}' |
                '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}' |
                '\u{0085}' | '\u{2028}' | '\u{2029}'
            )
        })
        .map_err(|e: ParseError| e.with_expected_kind("letter"))
}

// (identifier-char - digit - sign - '.')
fn id_sans_sign_dig_point<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| {
            !matches!(c,
                '-'| '+' | '0'..='9' |
                '\u{0000}'..='\u{0020}' |
                '\\'|'/'|'('|')'|'{'|'}'|';'|'['|']'|'='|'"'|'#' |
                '\u{00a0}' | '\u{1680}' |
                '\u{2000}'..='\u{200A}' |
                '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}' |
                '\u{0085}' | '\u{2028}' | '\u{2029}'
            )
        })
        .map_err(|e: ParseError| e.with_expected_kind("letter"))
}

// Single-line quoted string: '"' single-line-string-body '"'
fn single_line_quoted_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
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

// string-character escape handling
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

// Multi-line quoted string: '"""' newline ... '"""'
fn multi_line_quoted_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
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

            let (dedented, indent_len) = match dedent_multiline_string(content) {
                Ok(d) => d,
                Err(e) => {
                    emit_multiline_dedent_error(e, span, 3, 3, emit);
                    return "".into();
                }
            };

            match process_escapes(&dedented) {
                Ok(processed) => processed.into(),
                Err((start, end, msg)) => {
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
            let span: Span = span.into();
            if matches!(
                &e,
                ParseError::Unexpected {
                    found: TokenFormat::Eoi,
                    ..
                }
            ) {
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

// raw-string := '#' raw-string-quotes '#' | '#' raw-string '#'
fn raw_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    just('#')
        .repeated()
        .at_least(1)
        .count()
        .ignore_with_ctx(raw_string_quotes())
}

// raw-string-quotes :=
//     '"' single-line-raw-string-body '"' |
//     '"""' newline (multi-line-raw-string-body newline)? unicode-space* '"""'
fn raw_string_quotes<'src>(
) -> impl Parser<'src, Input<'src>, Box<str>, extra::Full<ParseError, (), usize>> + Clone {
    let matching_hashes = just('#')
        .repeated()
        .configure(|cfg, hash_num| cfg.exactly(*hash_num));

    // Multi-line: """...""" (must be tried before single-line since """ starts with ")
    let multi_line = just("\"\"\"").ignore_then(
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
                let hash_num = *extras.ctx();

                match dedent_multiline_string(content) {
                    Ok((dedented, _indent_len)) => dedented.into(),
                    Err(e) => {
                        emit_multiline_dedent_error(e, span, hash_num + 3, 3 + hash_num, emit);
                        "".into()
                    }
                }
            }),
    );

    // Single-line: "..."
    let single_line = just('"')
        .then_ignore(just("\"\"").not().rewind())
        .ignore_then(
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
        .map(|(text, _): (&str, ())| -> Box<str> { text.into() });

    choice((multi_line, single_line))
}

// number := keyword-number | hex | octal | binary | decimal
// Note: keyword_number is handled in literal() alongside keyword(),
// not here, to avoid polluting expected-token sets in error messages.
fn number<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    choice((hex_or_octal_or_binary(), decimal()))
}

// hex | octal | binary — these share the sign? '0' prefix
fn hex_or_octal_or_binary<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    just('-')
        .or(just('+'))
        .or_not()
        .then_ignore(just('0'))
        .then(choice((
            // binary := sign? '0b' ('0' | '1') ('0' | '1' | '_')*
            just('b')
                .ignore_then(digit(2).then(integer(2)).to_slice())
                .map(|s| (Radix::Bin, s)),
            // octal := sign? '0o' [0-7] [0-7_]*
            just('o')
                .ignore_then(digit(8).then(integer(8)).to_slice())
                .map(|s| (Radix::Oct, s)),
            // hex := sign? '0x' hex-digit (hex-digit | '_')*
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

// decimal := sign? integer ('.' integer)? exponent?
fn decimal<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    just('-')
        .or(just('+'))
        .or_not()
        .then(digit(10))
        .then(integer(10))
        .then(just('.').then(digit(10)).then(integer(10)).or_not())
        .then(
            // exponent := ('e' | 'E') sign? integer
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

// exponent := ('e' | 'E') sign? integer
// (handled inline in decimal)

// integer := digit (digit | '_')*
fn integer<'src>(radix: u32) -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    any::<_, Error>()
        .filter(move |c: &char| c == &'_' || c.is_digit(radix))
        .repeated()
}

// digit := [0-9]
fn digit<'src>(radix: u32) -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>().filter(move |c: &char| c.is_digit(radix))
}

// keyword := boolean | '#null'
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
    ))
}

// keyword-number := '#inf' | '#-inf' | '#nan'
fn keyword_number<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    choice((
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

// boolean := '#true' | '#false'
// (handled inline in keyword)

// bom := '\u{FEFF}'
fn bom<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just('\u{FEFF}').ignored()
}

// unicode-space := See Table
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

// single-line-comment := '//' ^newline* (newline | eof)
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

// multi-line-comment := '/*' commented-block
// commented-block := '*/' | (multi-line-comment | '*' | '/' | [^*/]+) commented-block
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

// slashdash := '/-' line-space*
fn slashdash<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    begin_comment('-').then_ignore(line_space().repeated())
}

// ws := unicode-space | multi-line-comment
fn ws<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    unicode_space()
        .repeated()
        .at_least(1)
        .ignored()
        .or(multi_line_comment())
        .map_err(|e: ParseError| e.with_expected_kind("whitespace"))
}

// escline := '\\' ws* (single-line-comment | newline | eof)
fn escline<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just('\\')
        .ignore_then(ws().repeated())
        .ignore_then(single_line_comment().or(newline()).or(end()))
}

// newline := See Table (All Newline White_Space)
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

// line-space := node-space | newline | single-line-comment
fn line_space<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    newline().or(ws()).or(single_line_comment())
}

// node-space := ws* escline ws* | ws+
fn node_space<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    ws().or(escline())
}

// version := '/-' unicode-space* 'kdl-version' unicode-space+ ('1' | '2') unicode-space* newline
fn version<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just("/-")
        .then(unicode_space().repeated())
        .then(just("kdl-version"))
        .then(unicode_space().repeated().at_least(1))
        .then(just('1').or(just('2')))
        .then(unicode_space().repeated())
        .then(newline())
        .ignored()
}

// Helper: begin a comment sequence (// or /- or /*)
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

// --- Helper functions for multi-line strings ---

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
    NoOpeningNewline,
    ClosingNotOnOwnLine,
    InsufficientIndent { offset: usize, length: usize },
}

/// Emit a parse error for a multiline string dedent failure.
/// `opening_delimiter_len` is the length of the opening delimiter (e.g. 3 for `"""`, 3+hashes for raw).
/// `closing_delimiter_len` is the length of the closing delimiter.
fn emit_multiline_dedent_error(
    e: MultilineStringError,
    span: Span,
    opening_delimiter_len: usize,
    closing_delimiter_len: usize,
    emit: &mut Emitter<ParseError>,
) {
    let (label, error_span, message) = match e {
        MultilineStringError::NoOpeningNewline => (
            "must be followed by newline",
            span.before_start(opening_delimiter_len),
            "opening delimiter must be immediately followed by a newline",
        ),
        MultilineStringError::ClosingNotOnOwnLine => (
            "must be on its own line",
            Span(span.1 - closing_delimiter_len, span.1),
            "closing delimiter must be on its own line with only whitespace prefix",
        ),
        MultilineStringError::InsufficientIndent { offset, length } => (
            "insufficient indentation",
            Span(span.0 + offset, span.0 + offset + length),
            "line must start with the same whitespace as the closing delimiter",
        ),
    };
    emit.emit(ParseError::Message {
        label: Some(label),
        span: error_span,
        message: message.to_string(),
    });
}

/// Dedent a multi-line string based on the closing line's whitespace prefix.
fn dedent_multiline_string(s: &str) -> Result<(String, usize), MultilineStringError> {
    let normalized = normalize_newlines(s);

    let last_newline_pos = match normalized.rfind('\n') {
        Some(pos) => pos,
        None => {
            return Err(MultilineStringError::NoOpeningNewline);
        }
    };

    let indent = &normalized[last_newline_pos + 1..];
    let indent_len = indent.len();

    if !indent.chars().all(is_kdl_ws) {
        return Err(MultilineStringError::ClosingNotOnOwnLine);
    }

    let before_last_newline = &normalized[..last_newline_pos];

    if before_last_newline.is_empty() {
        return Ok((String::new(), indent_len));
    }

    if !before_last_newline.starts_with('\n') {
        return Err(MultilineStringError::NoOpeningNewline);
    }

    let content = &before_last_newline[1..];

    let mut result = String::with_capacity(content.len());
    let mut offset_in_content = 0usize;
    let mut first = true;
    for line in content.split('\n') {
        if !first {
            result.push('\n');
        }
        first = false;

        if line.chars().all(is_kdl_ws) {
            offset_in_content += line.len() + 1;
            continue;
        }

        if !line.starts_with(indent) {
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
        offset_in_content += line.len() + 1;
    }

    Ok((result, indent_len))
}

/// Process escape sequences in a string
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
                    'check_brace: {
                        let char_len = match chars.next() {
                            Some((_, '{')) => {
                                break 'check_brace;
                            }
                            Some((_, c)) => c.len_utf8(),
                            None => 0,
                        };
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
                                    return Err((
                                        i,
                                        j + c.len_utf8(),
                                        "unicode escape too long".to_string(),
                                    ));
                                }
                                hex.push(c);
                            }
                            Some((j, c)) => {
                                return Err((
                                    i,
                                    j + c.len_utf8(),
                                    format!("invalid character '{}' in unicode escape", c),
                                ));
                            }
                            None => {
                                return Err((i, s.len(), "unclosed unicode escape".to_string()));
                            }
                        }
                    };
                    if hex.is_empty() {
                        return Err((i, close_pos, "empty unicode escape".to_string()));
                    }
                    let code = u32::from_str_radix(&hex, 16).unwrap();
                    match char::try_from(code) {
                        Ok(c) => result.push(c),
                        Err(_) => {
                            return Err((
                                i,
                                close_pos,
                                format!("invalid unicode code point: {}", code),
                            ));
                        }
                    }
                }
                Some((_, c)) if c == ' ' || c == '\t' || c == '\n' || is_kdl_ws(c) => {
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
                    return Err((
                        i,
                        j + c.len_utf8(),
                        format!("invalid escape character: '{}'", c),
                    ));
                }
                None => {
                    return Err((i, i + 1, "trailing backslash".to_string()));
                }
            }
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::{Error, Input};
    use super::{
        identifier_string, keyword, keyword_number, multi_line_comment, single_line_comment,
        string, r#type, ws,
    };
    use super::{nodes, number};
    use crate::ast::{Decimal, Integer, Literal, Radix, TypeName};
    use crate::errors::Error as MietteError;
    use chumsky::prelude::*;
    use miette::NamedSource;

    macro_rules! err_eq {
        ($left: expr_2021, $right: expr_2021) => {
            let left = $left.unwrap_err();
            let left: serde_json::Value = serde_json::from_str(&left).unwrap();
            let right: serde_json::Value =
                serde_json::from_str($right).unwrap();
            assert_json_diff::assert_json_include!(
                actual: left, expected: right);
            //assert_json_diff::assert_json_eq!(left, right);
        }
    }

    fn parse<'src, P, T>(p: P, text: &'src str) -> Result<T, String>
    where
        P: Parser<'src, Input<'src>, T, Error>,
    {
        p.parse(text).into_result().map_err(|errors| {
            let source = text.to_string() + " ";
            let e = MietteError {
                source_code: NamedSource::new("<test>", source),
                errors: errors.into_iter().map(Into::into).collect(),
            };
            let mut buf = String::with_capacity(512);
            miette::GraphicalReportHandler::new()
                .render_report(&mut buf, &e)
                .unwrap();
            println!("{}", buf);
            buf.truncate(0);
            miette::JSONReportHandler::new()
                .render_report(&mut buf, &e)
                .unwrap();
            buf
        })
    }

    #[test]
    fn parse_ws() {
        parse(ws(), "   ").unwrap();
        parse(ws(), "text").unwrap_err();
    }

    #[test]
    fn parse_comments() {
        parse(single_line_comment(), "//hello").unwrap();
        parse(single_line_comment(), "//hello\n").unwrap();
        parse(multi_line_comment(), "/*nothing*/").unwrap();
        parse(multi_line_comment(), "/*nothing**/").unwrap();
        parse(multi_line_comment(), "/*no*thing*/").unwrap();
        parse(multi_line_comment(), "/*no/**/thing*/").unwrap();
        parse(multi_line_comment(), "/*no/*/**/*/thing*/").unwrap();
        parse(ws().then(single_line_comment()), "   // hello").unwrap();
        parse(
            ws().then(single_line_comment())
                .then(ws())
                .then(single_line_comment()),
            "   // hello\n   //world",
        )
        .unwrap();
    }

    #[test]
    fn parse_comment_err() {
        err_eq!(
            parse(ws(), r#"/* comment"#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed comment `/*`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 2}},
                    {"label": "expected `*/`",
                    "span": {"offset": 10, "length": 0}}
                ],
                "related": []
            }]
        }"#
        );
        err_eq!(
            parse(ws(), r#"/* com/*ment *"#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed comment `/*`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 2}},
                    {"label": "expected `*/`",
                    "span": {"offset": 14, "length": 0}}
                ],
                "related": []
            }]
        }"#
        );
        err_eq!(
            parse(ws(), r#"/* com/*me*/nt *"#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed comment `/*`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 2}},
                    {"label": "expected `*/`",
                    "span": {"offset": 16, "length": 0}}
                ],
                "related": []
            }]
        }"#
        );
        err_eq!(
            parse(ws(), r#"/* comment *"#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed comment `/*`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 2}},
                    {"label": "expected `*/`",
                    "span": {"offset": 12, "length": 0}}
                ],
                "related": []
            }]
        }"#
        );
        err_eq!(
            parse(ws(), r#"/*/"#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed comment `/*`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 2}},
                    {"label": "expected `*/`",
                    "span": {"offset": 3, "length": 0}}
                ],
                "related": []
            }]
        }"#
        );
        // nothing is expected for comment or whitespace
        err_eq!(
            parse(ws(), r#"xxx"#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "found `x`, expected whitespace",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected token",
                    "span": {"offset": 0, "length": 1}}
                ],
                "related": []
            }]
        }"#
        );
    }

    #[test]
    fn parse_str() {
        assert_eq!(&*parse(string(), r#""hello""#).unwrap(), "hello");
        assert_eq!(&*parse(string(), r#""""#).unwrap(), "");
        assert_eq!(&*parse(string(), r#""hel\"lo""#).unwrap(), "hel\"lo");
        assert_eq!(
            &*parse(string(), r#""hello\nworld!""#).unwrap(),
            "hello\nworld!"
        );
        assert_eq!(&*parse(string(), r#""\u{1F680}""#).unwrap(), "🚀");
    }

    #[test]
    fn parse_raw_str() {
        assert_eq!(&*parse(string(), r#""hello""#).unwrap(), "hello");
        assert_eq!(&*parse(string(), r##"#"world"#"##).unwrap(), "world");
        assert_eq!(&*parse(string(), r##"#"world"#"##).unwrap(), "world");
        assert_eq!(
            &*parse(string(), r####"###"a\n"##b"###"####).unwrap(),
            "a\\n\"##b"
        );
    }

    #[test]
    fn parse_str_err() {
        err_eq!(
            parse(string(), r#""hello"#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed string `\"`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 1}},
                    {"label": "expected `\"`",
                    "span": {"offset": 6, "length": 0}}
                ],
                "related": []
            }]
        }"#
        );
        err_eq!(
            parse(string(), r#""he\u{FFFFFF}llo""#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "converted integer out of range for `char`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "invalid character code",
                    "span": {"offset": 5, "length": 8}}
                ],
                "related": []
            }]
        }"#
        );
        err_eq!(
            parse(string(), r#""he\u{1234567}llo""#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "found `7`, expected `}`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected token",
                    "span": {"offset": 12, "length": 1}}
                ],
                "related": []
            }]
        }"#
        );
        err_eq!(
            parse(string(), r#""he\u{1gh}llo""#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "found `g`, expected `}` or hexadecimal digit",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected character",
                    "span": {"offset": 7, "length": 1}}
                ],
                "related": []
            }]
        }"#
        );
        err_eq!(
            parse(string(), r#""he\x01llo""#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message":
                    "found `x`, expected `\"`, `\\`, `b`, `f`, `n`, `r`, `s`, `t`, `u` or newline",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "invalid escape char",
                    "span": {"offset": 4, "length": 1}}
                ],
                "related": []
            }]
        }"#
        );
        // Tests error recovery
        err_eq!(
            parse(string(), r#""he\u{FFFFFF}l\!lo""#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "converted integer out of range for `char`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "invalid character code",
                    "span": {"offset": 5, "length": 8}}
                ],
                "related": []
            }, {
                "message":
                    "found `!`, expected `\"`, `\\`, `b`, `f`, `n`, `r`, `s`, `t`, `u` or newline",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "invalid escape char",
                    "span": {"offset": 15, "length": 1}}
                ],
                "related": []
            }]
        }"#
        );
    }
    #[test]
    fn parse_raw_str_err() {
        err_eq!(
            parse(string(), r#"#"hello"#),
            r##"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed raw string `#\"`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 2}},
                    {"label": "expected `\"#`",
                    "span": {"offset": 7, "length": 0}}
                ],
                "related": []
            }]
        }"##
        );
        err_eq!(
            parse(string(), r###"#"hello""###),
            r###"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed raw string `#\"`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 2}},
                    {"label": "expected `\"#`",
                    "span": {"offset": 8, "length": 0}}
                ],
                "related": []
            }]
        }"###
        );
        err_eq!(
            parse(string(), r####"###"hello"####),
            r####"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed raw string `###\"`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 4}},
                    {"label": "expected `\"###`",
                    "span": {"offset": 9, "length": 0}}
                ],
                "related": []
            }]
        }"####
        );
        err_eq!(
            parse(string(), r####"###"hello"#world"####),
            r####"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed raw string `###\"`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 0, "length": 4}},
                    {"label": "expected `\"###`",
                    "span": {"offset": 16, "length": 0}}
                ],
                "related": []
            }]
        }"####
        );
    }

    #[test]
    fn parse_multiline_str() {
        // Basic multi-line quoted string
        assert_eq!(
            &*parse(string(), "\"\"\"\n    hello\n    \"\"\"").unwrap(),
            "hello"
        );

        // Multi-line string with dedentation
        assert_eq!(
            &*parse(string(), "\"\"\"\n    line1\n    line2\n    \"\"\"").unwrap(),
            "line1\nline2"
        );

        // Multi-line string with no indent
        assert_eq!(
            &*parse(string(), "\"\"\"\nline1\nline2\n\"\"\"").unwrap(),
            "line1\nline2"
        );

        // Empty multi-line string
        assert_eq!(&*parse(string(), "\"\"\"\n\"\"\"").unwrap(), "");

        // Multi-line string with escape sequences
        assert_eq!(
            &*parse(string(), "\"\"\"\n    hello\\nworld\n    \"\"\"").unwrap(),
            "hello\nworld"
        );

        // Multi-line string with one or two quotes (not three)
        assert_eq!(
            &*parse(string(), "\"\"\"\n    say \"hi\"\n    \"\"\"").unwrap(),
            "say \"hi\""
        );
        assert_eq!(
            &*parse(string(), "\"\"\"\n    say \"\"hi\"\"\n    \"\"\"").unwrap(),
            "say \"\"hi\"\""
        );

        // Multi-line string with whitespace-only lines (become empty)
        assert_eq!(
            &*parse(string(), "\"\"\"\n    line1\n    \n    line2\n    \"\"\"").unwrap(),
            "line1\n\nline2"
        );
    }

    #[test]
    fn parse_multiline_raw_str() {
        // Basic multi-line raw string
        assert_eq!(
            &*parse(string(), "#\"\"\"\n    hello\n    \"\"\"#").unwrap(),
            "hello"
        );

        // Multi-line raw string with multiple hashes
        assert_eq!(
            &*parse(string(), "##\"\"\"\n    hello\n    \"\"\"##").unwrap(),
            "hello"
        );

        // Multi-line raw string preserves backslashes
        assert_eq!(
            &*parse(string(), "#\"\"\"\n    hello\\nworld\n    \"\"\"#").unwrap(),
            "hello\\nworld"
        );

        // Multi-line raw string with quotes inside
        assert_eq!(
            &*parse(string(), "#\"\"\"\n    say \"\"\"hi\"\"\"\n    \"\"\"#").unwrap(),
            "say \"\"\"hi\"\"\""
        );

        // Empty multi-line raw string
        assert_eq!(&*parse(string(), "#\"\"\"\n\"\"\"#").unwrap(), "");
    }

    #[test]
    fn parse_multiline_str_crlf() {
        // CRLF should be normalized to LF
        assert_eq!(
            &*parse(string(), "\"\"\"\r\n    hello\r\n    \"\"\"").unwrap(),
            "hello"
        );
        assert_eq!(
            &*parse(string(), "\"\"\"\r\n    line1\r\n    line2\r\n    \"\"\"").unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn parse_multiline_str_err_no_opening_newline() {
        err_eq!(
            parse(string(), "\"\"\"hello\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "opening delimiter must be immediately followed by a newline",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "must be followed by newline",
                     "span": {"offset": 0, "length": 3}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_raw_str_err_no_opening_newline() {
        err_eq!(
            parse(string(), "##\"\"\"hello\"\"\"##"),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "opening delimiter must be immediately followed by a newline",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "must be followed by newline",
                     "span": {"offset": 0, "length": 5}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_closing_not_on_own_line() {
        err_eq!(
            parse(string(), "\"\"\"\nhello\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "closing delimiter must be on its own line with only whitespace prefix",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "must be on its own line",
                     "span": {"offset": 9, "length": 3}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_raw_str_err_closing_not_on_own_line() {
        err_eq!(
            parse(string(), "##\"\"\"\nhello\"\"\"##"),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "closing delimiter must be on its own line with only whitespace prefix",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "must be on its own line",
                     "span": {"offset": 11, "length": 5}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_insufficient_indent() {
        err_eq!(
            parse(
                string(),
                "\"\"\"\n    hello\n\u{00a0}\u{00a0}world\n    \"\"\""
            ),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "line must start with the same whitespace as the closing delimiter",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "insufficient indentation",
                     "span": {"offset": 14, "length": 4}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn triple_quote_not_single_line() {
        err_eq!(
            parse(string(), "\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "unclosed multi-line string `\"\"\"`",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "opened here",
                     "span": {"offset": 0, "length": 3}},
                     {"label": "expected `\"\"\"`",
                     "span": {"offset": 3, "length": 0}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn hash_triple_quote_is_multiline() {
        err_eq!(
            parse(string(), "#\"\"\"#"),
            r##"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "unclosed multi-line raw string `#\"\"\"`",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "opened here",
                     "span": {"offset": 0, "length": 4}},
                     {"label": "expected `\"\"\"#`",
                     "span": {"offset": 5, "length": 0}}
                 ],
                 "related": []
             }]
         }"##
        );
    }

    #[test]
    fn parse_multiline_str_err_expected_brace_after_u() {
        err_eq!(
            parse(string(), "\"\"\"\n\\uABCD\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "expected '{' after \\u",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 4, "length": 3}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_expected_brace_after_u_eoi() {
        err_eq!(
            parse(string(), "\"\"\"\n\\u\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "expected '{' after \\u",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 4, "length": 2}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_unicode_escape_too_long() {
        err_eq!(
            parse(string(), "\"\"\"\n\\u{1234567}\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "unicode escape too long",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 4, "length": 10}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_invalid_char_in_unicode_escape() {
        err_eq!(
            parse(string(), "\"\"\"\n\\u{12gh}\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "invalid character 'g' in unicode escape",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 4, "length": 6}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_unclosed_unicode_escape() {
        err_eq!(
            parse(string(), "\"\"\"\n\\u{1234\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "unclosed unicode escape",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 4, "length": 7}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_empty_unicode_escape() {
        err_eq!(
            parse(string(), "\"\"\"\n\\u{}\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "empty unicode escape",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 4, "length": 4}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_invalid_unicode_code_point() {
        err_eq!(
            parse(string(), "\"\"\"\n\\u{D800}\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "invalid unicode code point: 55296",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 4, "length": 8}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_invalid_escape_char() {
        err_eq!(
            parse(string(), "\"\"\"\n\\x01\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "invalid escape character: 'x'",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 4, "length": 2}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_trailing_backslash() {
        err_eq!(
            parse(string(), "\"\"\"\nhello\\\n\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "trailing backslash",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 9, "length": 1}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_second_line() {
        err_eq!(
            parse(string(), "\"\"\"\n    line1\n    \\x01\n    \"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "invalid escape character: 'x'",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 18, "length": 2}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_non_ascii_indent() {
        err_eq!(
            parse(string(), "\"\"\"\n \u{00A0}hello\\x01\n \u{00A0}\"\"\""),
            r#"{
             "message": "error parsing KDL",
             "severity": "error",
             "labels": [],
             "related": [{
                 "message": "invalid escape character: 'x'",
                 "severity": "error",
                 "filename": "<test>",
                 "labels": [
                     {"label": "invalid escape sequence",
                     "span": {"offset": 12, "length": 2}}
                 ],
                 "related": []
             }]
         }"#
        );
    }

    #[test]
    fn parse_ident() {
        assert_eq!(&*parse(identifier_string(), "abcdef").unwrap(), "abcdef");
        assert_eq!(
            &*parse(identifier_string(), "xx_cd$yy").unwrap(),
            "xx_cd$yy"
        );
        assert_eq!(&*parse(identifier_string(), "-").unwrap(), "-");
        assert_eq!(&*parse(identifier_string(), "--hello").unwrap(), "--hello");
        assert_eq!(
            &*parse(identifier_string(), "--hello1234").unwrap(),
            "--hello1234"
        );
        assert_eq!(&*parse(identifier_string(), "--1").unwrap(), "--1");
        assert_eq!(&*parse(identifier_string(), "++1").unwrap(), "++1");
        assert_eq!(&*parse(identifier_string(), "-hello").unwrap(), "-hello");
        assert_eq!(&*parse(identifier_string(), "+hello").unwrap(), "+hello");
        assert_eq!(&*parse(identifier_string(), "-A").unwrap(), "-A");
        assert_eq!(&*parse(identifier_string(), "+b").unwrap(), "+b");
        assert_eq!(
            &*parse(identifier_string().then_ignore(ws()), "adef   ").unwrap(),
            "adef"
        );
        assert_eq!(
            &*parse(identifier_string().then_ignore(ws()), "a123@   ").unwrap(),
            "a123@"
        );
        parse(identifier_string(), "1abc").unwrap_err();
        parse(identifier_string(), "-1").unwrap_err();
        parse(identifier_string(), "-1test").unwrap_err();
        parse(identifier_string(), "+1").unwrap_err();
    }

    #[test]
    fn parse_literal() {
        assert_eq!(parse(keyword(), "#true").unwrap(), Literal::Bool(true));
        assert_eq!(parse(keyword(), "#false").unwrap(), Literal::Bool(false));
        assert_eq!(parse(keyword(), "#null").unwrap(), Literal::Null);
        assert_eq!(parse(keyword_number(), "#nan").unwrap(), Literal::Nan);
        assert_eq!(parse(keyword_number(), "#inf").unwrap(), Literal::Inf);
        assert_eq!(parse(keyword_number(), "#-inf").unwrap(), Literal::NegInf);
    }

    #[test]
    fn exclude_keywords() {
        parse(nodes(), "item #true").unwrap();

        // would be nice for this to error with "unexpected keyword #true", but
        // right now its reading it as an improperly formatted raw string.
        err_eq!(
            parse(nodes(), "#true \"item\""),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message":
                    "found `t`, expected `\"` or `#`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected token",
                    "span": {"offset": 1, "length": 1}}
                ],
                "related": []
            }]
        }"#
        );

        err_eq!(
            parse(nodes(), "item #false=#true"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message":
                    "found keyword, expected identifier or string",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected keyword",
                    "span": {"offset": 5, "length": 6}}
                ],
                "related": []
            }]
        }"#
        );

        err_eq!(
            parse(nodes(), "item 2=2"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "numbers cannot be used as property names",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected number",
                    "span": {"offset": 5, "length": 1}}
                ],
                "help": "consider enclosing in double quotes \"..\"",
                "related": []
            }]
        }"#
        );
    }

    #[test]
    fn exclude_bare_keywords() {
        err_eq!(
            parse(nodes(), "item true"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message":
                    "`true` is not allowed as a bare string",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "illegal identifier",
                    "span": {"offset": 5, "length": 4}}
                ],
                "related": []
            }]
        }"#
        );

        err_eq!(
            parse(nodes(), r#"true "item""#),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message":
                    "`true` is not allowed as a bare string",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "illegal identifier",
                    "span": {"offset": 0, "length": 4}}
                ],
                "related": []
            }]
        }"#
        );

        err_eq!(
            parse(nodes(), "item false=#true"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message":
                    "`false` is not allowed as a bare string",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "illegal identifier",
                    "span": {"offset": 5, "length": 5}}
                ],
                "related": []
            }]
        }"#
        );
    }

    #[test]
    fn parse_type() {
        assert_eq!(
            parse(r#type(), "(abcdef)").unwrap(),
            TypeName::from_string("abcdef".into())
        );
        assert_eq!(
            parse(r#type(), "(xx_cd$yy)").unwrap(),
            TypeName::from_string("xx_cd$yy".into())
        );
        parse(r#type(), "(1abc)").unwrap_err();
        assert_eq!(
            parse(r#type(), "( abc)").unwrap(),
            TypeName::from_string("abc".into())
        );
        assert_eq!(
            parse(r#type(), "(abc )").unwrap(),
            TypeName::from_string("abc".into())
        );
    }

    #[test]
    fn parse_type_err() {
        err_eq!(
            parse(r#type(), "(123)"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "found number, expected identifier",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected number",
                    "span": {"offset": 1, "length": 3}}
                ],
                "related": []
            }]
        }"#
        );

        err_eq!(
            parse(r#type(), "(-1)"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "found number, expected identifier",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected number",
                    "span": {"offset": 1, "length": 2}}
                ],
                "related": []
            }]
        }"#
        );
    }

    fn single<T, E: std::fmt::Debug>(r: Result<Vec<T>, E>) -> T {
        let mut v = r.unwrap();
        assert_eq!(v.len(), 1);
        v.remove(0)
    }

    #[test]
    fn parse_node() {
        let nval = single(parse(nodes(), "hello"));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);

        let nval = single(parse(nodes(), "\"123\""));
        assert_eq!(nval.node_name.as_ref(), "123");
        assert_eq!(nval.type_name.as_ref(), None);

        let nval = single(parse(nodes(), "(typ)other"));
        assert_eq!(nval.node_name.as_ref(), "other");
        assert_eq!(nval.type_name.as_ref().map(|x| &***x), Some("typ"));

        let nval = single(parse(nodes(), "(typ) \tafter-ws"));
        assert_eq!(nval.node_name.as_ref(), "after-ws");
        assert_eq!(nval.type_name.as_ref().map(|x| &***x), Some("typ"));

        let nval = single(parse(nodes(), "(\"std::duration\")\"timeout\""));
        assert_eq!(nval.node_name.as_ref(), "timeout");
        assert_eq!(
            nval.type_name.as_ref().map(|x| &***x),
            Some("std::duration")
        );

        let nval = single(parse(nodes(), "hello \"arg1\""));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 1);
        assert_eq!(nval.properties.len(), 0);
        assert_eq!(&*nval.arguments[0].literal, &Literal::String("arg1".into()));

        let nval = single(parse(nodes(), "node \"true\""));
        assert_eq!(nval.node_name.as_ref(), "node");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 1);
        assert_eq!(nval.properties.len(), 0);
        assert_eq!(&*nval.arguments[0].literal, &Literal::String("true".into()));

        let nval = single(parse(nodes(), "hello (string)\"arg1\""));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 1);
        assert_eq!(nval.properties.len(), 0);
        assert_eq!(&***nval.arguments[0].type_name.as_ref().unwrap(), "string");
        assert_eq!(&*nval.arguments[0].literal, &Literal::String("arg1".into()));

        let nval = single(parse(nodes(), "hello (typ) \t\"after whitespace\""));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 1);
        assert_eq!(nval.properties.len(), 0);
        assert_eq!(&***nval.arguments[0].type_name.as_ref().unwrap(), "typ");
        assert_eq!(
            &*nval.arguments[0].literal,
            &Literal::String("after whitespace".into())
        );

        let nval = single(parse(nodes(), "hello key=(string)\"arg1\""));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 0);
        assert_eq!(nval.properties.len(), 1);
        assert_eq!(
            &***nval
                .properties
                .get("key")
                .unwrap()
                .type_name
                .as_ref()
                .unwrap(),
            "string"
        );
        assert_eq!(
            &*nval.properties.get("key").unwrap().literal,
            &Literal::String("arg1".into())
        );

        let nval = single(parse(nodes(), "hello key=\"arg1\""));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 0);
        assert_eq!(nval.properties.len(), 1);
        assert_eq!(
            &*nval.properties.get("key").unwrap().literal,
            &Literal::String("arg1".into())
        );

        let nval = single(parse(nodes(), "parent {\nchild\n}"));
        assert_eq!(nval.node_name.as_ref(), "parent");
        assert_eq!(nval.children().len(), 1);
        assert_eq!(
            nval.children.as_ref().unwrap()[0].node_name.as_ref(),
            "child"
        );

        let nval = single(parse(nodes(), "parent {\nchild1\nchild2\n}"));
        assert_eq!(nval.node_name.as_ref(), "parent");
        assert_eq!(nval.children().len(), 2);
        assert_eq!(
            nval.children.as_ref().unwrap()[0].node_name.as_ref(),
            "child1"
        );
        assert_eq!(
            nval.children.as_ref().unwrap()[1].node_name.as_ref(),
            "child2"
        );

        let nval = single(parse(nodes(), "parent{\nchild3\n}"));
        assert_eq!(nval.node_name.as_ref(), "parent");
        assert_eq!(nval.children().len(), 1);
        assert_eq!(
            nval.children.as_ref().unwrap()[0].node_name.as_ref(),
            "child3"
        );

        let nval = single(parse(nodes(), "parent \"x\"=1 {\nchild4\n}"));
        assert_eq!(nval.node_name.as_ref(), "parent");
        assert_eq!(nval.properties.len(), 1);
        assert_eq!(nval.children().len(), 1);
        assert_eq!(
            nval.children.as_ref().unwrap()[0].node_name.as_ref(),
            "child4"
        );

        let nval = single(parse(nodes(), "parent \"x\" {\nchild4\n}"));
        assert_eq!(nval.node_name.as_ref(), "parent");
        assert_eq!(nval.arguments.len(), 1);
        assert_eq!(nval.children().len(), 1);
        assert_eq!(
            nval.children.as_ref().unwrap()[0].node_name.as_ref(),
            "child4"
        );

        let nval = single(parse(nodes(), "parent \"x\"{\nchild5\n}"));
        assert_eq!(nval.node_name.as_ref(), "parent");
        assert_eq!(nval.arguments.len(), 1);
        assert_eq!(nval.children().len(), 1);
        assert_eq!(
            nval.children.as_ref().unwrap()[0].node_name.as_ref(),
            "child5"
        );

        let nval = single(parse(nodes(), "hello /-\"skip_arg\" \"arg2\""));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 1);
        assert_eq!(nval.properties.len(), 0);
        assert_eq!(&*nval.arguments[0].literal, &Literal::String("arg2".into()));

        let nval = single(parse(nodes(), "hello /- \"skip_arg\" \"arg2\""));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 1);
        assert_eq!(nval.properties.len(), 0);
        assert_eq!(&*nval.arguments[0].literal, &Literal::String("arg2".into()));

        let nval = single(parse(nodes(), "hello prop1=\"1\" /-prop1=\"2\""));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
        assert_eq!(nval.arguments.len(), 0);
        assert_eq!(nval.properties.len(), 1);
        assert_eq!(
            &*nval.properties.get("prop1").unwrap().literal,
            &Literal::String("1".into())
        );

        let nval = single(parse(nodes(), "parent /-{\nchild\n}"));
        assert_eq!(nval.node_name.as_ref(), "parent");
        assert_eq!(nval.children().len(), 0);
    }

    #[test]
    fn parse_node_whitespace() {
        let nval = single(parse(nodes(), "hello  {   }"));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);

        let nval = single(parse(nodes(), "hello  {   }  "));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);

        let nval = single(parse(nodes(), "hello "));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);

        let nval = single(parse(nodes(), "hello   "));
        assert_eq!(nval.node_name.as_ref(), "hello");
        assert_eq!(nval.type_name.as_ref(), None);
    }

    #[test]
    fn parse_node_err() {
        err_eq!(
            parse(nodes(), "hello{"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed curly braces `{`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 5, "length": 1}},
                    {"label": "expected `}`",
                    "span": {"offset": 6, "length": 0}}
                ],
                "related": []
            }]
        }"#
        );

        err_eq!(
            parse(nodes(), "hello world {"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "unclosed curly braces `{`",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "opened here",
                    "span": {"offset": 12, "length": 1}},
                    {"label": "expected `}`",
                    "span": {"offset": 13, "length": 0}}
                ],
                "related": []
            }]
        }"#
        );

        err_eq!(
            parse(nodes(), "1 + 2"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "found number, expected identifier",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected number",
                    "span": {"offset": 0, "length": 1}}
                ],
                "related": []
            }]
        }"#
        );

        err_eq!(
            parse(nodes(), "-1 +2"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "found number, expected identifier",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected number",
                    "span": {"offset": 0, "length": 2}}
                ],
                "related": []
            }]
        }"#
        );
    }

    #[test]
    fn parse_nodes() {
        let nval = parse(nodes(), "parent {\n/-  child\n}").unwrap();
        assert_eq!(nval.len(), 1);
        assert_eq!(nval[0].node_name.as_ref(), "parent");
        assert_eq!(nval[0].children().len(), 0);

        let nval = parse(nodes(), "/-parent {\n  child\n}\nsecond").unwrap();
        assert_eq!(nval.len(), 1);
        assert_eq!(nval[0].node_name.as_ref(), "second");
        assert_eq!(nval[0].children().len(), 0);
    }

    #[test]
    fn parse_number() {
        assert_eq!(
            parse(number(), "12").unwrap(),
            Literal::Int(Integer(Radix::Dec, "12".into()))
        );
        assert_eq!(
            parse(number(), "012").unwrap(),
            Literal::Int(Integer(Radix::Dec, "012".into()))
        );
        assert_eq!(
            parse(number(), "0").unwrap(),
            Literal::Int(Integer(Radix::Dec, "0".into()))
        );
        assert_eq!(
            parse(number(), "-012").unwrap(),
            Literal::Int(Integer(Radix::Dec, "-012".into()))
        );
        assert_eq!(
            parse(number(), "+0").unwrap(),
            Literal::Int(Integer(Radix::Dec, "+0".into()))
        );
        assert_eq!(
            parse(number(), "123_555").unwrap(),
            Literal::Int(Integer(Radix::Dec, "123555".into()))
        );
        assert_eq!(
            parse(number(), "123.555").unwrap(),
            Literal::Decimal(Decimal("123.555".into()))
        );
        assert_eq!(
            parse(number(), "+1_23.5_55E-17").unwrap(),
            Literal::Decimal(Decimal("+123.555E-17".into()))
        );
        assert_eq!(
            parse(number(), "123e+555").unwrap(),
            Literal::Decimal(Decimal("123e+555".into()))
        );
    }

    #[test]
    fn parse_hex_or_octal_or_binary() {
        assert_eq!(
            parse(number(), "0x12").unwrap(),
            Literal::Int(Integer(Radix::Hex, "12".into()))
        );
        assert_eq!(
            parse(number(), "0xab_12").unwrap(),
            Literal::Int(Integer(Radix::Hex, "ab12".into()))
        );
        assert_eq!(
            parse(number(), "-0xab_12").unwrap(),
            Literal::Int(Integer(Radix::Hex, "-ab12".into()))
        );
        assert_eq!(
            parse(number(), "0o17").unwrap(),
            Literal::Int(Integer(Radix::Oct, "17".into()))
        );
        assert_eq!(
            parse(number(), "+0o17").unwrap(),
            Literal::Int(Integer(Radix::Oct, "+17".into()))
        );
        assert_eq!(
            parse(number(), "0b1010_101").unwrap(),
            Literal::Int(Integer(Radix::Bin, "1010101".into()))
        );
    }

    #[test]
    fn parse_dashes() {
        let nval = parse(nodes(), "-").unwrap();
        assert_eq!(nval.len(), 1);
        assert_eq!(nval[0].node_name.as_ref(), "-");
        assert_eq!(nval[0].children().len(), 0);

        let nval = parse(nodes(), "--").unwrap();
        assert_eq!(nval.len(), 1);
        assert_eq!(nval[0].node_name.as_ref(), "--");
        assert_eq!(nval[0].children().len(), 0);

        let nval = parse(nodes(), "--1").unwrap();
        assert_eq!(nval.len(), 1);
        assert_eq!(nval[0].node_name.as_ref(), "--1");
        assert_eq!(nval[0].children().len(), 0);

        let nval = parse(nodes(), "-\n-").unwrap();
        assert_eq!(nval.len(), 2);
        assert_eq!(nval[0].node_name.as_ref(), "-");
        assert_eq!(nval[0].children().len(), 0);
        assert_eq!(nval[1].node_name.as_ref(), "-");
        assert_eq!(nval[1].children().len(), 0);

        let nval = parse(nodes(), "node -1 --x=2").unwrap();
        assert_eq!(nval.len(), 1);
        assert_eq!(nval[0].arguments.len(), 1);
        assert_eq!(nval[0].properties.len(), 1);
        assert_eq!(
            &*nval[0].arguments[0].literal,
            &Literal::Int(Integer(Radix::Dec, "-1".into()))
        );
        assert_eq!(
            &*nval[0].properties.get("--x").unwrap().literal,
            &Literal::Int(Integer(Radix::Dec, "2".into()))
        );
    }

    #[test]
    fn parse_property_ws() {
        let variants = [
            "node a =b",
            "node a= b",
            "node a     =       b",
            "node\ta\t=\tb",
        ];
        for ea_variant in variants {
            let nval = parse(nodes(), ea_variant).unwrap();
            assert_eq!(nval.len(), 1);
            assert_eq!(nval[0].node_name.as_ref(), "node");
            assert_eq!(nval[0].arguments.len(), 0);
            assert_eq!(nval[0].properties.len(), 1);
            assert_eq!(
                &*nval[0].properties.get("a").unwrap().literal,
                &Literal::String("b".into())
            );
        }

        err_eq!(
            parse(nodes(), "node a\\\n=b"),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message": "found `=`, expected `\"`, `#`, `(`, `+`, `-`, `.`, `0`, `;`, `\\`, `{`, `#-inf`, `#false`, `#inf`, `#nan`, `#null`, `#true`, letter, newline, whitespace or end of input",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "unexpected token",
                    "span": {"offset": 8, "length": 1}}
                ],
                "related": []
            }]
        }"#
        );
    }
}
