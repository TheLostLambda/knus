use std::collections::{BTreeMap, BTreeSet};

use chumsky::input::Emitter;
use chumsky::prelude::*;

use crate::ast::{Decimal, Integer, Literal, Node, Radix, TypeName, Value};
use crate::ast::{Document, SpannedName, SpannedNode};
use crate::errors::{ParseError, TokenFormat};
use crate::span::{Span, Spanned};

type Error = extra::Err<ParseError>;
type Input<'src> = &'src str;

// A note on parser type sizes: every combinator spells out its whole
// sub-parser in its own type, so a rule used from several places multiplies
// the size of every type above it -- growth here is multiplicative, not
// additive. Rust's pre-1.97 `legacy` symbol mangling writes those types into
// symbol names verbatim, and the macOS linker rejects any symbol over 1 MiB
// with `ld: Assertion failed: (name.size() <= maxLength)`. This grammar has
// been over that limit before. (Rust 1.97 defaults to `v0` mangling, which
// compresses repeats; on 1.97+ the names stay tiny either way.)
//
// Three things keep the types small, in descending order of effect:
//
//  * A generic wrapper must not pass a closure to a combinator. A closure
//    declared in `fn spanned<T, P>(p: P)` is named `spanned::<T, P>::{closure}`
//    and so spells out the whole of `P` a second time; because `spanned` nests,
//    those doublings compound. Hence the free `make_spanned` function.
//  * Prefer a single `filter` over a chain of `or`s in rules that whitespace
//    handling reaches, since those are instantiated dozens of times -- see
//    `newline` and `single_line_comment`.
//  * Mention a large sub-parser once rather than in two alternatives, and give
//    repeated fragments a shared function -- see `maybe_slashdash_node_prop_or_arg`
//    and the `opt_type` / `literal` / `string_expecting_identifier` helpers.
//
// If that is ever not enough, `.boxed()` erases a parser's type for its
// *callers*. The useful place for it is a rule with several callers, not the
// outermost one: boxing at the end of a chain leaves that chain's own type
// untouched. It costs a little parse throughput, so it is a last resort.

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

        // base-node := slashdash? type? node-space* string
        //     (node-space* (node-space | slashdash) node-prop-or-arg)*
        //     (node-space* slashdash node-children)*
        //     (node-space* node-children)?
        //     (node-space* slashdash node-children)*
        //     node-space*

        let base_node = opt_type()
            .then(spanned(string_expecting_identifier()))
            .then(
                maybe_slashdash_node_prop_or_arg()
                    .repeated()
                    .collect::<Vec<PropOrArg>>(),
            )
            // The three children-block lines of `base-node` differ only in
            // whether the block is slashdashed, so they are parsed as one flat
            // repetition and reduced to the single block that survives.
            .then(
                node_space()
                    .repeated()
                    .ignore_then(slashdash().or_not())
                    .then(spanned(braced_nodes))
                    .repeated()
                    .collect::<Vec<(Option<()>, Spanned<Vec<SpannedNode>>)>>()
                    .validate(|blocks, _, emit| {
                        let mut children = None;
                        for (slashdashed, block) in blocks {
                            if slashdashed.is_some() {
                                continue;
                            }
                            if children.is_some() {
                                emit.emit(ParseError::Message {
                                    label: Some("unexpected children block"),
                                    span: block.span,
                                    message: "a node can only have one children block".into(),
                                });
                            }
                            children = Some(block);
                        }
                        children
                    }),
            )
            .then_ignore(node_space().repeated())
            .map(|(((type_name, node_name), line_items), children)| {
                let mut node = Node {
                    type_name,
                    node_name,
                    properties: BTreeMap::new(),
                    arguments: Vec::new(),
                    children,
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

// node-space* (node-space | slashdash) node-prop-or-arg
// Handles the slashdash alternative from base-node, returning PropOrArg::Ignore
// for slashdashed entries. A slashdash may stand in for the whitespace that
// would otherwise have to separate an entry from what precedes it, so both
// `node /-1` and `node/-1` are a node with one commented-out argument.
fn maybe_slashdash_node_prop_or_arg<'src>()
-> impl Parser<'src, Input<'src>, PropOrArg, Error> + Clone {
    choice((
        node_space()
            .repeated()
            .at_least(1)
            .ignore_then(slashdash().or_not()),
        slashdash().map(Some),
    ))
    .then(node_prop_or_arg())
    .map(|(slashdashed, item)| match slashdashed {
        Some(()) => PropOrArg::Ignore,
        None => item,
    })
}

// node-prop-or-arg := prop | value
fn node_prop_or_arg<'src>() -> impl Parser<'src, Input<'src>, PropOrArg, Error> + Clone {
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

    choice((
        spanned(literal())
            .then(equals_value.or_not())
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
        // Typed value like (string)"hello" — always an argument
        value().map(Arg),
    ))
}

// node-terminator := single-line-comment | newline | ';' | eof
//
// `node-children := '{' nodes final-node? '}'` lets the last node inside a
// child block go without a terminator, which is the same thing as letting a
// closing brace terminate it -- so `}` is accepted here without being consumed.
// Outside a child block a stray `}` still fails, just one rule further out.
fn node_terminator<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    choice((
        newline(),
        single_line_comment(),
        just(';').ignored(),
        just('}').ignored().rewind(), // FIXME: Can this be avoided?
        end(),
    ))
}

// value := type? node-space* (string | number | keyword)
fn value<'src>() -> impl Parser<'src, Input<'src>, Value, Error> + Clone {
    opt_type()
        .then(spanned(literal()))
        .map(|(type_name, literal)| Value { type_name, literal })
}

// `type? node-space*`, shared by `base-node` and `value`
fn opt_type<'src>() -> impl Parser<'src, Input<'src>, Option<Spanned<TypeName>>, Error> + Clone {
    spanned(r#type().then_ignore(node_space().repeated())).or_not()
}

// `string | number | keyword`, the tail of both `value` and a prop name.
// The grammar puts `keyword-number` under `number`, but it is matched here
// instead so that it does not pollute the expected-token set of `number`.
fn literal<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    choice((
        keyword(),
        keyword_number(),
        number(),
        string().map(Literal::String),
    ))
}

// The grammar uses plain `string` for node names and type annotations, but we
// also try to match numbers so we can report "found number, expected
// identifier" instead of a bare parse failure.
fn string_expecting_identifier<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
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
}

// type := '(' node-space* string node-space* ')'
fn r#type<'src>() -> impl Parser<'src, Input<'src>, TypeName, Error> + Clone {
    string_expecting_identifier()
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
        // dotted-ident: sign? '.' ((identifier-char - digit) identifier-char*)?
        // Tried before signed-ident, which would otherwise match just the sign
        // of `+.` and leave the dot behind.
        dotted_ident(),
        // signed-ident: sign ((identifier-char - digit - '.') identifier-char*)?
        signed_ident(),
    ))
    .map(|v: &str| Box::<str>::from(v))
    .try_map(|s, span| {
        // disallowed-keyword-identifiers
        const KEYWORDS: [&str; 6] = ["#true", "#false", "#null", "#nan", "#inf", "#-inf"];
        match &s[..] {
            "true" | "false" | "null" | "nan" | "inf" | "-inf" => Err(ParseError::Message {
                label: Some("illegal identifier"),
                span: span.into(),
                message: format!("`{s}` is not allowed as a bare string"),
            }),
            _ => match KEYWORDS.iter().find(|&&kw| kw == &s[..]) {
                Some(&kw) => Err(ParseError::Unexpected {
                    label: Some("keyword"),
                    span: span.into(),
                    found: TokenFormat::Token(kw),
                    expected: expected_kind("identifier"),
                }),
                None => Ok(s),
            },
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
        .filter(is_identifier_char)
        .map_err(|e: ParseError| e.with_expected_kind("letter"))
}

fn is_identifier_char(c: &char) -> bool {
    !matches!(c,
        // disallowed-literal-code-points (U+0000-0008, U+000E-001F)
        // + unicode-space (U+0009 tab, U+0020 space)
        // + newline (U+000A-000D)
        '\u{0000}'..='\u{0020}' |
        // [\\/(){};\[\]"#=]
        '\\'|'/'|'('|')'|'{'|'}'|';'|'['|']'|'='|'"'|'#' |
        // disallowed-literal-code-points: U+007F (Delete)
        '\u{007F}' |
        // newline: U+0085 (NEL)
        '\u{0085}' |
        // unicode-space
        '\u{00a0}' | '\u{1680}' |
        '\u{2000}'..='\u{200A}' |
        // disallowed-literal-code-points: direction control characters
        '\u{200E}'..='\u{200F}' |
        '\u{202A}'..='\u{202E}' |
        // unicode-space
        '\u{202F}' | '\u{205F}' |
        // disallowed-literal-code-points: direction control characters
        '\u{2066}'..='\u{2069}' |
        // newline: U+2028 (LS), U+2029 (PS)
        '\u{2028}' | '\u{2029}' |
        // unicode-space + disallowed-literal-code-points: U+FEFF (BOM)
        '\u{3000}' | '\u{FEFF}'
    )
}

// (identifier-char - digit)
fn id_sans_dig<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| is_identifier_char(c) && !c.is_ascii_digit())
        .map_err(|e: ParseError| e.with_expected_kind("letter"))
}

// (identifier-char - digit - '.')
fn id_sans_dig_point<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| is_identifier_char(c) && !c.is_ascii_digit() && *c != '.')
        .map_err(|e: ParseError| e.with_expected_kind("letter"))
}

// (identifier-char - digit - sign - '.')
fn id_sans_sign_dig_point<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>()
        .filter(|c| is_identifier_char(c) && !c.is_ascii_digit() && !matches!(c, '.' | '+' | '-'))
        .map_err(|e: ParseError| e.with_expected_kind("letter"))
}

// Single-line quoted string: '"' single-line-string-body '"'
fn single_line_quoted_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    // single-line-string-body := (string-character - newline)*
    // A whitespace escape stands for nothing at all, hence the `Option`: it is
    // one of the alternatives, but the only one that yields no character.
    let character = choice((
        any::<_, Error>()
            .filter(|c| !matches!(c, '"' | '\\') && !is_newline_char(c))
            .map(Some),
        just('\\').ignore_then(escape()).map(Some),
        ws_escape().to(None),
    ));

    // Single quote only - reject """ which is multi-line syntax
    just('"')
        .then_ignore(just("\"\"").not().rewind())
        .ignore_then(
            character
                .repeated()
                .collect::<Vec<Option<char>>>()
                .map(|chars| chars.into_iter().flatten().collect::<String>())
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

// ws-escape := '\\' (unicode-space | newline)+
fn ws_escape<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just('\\')
        .then(unicode_space().or(newline()).repeated().at_least(1))
        .ignored()
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
        // multi-line-string-body := ('"' ^'"' | '""' ^'"' | string-character)*?
        choice((
            // An escape is taken whole, so that the `"` of `\"` cannot be read
            // as part of the closing delimiter, nor the second `\` of `\\` as
            // the start of another escape.
            just('\\').then(any()).ignored(),
            // One or two double-quotes, as long as a third does not follow.
            just("\"\"").then_ignore(just('"').not().rewind()).ignored(),
            just('"').then_ignore(just('"').not().rewind()).ignored(),
            // Regular character (not quote)
            none_of('"').ignored(),
        ))
        .repeated()
        .to_slice()
        .then_ignore(just("\"\"\""))
        .validate(|content: &str, extras, emit| {
            let span = Span::from(extras.span());

            // The spec requires the dedent to happen *after* whitespace
            // escapes are resolved but *before* any other escape is: a `\` at
            // the end of a line swallows the next line's indentation, and so
            // can change what the closing line's prefix even is.
            let (resolved, map) = resolve_ws_escapes(content, false);

            let (dedented, indent_len) = match dedent_multiline_string(&resolved) {
                Ok(d) => d,
                Err(e) => {
                    emit_multiline_dedent_error(remap(e, &map), span, 3, 3, emit);
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
                    let error_span = Span(
                        span.0 + map_offset(&map, content_start),
                        span.0 + map_offset(&map, content_end),
                    );
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
fn raw_string_quotes<'src>()
-> impl Parser<'src, Input<'src>, Box<str>, extra::Full<ParseError, (), usize>> + Clone {
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

                // A raw string has no escapes, so only newline normalization
                // stands between its source text and the dedent.
                let (resolved, map) = resolve_ws_escapes(content, true);
                match dedent_multiline_string(&resolved) {
                    Ok((dedented, _indent_len)) => dedented.into(),
                    Err(e) => {
                        let e = remap(e, &map);
                        emit_multiline_dedent_error(e, span, hash_num + 3, 3 + hash_num, emit);
                        "".into()
                    }
                }
            }),
    );

    // Single-line: "..."
    // single-line-raw-string-char := unicode - newline
    let single_line = just('"')
        .then_ignore(just("\"\"").not().rewind())
        .ignore_then(
            any()
                .filter(|c: &char| !is_newline_char(c))
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
    // `^newline*` is expressed as a character filter rather than
    // `any().and_is(newline().not())` so that `newline` is instantiated once
    // here instead of twice; see the note on `newline` itself.
    begin_comment('/')
        .ignore_then(
            any::<_, Error>()
                .filter(|c: &char| !is_newline_char(c))
                .repeated(),
        )
        .then(newline().or(end()))
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
    // Matching the single-character newlines with one `filter` rather than a
    // chain of `or`s keeps this parser's *type* small. `newline` is reached
    // from `ws`, `line-space`, `node-space` and `node-terminator`, so it is
    // instantiated dozens of times and its size is multiplied throughout.
    just('\r')
        .then_ignore(just('\n').or_not()) // CR, or CRLF
        .ignored()
        .or(any::<_, Error>()
            .filter(|c: &char| is_newline_char(c) && *c != '\r')
            .ignored())
        .map_err(|e: ParseError| e.with_expected_kind("newline"))
}

fn is_newline_char(c: &char) -> bool {
    matches!(
        c,
        '\r' |          // Carriage return
        '\n' |          // Line feed
        '\x0C' |        // Form feed
        '\x0B' |        // Vertical tab
        '\u{0085}' |    // Next line
        '\u{2028}' |    // Line separator
        '\u{2029}' // Paragraph separator
    )
}

// line-space := node-space | newline | single-line-comment
fn line_space<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    newline().or(ws()).or(single_line_comment()).or(escline())
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
    // Deliberately a free function, not a closure: a closure's type name
    // would include `P`, doubling the length of the resulting parser's
    // type name, which can overflow the linker's symbol-length limit.
    p.map_with(make_spanned)
}

fn make_spanned<'src, T>(
    value: T,
    e: &mut chumsky::input::MapExtra<'src, '_, Input<'src>, Error>,
) -> Spanned<T> {
    Spanned {
        span: e.span().into(),
        value,
    }
}

// --- Helper functions for multi-line strings ---

/// Normalize literal newlines to LF and discard whitespace escapes, returning
/// the result along with a map from each of its bytes back to the byte of `s`
/// that byte came from (plus one final entry for the end).
///
/// Both of those steps move the text around, so an error found afterwards --
/// in the dedent, or in the escapes that are left -- needs the map to point at
/// the right place in the source. `raw` turns off the escape handling for raw
/// strings, which have none.
fn resolve_ws_escapes(s: &str, raw: bool) -> (String, Vec<usize>) {
    fn keep(out: &mut String, map: &mut Vec<usize>, at: usize, c: char) {
        for _ in 0..c.len_utf8() {
            map.push(at);
        }
        out.push(c);
    }
    fn is_escapable_ws(c: char) -> bool {
        is_kdl_ws(c) || is_newline_char(&c)
    }

    let mut out = String::with_capacity(s.len());
    let mut map = Vec::with_capacity(s.len() + 1);
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            // CRLF and CR alike collapse to a single LF, as do the other
            // literal newlines. Newlines written as `\n` are left alone.
            '\r' => {
                if chars.peek().is_some_and(|&(_, next)| next == '\n') {
                    chars.next();
                }
                map.push(i);
                out.push('\n');
            }
            '\x0B' | '\x0C' | '\u{0085}' | '\u{2028}' | '\u{2029}' => {
                map.push(i);
                out.push('\n');
            }
            '\\' if !raw => match chars.peek() {
                // ws-escape := '\\' (unicode-space | newline)+ -- dropped whole.
                Some(&(_, next)) if is_escapable_ws(next) => {
                    while chars.peek().is_some_and(|&(_, n)| is_escapable_ws(n)) {
                        chars.next();
                    }
                }
                // Every other escape is copied over as a unit, so that the
                // second `\` of `\\` cannot start a whitespace escape.
                Some(&(j, next)) => {
                    chars.next();
                    keep(&mut out, &mut map, i, '\\');
                    keep(&mut out, &mut map, j, next);
                }
                None => keep(&mut out, &mut map, i, '\\'),
            },
            _ => keep(&mut out, &mut map, i, c),
        }
    }
    map.push(s.len());
    (out, map)
}

/// Translate an offset into the string `resolve_ws_escapes` produced back into
/// an offset in the text it was given.
fn map_offset(map: &[usize], offset: usize) -> usize {
    map.get(offset)
        .or_else(|| map.last())
        .copied()
        .unwrap_or(offset)
}

/// The same translation, for the offsets a dedent error carries.
fn remap(e: MultilineStringError, map: &[usize]) -> MultilineStringError {
    match e {
        MultilineStringError::InsufficientIndent { offset, length } => {
            let start = map_offset(map, offset);
            MultilineStringError::InsufficientIndent {
                offset: start,
                length: map_offset(map, offset + length) - start,
            }
        }
        other => other,
    }
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
/// Takes the string as `resolve_ws_escapes` left it, so newlines are already
/// LF and no whitespace escape remains to be mistaken for content.
fn dedent_multiline_string(normalized: &str) -> Result<(String, usize), MultilineStringError> {
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
                // A whitespace escape discards the `\` and the whitespace and
                // leaves nothing in its place. For a multi-line string these
                // are already gone by now, since they have to be resolved
                // before the dedent.
                Some((_, c)) if c == ' ' || c == '\t' || c == '\n' || is_kdl_ws(c) => {
                    while let Some(&(_, next)) = chars.peek() {
                        if next == ' ' || next == '\t' || next == '\n' || is_kdl_ws(next) {
                            chars.next();
                        } else {
                            break;
                        }
                    }
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
            buf.clear();
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
        // Missing newline after opening delimiter: """hello"""
        // Points to opening """ (offset 0, length 3)
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
        // Missing newline after opening delimiter: ##"""hello"""##
        // Points to opening ##""" (offset 0, length 5)
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
        // Closing delimiter not on its own line: """\nhello"""
        // Points to closing """ (offset 9, length 3)
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
        // Closing delimiter not on its own line: ##"""\nhello"""##
        // Points to closing """## (offset 11, length 5)
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
        // Insufficient indentation with non-ASCII whitespace: """\n    hello\n\u{00a0}\u{00a0}world\n    """
        // Uses two non-breaking spaces (\u{00a0}, 2 bytes each in UTF-8) as the bad indentation
        // Points to the whitespace prefix (offset 14, length 4 bytes)
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
        // """ should not be parsed as a single-line string
        // It is treated as a multi-line string opening, which then fails due to missing structure
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
        // #"""# should be treated as invalid multi-line raw string, not as single-line with content ""
        // The old behavior was: #"""# = single-line raw string with content """
        // The new behavior is: #"""...."""# is multi-line, so #"""# without proper structure is an error
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
        // \u without { in multi-line string - points to \uA (the wrong char after \u)
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
        // \u without { in multi-line string - points to \uA (the wrong char after \u)
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
        // More than 6 hex digits in unicode escape - spans the whole escape including excess digit
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
        // Invalid character 'g' in unicode escape - spans up to and including the invalid char
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
        // Unclosed unicode escape - \u{1234 without closing }
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
        // Empty unicode escape \u{} - spans the whole escape
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
        // Invalid unicode code point (surrogate) - spans the whole escape
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
        // Invalid escape character \x - spans the backslash and invalid char
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
        // A backslash at the end of the last content line escapes the newline
        // that the closing delimiter needs to have in front of it, leaving
        // `"""` on the same line as `hello` -- which the spec calls out as
        // illegal. The span is the closing delimiter that ended up misplaced.
        err_eq!(
            parse(string(), "\"\"\"\nhello\\\n\"\"\""),
            r#"{
            "message": "error parsing KDL",
            "severity": "error",
            "labels": [],
            "related": [{
                "message":
                    "closing delimiter must be on its own line with only whitespace prefix",
                "severity": "error",
                "filename": "<test>",
                "labels": [
                    {"label": "must be on its own line",
                    "span": {"offset": 11, "length": 3}}
                ],
                "related": []
            }]
        }"#
        );
    }

    #[test]
    fn parse_multiline_str_err_second_line() {
        // Error on second line of multi-line string
        // Input: """\n    line1\n    \x01\n    """
        // The \x is at source offset 18-19 (after """, newline, indent, line1, newline, indent)
        // With correct span calculation, offset should be 18, length 2
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
        // Test with non-ASCII whitespace in indentation
        // Both content line and closing line use: ASCII space + non-breaking space (U+00A0)
        // This verifies byte-based indent_len works correctly with multi-byte whitespace
        //
        // Byte layout:
        // - bytes 0-2: """
        // - byte 3: \n
        // - byte 4: ASCII space
        // - bytes 5-6: U+00A0 (NBSP, 2 bytes in UTF-8)
        // - bytes 7-11: hello
        // - byte 12: \
        // - byte 13: x
        // - bytes 14-15: 01
        // - byte 16: \n
        // - byte 17: ASCII space
        // - bytes 18-19: U+00A0
        // - bytes 20-22: """
        //
        // indent_len = 3 bytes (1 space + 2 for NBSP)
        // The \x escape error should be at source offset 12, length 2
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
                "message": "found `=`, expected `\"`, `#`, `(`, `+`, `-`, `.`, `0`, `;`, `\\`, `{`, `}`, `#-inf`, `#false`, `#inf`, `#nan`, `#null`, `#true`, letter, newline, whitespace or end of input",
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
