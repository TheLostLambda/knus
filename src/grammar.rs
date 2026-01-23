use std::collections::{BTreeMap, BTreeSet};

use chumsky::prelude::*;

use crate::ast::{Decimal, Integer, Literal, Node, Radix, TypeName, Value};
use crate::ast::{Document, SpannedName, SpannedNode};
use crate::errors::{ParseError, TokenFormat};
use crate::span::{Span, Spanned};

type Error = extra::Err<ParseError>;
type Input<'src> = &'src str;

fn begin_comment<'src>(which: char) -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just('/')
        .map_err(|e: ParseError| e.with_no_expected())
        .ignore_then(just(which).ignored())
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

fn ws_char<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
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

fn id_char<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
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

fn ws<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    ws_char()
        .repeated()
        .at_least(1)
        .ignored()
        .or(ml_comment())
        .map_err(|e| e.with_expected_kind("whitespace"))
}

fn comment<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
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

fn ml_comment<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
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

fn raw_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    let matching_hashes = just('#')
        .repeated()
        .configure(|cfg, hash_num| cfg.exactly(*hash_num));
    just('#')
        .repeated()
        .at_least(1)
        .count()
        .then_ignore(just('"'))
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

fn string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    choice((raw_string(), escaped_string()))
}

fn expected_kind(s: &'static str) -> BTreeSet<TokenFormat> {
    [TokenFormat::Kind(s)].into_iter().collect()
}

fn esc_char<'src>() -> impl Parser<'src, Input<'src>, char, Error> + Clone {
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

fn escaped_string<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    just('"').ignore_then(
        choice((
            none_of(['"', '\\']),
            just('\\').ignore_then(esc_char()),
            // ws-escape
            just('\\')
                .then(ws_char().or(newline()).repeated().at_least(1))
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

fn bare_ident<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    let sign = just('+').or(just('-'));
    choice((
        // unambiguous-ident
        id_sans_sign_dig_point()
            .then(id_char().repeated())
            .to_slice(),
        // signed-ident
        sign.then(id_sans_dig_point().then(id_char().repeated()).or_not())
            .to_slice(),
        // dotted-ident
        sign.or_not()
            .then(just('.'))
            .then(id_sans_dig().then(id_char().repeated()).or_not())
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

fn ident<'src>() -> impl Parser<'src, Input<'src>, Box<str>, Error> + Clone {
    choice((
        // match -123 so `-` will not be treated as an ident by backtracking
        number().map(Err),
        bare_ident().map(Ok),
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

fn digit<'src>(radix: u32) -> impl Parser<'src, Input<'src>, char, Error> + Clone {
    any::<_, Error>().filter(move |c: &char| c.is_digit(radix))
}

fn digits<'src>(radix: u32) -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    any::<_, Error>()
        .filter(move |c: &char| c == &'_' || c.is_digit(radix))
        .repeated()
}

fn decimal_number<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    just('-')
        .or(just('+'))
        .or_not()
        .then(digit(10))
        .then(digits(10))
        .then(just('.').then(digit(10)).then(digits(10)).or_not())
        .then(
            just('e')
                .or(just('E'))
                .then(just('-').or(just('+')).or_not())
                .then(digits(10))
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

fn radix_number<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    just('-')
        .or(just('+'))
        .or_not()
        .then_ignore(just('0'))
        .then(choice((
            just('b')
                .ignore_then(digit(2).then(digits(2)).to_slice())
                .map(|s| (Radix::Bin, s)),
            just('o')
                .ignore_then(digit(8).then(digits(8)).to_slice())
                .map(|s| (Radix::Oct, s)),
            just('x')
                .ignore_then(digit(16).then(digits(16)).to_slice())
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

fn number<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    radix_number().or(decimal_number())
}

fn literal<'src>() -> impl Parser<'src, Input<'src>, Literal, Error> + Clone {
    // Check for `ident` last, because `ident` first checks for numbers,
    // and it can confuse keywords with raw strings.
    choice((keyword(), number(), ident().map(Literal::String)))
}

fn type_name<'src>() -> impl Parser<'src, Input<'src>, TypeName, Error> + Clone {
    ident()
        .delimited_by(
            just('(').then(ws_char().repeated()),
            ws_char().repeated().then(just(')')),
        )
        .map(TypeName::from_string)
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

fn esc_line<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    just('\\')
        .ignore_then(ws().repeated())
        .ignore_then(comment().or(newline()).or(end()))
}

fn node_space<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    ws().or(esc_line())
}

fn node_terminator<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    choice((newline(), comment(), just(';').ignored(), end()))
}

#[derive(Clone)]
enum PropOrArg {
    Prop(SpannedName, Value),
    Arg(Value),
    Ignore,
}

fn type_name_value<'src>() -> impl Parser<'src, Input<'src>, Value, Error> + Clone {
    spanned(type_name().then_ignore(ws_char().repeated()))
        .then(spanned(literal()))
        .map(|(type_name, literal)| Value {
            type_name: Some(type_name),
            literal,
        })
}

fn value<'src>() -> impl Parser<'src, Input<'src>, Value, Error> + Clone {
    type_name_value().or(spanned(literal()).map(|literal| Value {
        type_name: None,
        literal,
    }))
}

fn prop_or_arg_inner<'src>() -> impl Parser<'src, Input<'src>, PropOrArg, Error> + Clone {
    use PropOrArg::*;

    let equals_value = ws_char()
        .repeated()
        .then(just('='))
        .then(ws_char().repeated())
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
        spanned(bare_ident())
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

fn prop_or_arg<'src>() -> impl Parser<'src, Input<'src>, PropOrArg, Error> + Clone {
    begin_comment('-')
        .ignore_then(line_space().repeated())
        .ignore_then(prop_or_arg_inner())
        .to(PropOrArg::Ignore)
        .or(prop_or_arg_inner())
}

fn line_space<'src>() -> impl Parser<'src, Input<'src>, (), Error> + Clone {
    newline().or(ws()).or(comment())
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

        let node = spanned(type_name().then_ignore(ws_char().repeated()))
            .or_not()
            .then(spanned(ident()))
            .then(
                node_space()
                    .repeated()
                    .at_least(1)
                    .ignore_then(prop_or_arg())
                    .repeated()
                    .collect::<Vec<PropOrArg>>(),
            )
            .then(
                node_space()
                    .repeated()
                    .ignore_then(
                        begin_comment('-')
                            .then_ignore(line_space().repeated())
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
            .then_ignore(line_space().repeated())
            .or_not()
            .then(spanned(node))
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

pub(crate) fn document<'src>() -> impl Parser<'src, Input<'src>, Document, Error> {
    just('\u{FEFF}')
        .or_not()
        .ignore_then(nodes())
        .map(|nodes| Document { nodes })
}

#[cfg(test)]
mod test {
    use super::{Error, Input};
    use super::{comment, ident, literal, ml_comment, string, type_name, ws};
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
        parse(comment(), "//hello").unwrap();
        parse(comment(), "//hello\n").unwrap();
        parse(ml_comment(), "/*nothing*/").unwrap();
        parse(ml_comment(), "/*nothing**/").unwrap();
        parse(ml_comment(), "/*no*thing*/").unwrap();
        parse(ml_comment(), "/*no/**/thing*/").unwrap();
        parse(ml_comment(), "/*no/*/**/*/thing*/").unwrap();
        parse(ws().then(comment()), "   // hello").unwrap();
        parse(
            ws().then(comment()).then(ws()).then(comment()),
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
    fn parse_ident() {
        assert_eq!(&*parse(ident(), "abcdef").unwrap(), "abcdef");
        assert_eq!(&*parse(ident(), "xx_cd$yy").unwrap(), "xx_cd$yy");
        assert_eq!(&*parse(ident(), "-").unwrap(), "-");
        assert_eq!(&*parse(ident(), "--hello").unwrap(), "--hello");
        assert_eq!(&*parse(ident(), "--hello1234").unwrap(), "--hello1234");
        assert_eq!(&*parse(ident(), "--1").unwrap(), "--1");
        assert_eq!(&*parse(ident(), "++1").unwrap(), "++1");
        assert_eq!(&*parse(ident(), "-hello").unwrap(), "-hello");
        assert_eq!(&*parse(ident(), "+hello").unwrap(), "+hello");
        assert_eq!(&*parse(ident(), "-A").unwrap(), "-A");
        assert_eq!(&*parse(ident(), "+b").unwrap(), "+b");
        assert_eq!(
            &*parse(ident().then_ignore(ws()), "adef   ").unwrap(),
            "adef"
        );
        assert_eq!(
            &*parse(ident().then_ignore(ws()), "a123@   ").unwrap(),
            "a123@"
        );
        parse(ident(), "1abc").unwrap_err();
        parse(ident(), "-1").unwrap_err();
        parse(ident(), "-1test").unwrap_err();
        parse(ident(), "+1").unwrap_err();
    }

    #[test]
    fn parse_literal() {
        assert_eq!(parse(literal(), "#true").unwrap(), Literal::Bool(true));
        assert_eq!(parse(literal(), "#false").unwrap(), Literal::Bool(false));
        assert_eq!(parse(literal(), "#null").unwrap(), Literal::Null);
        assert_eq!(parse(literal(), "#nan").unwrap(), Literal::Nan);
        assert_eq!(parse(literal(), "#inf").unwrap(), Literal::Inf);
        assert_eq!(parse(literal(), "#-inf").unwrap(), Literal::NegInf);
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
            parse(type_name(), "(abcdef)").unwrap(),
            TypeName::from_string("abcdef".into())
        );
        assert_eq!(
            parse(type_name(), "(xx_cd$yy)").unwrap(),
            TypeName::from_string("xx_cd$yy".into())
        );
        parse(type_name(), "(1abc)").unwrap_err();
        assert_eq!(
            parse(type_name(), "( abc)").unwrap(),
            TypeName::from_string("abc".into())
        );
        assert_eq!(
            parse(type_name(), "(abc )").unwrap(),
            TypeName::from_string("abc".into())
        );
    }

    #[test]
    fn parse_type_err() {
        err_eq!(
            parse(type_name(), "(123)"),
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
            parse(type_name(), "(-1)"),
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
    fn parse_radix_number() {
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
