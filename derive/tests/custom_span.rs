use knus::decode::Context;
use knus::span::Span;
use knus::traits::{Decode, DecodeSpan};

#[derive(Debug, PartialEq)]
struct MySpan {
    start: usize,
    end: usize,
}

impl DecodeSpan for MySpan {
    fn decode_span(span: &Span, _ctx: &mut Context) -> Self {
        MySpan {
            start: span.0,
            end: span.1,
        }
    }
}

#[derive(knus_derive::Decode, Debug, PartialEq)]
struct NodeSpan {
    #[knus(span)]
    span: MySpan,
}

fn parse<T: Decode>(text: &str) -> T {
    let mut nodes: Vec<T> = knus::parse("<test>", text).unwrap();
    assert_eq!(nodes.len(), 1);
    nodes.remove(0)
}

#[test]
fn parse_node_span() {
    assert_eq!(
        parse::<NodeSpan>(r#"node"#),
        NodeSpan {
            span: MySpan { start: 0, end: 4 },
        }
    );
    assert_eq!(
        parse::<NodeSpan>(r#"   node  "#),
        NodeSpan {
            span: MySpan { start: 3, end: 9 },
        }
    );
}
