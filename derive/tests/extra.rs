use knus::ast::{BuiltinType, TypeName};
use knus::span::Span;
use knus::traits::Decode;

#[derive(knus_derive::Decode, Debug, PartialEq)]
struct Child;

#[derive(knus_derive::Decode, Debug, PartialEq)]
struct NodeSpan {
    #[knus(span)]
    span: Span,
    #[knus(argument)]
    name: String,
    #[knus(children)]
    children: Vec<Child>,
}

#[derive(knus_derive::Decode, Debug, PartialEq)]
struct NodeType {
    #[knus(type_name)]
    type_name: String,
}

#[derive(knus_derive::Decode, Debug, PartialEq)]
struct NameAndType {
    #[knus(node_name)]
    node_name: String,
    #[knus(type_name)]
    type_name: Option<TypeName>,
}

fn parse<T: Decode>(text: &str) -> T {
    let mut nodes: Vec<T> = knus::parse("<test>", text).unwrap();
    assert_eq!(nodes.len(), 1);
    nodes.remove(0)
}

#[test]
fn parse_node_span() {
    assert_eq!(
        parse::<NodeSpan>(r#"node "hello""#),
        NodeSpan {
            span: Span(0, 12),
            name: "hello".into(),
            children: Vec::new(),
        }
    );
    assert_eq!(
        parse::<NodeSpan>(r#"   node  "hello"     "#),
        NodeSpan {
            span: Span(3, 21),
            name: "hello".into(),
            children: Vec::new(),
        }
    );
    assert_eq!(
        parse::<NodeSpan>(r#"   node  "hello";     "#),
        NodeSpan {
            span: Span(3, 17),
            name: "hello".into(),
            children: Vec::new(),
        }
    );
    assert_eq!(
        parse::<NodeSpan>(r#"   node  "hello"     {   child;   }"#),
        NodeSpan {
            span: Span(3, 35),
            name: "hello".into(),
            children: vec![Child],
        }
    );
}

#[test]
fn parse_node_type() {
    assert_eq!(
        parse::<NodeType>(r#"(unknown)node {}"#),
        NodeType {
            type_name: "unknown".into()
        }
    );
}

#[test]
fn parse_name_and_type() {
    assert_eq!(
        parse::<NameAndType>(r#"(u32)nodexxx"#),
        NameAndType {
            node_name: "nodexxx".into(),
            type_name: Some(BuiltinType::U32.into()),
        }
    );

    assert_eq!(
        parse::<NameAndType>(r#"yyynode /-{   }"#),
        NameAndType {
            node_name: "yyynode".into(),
            type_name: None,
        }
    );
}
