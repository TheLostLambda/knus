use knus::traits::Decode;

#[derive(knus_derive::Decode, Debug)]
struct AstChildren {
    #[knus(children)]
    children: Vec<knus::ast::SpannedNode>,
}

fn parse<T: Decode>(text: &str) -> T {
    let mut nodes: Vec<T> = knus::parse("<test>", text).unwrap();
    assert_eq!(nodes.len(), 1);
    nodes.remove(0)
}

#[test]
fn parse_node_span() {
    let item = parse::<AstChildren>(r#"node {a; b;}"#);
    assert_eq!(item.children.len(), 2);
}
