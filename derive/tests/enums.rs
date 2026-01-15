use knus::Decode;

#[derive(knus_derive::Decode, PartialEq, Debug)]
enum Test {
    A(
        #[knus(property(name = "named"))] String,
        #[knus(argument)] String,
    ),
    B {
        #[knus(property)]
        named: String,
        #[knus(argument)]
        arg: String,
    },
}

fn parse<T: Decode>(text: &str) -> T {
    let mut nodes: Vec<T> = knus::parse("<test>", text).unwrap();
    assert_eq!(nodes.len(), 1);
    nodes.remove(0)
}

#[test]
fn parse_enum() {
    assert_eq!(
        parse::<Test>(r#"a named="aaa" "bbb""#),
        Test::A("aaa".to_owned(), "bbb".to_owned())
    );
    assert_eq!(
        parse::<Test>(r#"b named="aaa" "bbb""#),
        Test::B {
            named: "aaa".to_owned(),
            arg: "bbb".to_owned()
        }
    );
}
