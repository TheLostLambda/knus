use std::path::PathBuf;

use knus::traits::DecodeChildren;

#[derive(knus_derive::Decode, Debug, PartialEq)]
struct Scalars {
    #[knus(child, unwrap(argument))]
    str: String,
    #[knus(child, unwrap(argument))]
    u64: u64,
    #[knus(child, unwrap(argument))]
    f64: f64,
    #[knus(child, unwrap(argument))]
    path: PathBuf,
    #[knus(child, unwrap(argument))]
    boolean: bool,
}

fn parse<T: DecodeChildren>(text: &str) -> T {
    knus::parse("<test>", text).unwrap()
}

#[test]
fn parse_enum() {
    assert_eq!(
        parse::<Scalars>(
            r#"
            str "hello"
            u64 1234
            f64 16.125e+1
            path "/hello/world"
            boolean #true
        "#
        ),
        Scalars {
            str: "hello".into(),
            u64: 1234,
            f64: 161.25,
            path: PathBuf::from("/hello/world"),
            boolean: true,
        }
    );
}
