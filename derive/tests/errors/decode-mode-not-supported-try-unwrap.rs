#[derive(knus::Decode)]
struct MyStruct {
    #[knus(str, child, unwrap())]
    field: Vec<String>,
}

fn main() {}
