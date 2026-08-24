#[derive(knus::Decode)]
struct MyStruct {
    #[knus(str, child)]
    field: Vec<String>,
}

fn main() {}
