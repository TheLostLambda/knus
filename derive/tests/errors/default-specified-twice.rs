#[derive(knus::Decode)]
struct MyStruct {
    #[knus(default, default)]
    field: String,
}

fn main() {}
