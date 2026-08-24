#[derive(knus::Decode)]
struct MyStruct {
    #[knus(str, bytes)]
    field: String,
}

fn main() {}
