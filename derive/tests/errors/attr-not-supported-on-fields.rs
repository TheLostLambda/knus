#[derive(knus::Decode)]
struct MyStruct {
    #[knus(skip)]
    field: String,
}

fn main() {}
