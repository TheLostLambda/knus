#[derive(knus::Decode)]
struct MyStruct {
    #[knus(argument, argument)]
    field: String,
}

fn main() {}
