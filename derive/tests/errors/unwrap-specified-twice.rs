#[derive(knus::Decode)]
struct MyStruct {
    #[knus(unwrap(), unwrap())]
    field: String,
}

fn main() {}
