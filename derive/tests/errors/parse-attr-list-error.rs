#[derive(knus::Decode)]
struct Struct {
    #[knus(error)]
    field: String,
}

fn main() {}
