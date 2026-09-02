#[derive(knus::Decode)]
enum Enum {
    #[knus(child)]
    Variant,
}

fn main() {}
