macro_rules! make_wrappers {
    ($($Wrapper:ident($Left:ident, $Right:ident)),* $(,)?) => {
        $(
            #[derive(knus::Decode, Debug, Eq, PartialEq)]
            pub struct $Left {
                #[knus(argument)]
                pub left: u32,
                #[knus(argument)]
                pub right: u32,
            }

            #[derive(knus::Decode, Debug, Eq, PartialEq)]
            pub struct $Right {
                #[knus(argument)]
                pub left: u32,
                #[knus(argument)]
                pub right: u32,
            }

            #[derive(knus::Decode, Debug, Eq, PartialEq)]
            pub enum $Wrapper {
                $Left($Left),
                $Right($Right)
            }
        )*
    }
}

mod letters {
    make_wrappers! {
        Letter1(A, B),
        Letter2(C, D),
        Letter3(E, F),
        Letter4(G, H),
        Letter5(I, J)
    }
}

use letters::*;

#[derive(knus::Decode, Debug, Eq, PartialEq)]
enum Letter {
    /// Reference inner using path
    #[knus(transparent)]
    LetterA(letters::Letter1),
    /// Uses the same name as the inner variant
    #[knus(transparent)]
    Letter2(Letter2),
    /// Inner variant is `Option<...>`
    #[knus(transparent)]
    Optional(Option<Letter3>),
    /// Inner variant is `Option<...>`
    /// And reference with path
    #[knus(transparent)]
    OptionalWithPath(Option<letters::Letter4>),
}

#[test]
fn test() {
    use Letter as L;

    assert_eq!(
        knus::parse::<Vec<Letter>>(
            "test.kdl",
            "
            a 1 2
            b 3 4

            c 5 6
            d 7 8

            e 9 10
            f 11 12

            g 13 14
            h 10 20
        ",
        )
        .unwrap(),
        vec![
            L::LetterA(Letter1::A(A { left: 1, right: 2 })),
            L::LetterA(Letter1::B(B { left: 3, right: 4 })),
            //
            L::Letter2(Letter2::C(C { left: 5, right: 6 })),
            L::Letter2(Letter2::D(D { left: 7, right: 8 })),
            //
            L::Optional(Some(Letter3::E(E { left: 9, right: 10 }))),
            L::Optional(Some(Letter3::F(F {
                left: 11,
                right: 12,
            }))),
            //
            L::OptionalWithPath(Some(Letter4::G(G {
                left: 13,
                right: 14,
            }))),
            L::OptionalWithPath(Some(Letter4::H(H {
                left: 10,
                right: 20,
            }))),
        ]
    );
}
