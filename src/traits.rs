//! Traits used for the library
//!
//! Most users will never implement these manually. See
//! [`Decode`](derive@crate::Decode)` and
//! [`DecodeScalar`](derive@crate::DecodeScalar) for a
//! documentation of the derives to implement these traits.
use crate::ast::{Literal, SpannedNode, TypeName, Value};
use crate::decode::Context;
use crate::errors::DecodeError;
use crate::span::{Span, Spanned};

/// Trait to decode KDL node from the AST
pub trait Decode: Sized {
    /// Decodes the node from the ast
    fn decode_node(node: &SpannedNode, ctx: &mut Context) -> Result<Self, DecodeError>;
}

/// Trait to decode children of the KDL node, mostly used for root document
pub trait DecodeChildren: Sized {
    /// Decodes from a list of chidren ASTs
    fn decode_children(nodes: &[SpannedNode], ctx: &mut Context) -> Result<Self, DecodeError>;
}

/// The trait is implemented for structures that can be used as part of other
/// structs
///
/// The type of field that `#[knus(flatten)]` is used for should implement
/// this trait. It is automatically implemented by `#[derive(knus::Decode)]`
/// by structures that have only optional properties and children (no
/// arguments).
pub trait DecodePartial: Sized {
    /// The method is called when unknown child is encountered by parent
    /// structure
    ///
    /// Returns `Ok(true)` if the child is "consumed" (i.e. stored in this
    /// structure).
    fn insert_child(&mut self, node: &SpannedNode, ctx: &mut Context) -> Result<bool, DecodeError>;
    /// The method is called when unknown property is encountered by parent
    /// structure
    ///
    /// Returns `Ok(true)` if the property is "consumed" (i.e. stored in this
    /// structure).
    fn insert_property(
        &mut self,
        name: &Spanned<Box<str>>,
        value: &Value,
        ctx: &mut Context,
    ) -> Result<bool, DecodeError>;
}

/// The trait that decodes scalar value and checks its type
pub trait DecodeScalar: Sized {
    /// Typecheck the value
    ///
    /// This method can only emit errors to the context in type mismatch case.
    /// Errors emitted to the context are considered fatal once the whole data
    /// is processed but non fatal when encountered. So even if there is a type
    /// in type name we can proceed and try parsing actual value.
    fn type_check(type_name: &Option<Spanned<TypeName>>, ctx: &mut Context);
    /// Decode value without typecheck
    ///
    /// This can be used by wrappers to parse some know value but use a
    /// different typename (kinda emulated subclassing)
    fn raw_decode(value: &Spanned<Literal>, ctx: &mut Context) -> Result<Self, DecodeError>;
    /// Decode the value and typecheck
    ///
    /// This should not be overriden and uses `type_check` in combination with
    /// `raw_decode`.
    fn decode(value: &Value, ctx: &mut Context) -> Result<Self, DecodeError> {
        Self::type_check(&value.type_name, ctx);
        Self::raw_decode(&value.literal, ctx)
    }
}

/// The trait that decodes span into the final structure
pub trait DecodeSpan: Sized {
    /// Decode span
    ///
    /// This method can use some extra data (say file name) from the context.
    /// Although, by default context is empty and end users are expected to use
    /// [`parse_with_context`](crate::parse_with_context) to add some values.
    fn decode_span(span: &Span, ctx: &mut Context) -> Self;
}
